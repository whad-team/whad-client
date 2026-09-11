"""Realtek HCI firmware helpers.

The RTL8761BU applies its public Bluetooth address from the configuration
blob appended to the vendor firmware download.  This module deliberately
contains only the format and file-selection code; the HCI transport remains
owned by :mod:`whad.device.hci`.
"""
import os
import struct
from dataclasses import dataclass
from pathlib import Path


RTK_CONFIG_MAGIC = 0x8723AB55
RTK_CONFIG_BDADDR_OFFSET = 0x0030
RTK_EPATCH_SIGNATURE = b"Realtech"
RTK_EXTENSION_SIGNATURE = bytes((0x51, 0x04, 0xFD, 0x77))
RTK_FRAGMENT_LENGTH = 252
RTK_PROJECT_ID_8761B = 14
RTK_ROM_LMP_8761A = 0x8761
RTK_FIRMWARE_DIR_ENV = "WHAD_RTK_FIRMWARE_DIR"
RTK_FIRMWARE_NAME_8761BU = "rtl8761bu_fw.bin"
RTK_CONFIG_NAME_8761BU = "rtl8761bu_config.bin"


class RealtekFirmwareError(ValueError):
    """Raised when a Realtek firmware or configuration image is invalid."""


@dataclass(frozen=True)
class RealtekPatch:
    """One selectable patch from a Realtek epatch image."""

    chip_id: int
    payload: bytes


class RealtekFirmware:
    """Validated Realtek epatch image."""

    def __init__(self, data):
        data = bytes(data)
        if not data.startswith(RTK_EPATCH_SIGNATURE):
            raise RealtekFirmwareError("firmware has no Realtek epatch signature")
        if not data.endswith(RTK_EXTENSION_SIGNATURE):
            raise RealtekFirmwareError("firmware has no Realtek extension signature")
        if len(data) < 14:
            raise RealtekFirmwareError("firmware header is truncated")

        self.project_id = self._read_project_id(data)
        self.version, patch_count = struct.unpack_from("<IH", data, 8)

        table_end = 14 + 8 * patch_count
        if table_end > len(data):
            raise RealtekFirmwareError("firmware patch table is truncated")

        patches = []
        lengths_offset = 14 + 2 * patch_count
        offsets_offset = 14 + 4 * patch_count
        for patch_index in range(patch_count):
            chip_id = struct.unpack_from("<H", data, 14 + 2 * patch_index)[0]
            patch_length = struct.unpack_from(
                "<H", data, lengths_offset + 2 * patch_index
            )[0]
            patch_offset = struct.unpack_from(
                "<I", data, offsets_offset + 4 * patch_index
            )[0]
            if patch_length < 8:
                raise RealtekFirmwareError("firmware patch is too short")
            if patch_offset < table_end or patch_offset + patch_length > len(data):
                raise RealtekFirmwareError("firmware patch range is invalid")

            # Realtek replaces the final four patch bytes with the image version
            # immediately before downloading the selected patch.
            payload = (
                data[patch_offset : patch_offset + patch_length - 4]
                + struct.pack("<I", self.version)
            )
            patches.append(RealtekPatch(chip_id, payload))

        self.patches = tuple(patches)

    @staticmethod
    def _read_project_id(data):
        offset = len(data) - len(RTK_EXTENSION_SIGNATURE)
        while offset >= 14:
            if offset < 2:
                break
            length, opcode = data[offset - 2 : offset]
            offset -= 2
            if opcode == 0xFF:
                break
            if length == 0 or offset - length < 14:
                raise RealtekFirmwareError("firmware extension is invalid")
            if opcode == 0x00 and length == 1:
                return data[offset - 1]
            offset -= length
        raise RealtekFirmwareError("firmware project id is missing")

    def patch_for_rom(self, rom_version):
        """Return the patch selected by the controller's ROM revision."""

        wanted_chip_id = rom_version + 1
        for patch in self.patches:
            if patch.chip_id == wanted_chip_id:
                return patch
        raise RealtekFirmwareError(
            "firmware has no patch for ROM revision 0x{:02x}".format(rom_version)
        )


class RealtekConfig:
    """Realtek configuration blob with lossless entry preservation."""

    def __init__(self, entries=()):
        self.entries = tuple((int(offset), bytes(value)) for offset, value in entries)
        for offset, value in self.entries:
            if not 0 <= offset <= 0xFFFF:
                raise RealtekFirmwareError("configuration offset is out of range")
            if not 1 <= len(value) <= 0xFF:
                raise RealtekFirmwareError("configuration entry length is invalid")

    @classmethod
    def parse(cls, data):
        """Parse an existing config, or return an empty config for ``None``."""

        if data is None:
            return cls()
        data = bytes(data)
        if len(data) < 6:
            raise RealtekFirmwareError("configuration header is truncated")
        magic, payload_length = struct.unpack_from("<IH", data)
        if magic != RTK_CONFIG_MAGIC:
            raise RealtekFirmwareError("configuration magic is invalid")
        if payload_length != len(data) - 6:
            raise RealtekFirmwareError("configuration length is invalid")

        entries = []
        offset = 6
        while offset < len(data):
            if offset + 3 > len(data):
                raise RealtekFirmwareError("configuration entry is truncated")
            config_offset, value_length = struct.unpack_from("<HB", data, offset)
            offset += 3
            if value_length == 0 or offset + value_length > len(data):
                raise RealtekFirmwareError("configuration entry value is invalid")
            entries.append((config_offset, data[offset : offset + value_length]))
            offset += value_length
        return cls(entries)

    def with_bd_address(self, bd_address):
        """Return a config containing exactly one public-address entry."""

        bd_address = bytes(bd_address)
        if len(bd_address) != 6:
            raise RealtekFirmwareError("Bluetooth address must contain six bytes")

        entries = []
        replaced = False
        for offset, value in self.entries:
            if offset == RTK_CONFIG_BDADDR_OFFSET:
                if not replaced:
                    entries.append((offset, bd_address))
                    replaced = True
                continue
            entries.append((offset, value))
        if not replaced:
            entries.append((RTK_CONFIG_BDADDR_OFFSET, bd_address))
        return type(self)(entries)

    def to_bytes(self):
        payload = b"".join(
            struct.pack("<HB", offset, len(value)) + value
            for offset, value in self.entries
        )
        if len(payload) > 0xFFFF:
            raise RealtekFirmwareError("configuration is too large")
        return struct.pack("<IH", RTK_CONFIG_MAGIC, len(payload)) + payload


def iter_download_fragments(payload):
    """Yield ``(index, bytes)`` pairs for Realtek opcode ``0xfc20``."""

    payload = bytes(payload)
    fragment_count = len(payload) // RTK_FRAGMENT_LENGTH + 1
    next_index = 0
    for fragment_number in range(fragment_count):
        index = next_index
        next_index += 1
        if index == 0x7F:
            next_index = 1

        start = fragment_number * RTK_FRAGMENT_LENGTH
        fragment = payload[start : start + RTK_FRAGMENT_LENGTH]
        if fragment_number == fragment_count - 1:
            index |= 0x80
        yield index, fragment


def load_rtl8761bu_images():
    """Load the RTL8761BU epatch and optional base configuration.

    ``WHAD_RTK_FIRMWARE_DIR`` takes precedence.  Uncompressed Linux firmware
    files are used as a fallback.  Compressed distro firmware is intentionally
    not decompressed in-process; callers can point the environment variable at
    an uncompressed copy.
    """

    search_dirs = []
    if RTK_FIRMWARE_DIR_ENV in os.environ:
        search_dirs.append(Path(os.environ[RTK_FIRMWARE_DIR_ENV]))
    else:
        search_dirs.append(Path("/lib/firmware/rtl_bt"))

    firmware_path = None
    for directory in search_dirs:
        candidate = directory / RTK_FIRMWARE_NAME_8761BU
        if candidate.is_file():
            firmware_path = candidate
            break
    if firmware_path is None:
        raise RealtekFirmwareError(
            "{} was not found; set {} to an uncompressed firmware directory".format(
                RTK_FIRMWARE_NAME_8761BU, RTK_FIRMWARE_DIR_ENV
            )
        )

    config_path = firmware_path.with_name(RTK_CONFIG_NAME_8761BU)
    config_data = config_path.read_bytes() if config_path.is_file() else None
    return RealtekFirmware(firmware_path.read_bytes()), RealtekConfig.parse(config_data)
