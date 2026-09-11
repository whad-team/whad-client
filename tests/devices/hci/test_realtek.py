"""Offline tests for the Realtek HCI firmware/configuration helpers."""

import struct
from collections import deque
from types import SimpleNamespace

import pytest
from scapy.layers.bluetooth import (
    HCI_Command_Hdr,
    HCI_Cmd_LE_Set_Random_Address,
    HCI_Cmd_Read_Local_Version_Information,
    HCI_Cmd_Reset,
    HCI_Hdr,
)

import whad.device.hci as hci_module
from whad.device.hci import (
    HCIUnsupportedCommand,
    Hci,
    REALTEK_COMMAND_TIMEOUT,
    REALTEK_COMPANY_IDENTIFIER,
)
from whad.device.hci.realtek import (
    RTK_CONFIG_BDADDR_OFFSET,
    RTK_CONFIG_MAGIC,
    RTK_CONFIG_NAME_8761BU,
    RTK_EXTENSION_SIGNATURE,
    RTK_FIRMWARE_DIR_ENV,
    RTK_FIRMWARE_NAME_8761BU,
    RTK_FRAGMENT_LENGTH,
    RTK_PROJECT_ID_8761B,
    RealtekConfig,
    RealtekFirmware,
    RealtekFirmwareError,
    iter_download_fragments,
    load_rtl8761bu_images,
)
from whad.hub.ble import AddressType, BDAddress
from whad.scapy.layers.hci import (
    HCI_Cmd_Complete_Realtek_Download,
    HCI_Cmd_Complete_Realtek_Read_ROM_Version,
    HCI_Cmd_Realtek_Download,
    HCI_Cmd_Realtek_Drop_Firmware,
    HCI_Cmd_Realtek_Read_ROM_Version,
)


def _epatch(
    patches=((1, b"patch000" + b"old!"),),
    *,
    version=0x12345678,
    project_id=RTK_PROJECT_ID_8761B,
    later_extension_instructions=b"",
):
    """Build a small synthetic Realtek epatch image.

    Extension instructions are stored payload-first and are parsed backwards
    from the extension signature.  ``later_extension_instructions`` therefore
    appears after the project-ID instruction and is visited first.
    """

    patches = tuple((chip_id, bytes(payload)) for chip_id, payload in patches)
    table_end = 14 + 8 * len(patches)
    offsets = []
    next_offset = table_end
    for _, payload in patches:
        offsets.append(next_offset)
        next_offset += len(payload)

    tables = b"".join(struct.pack("<H", chip_id) for chip_id, _ in patches)
    tables += b"".join(struct.pack("<H", len(payload)) for _, payload in patches)
    tables += b"".join(struct.pack("<I", offset) for offset in offsets)
    patch_data = b"".join(payload for _, payload in patches)

    if project_id is None:
        extension = later_extension_instructions
    else:
        extension = bytes((project_id, 1, 0)) + later_extension_instructions

    return (
        b"Realtech"
        + struct.pack("<IH", version, len(patches))
        + tables
        + patch_data
        + extension
        + RTK_EXTENSION_SIGNATURE
    )


def _config_blob(payload, *, magic=RTK_CONFIG_MAGIC, declared_length=None):
    payload = bytes(payload)
    if declared_length is None:
        declared_length = len(payload)
    return struct.pack("<IH", magic, declared_length) + payload


def _with_u16(data, offset, value):
    result = bytearray(data)
    struct.pack_into("<H", result, offset, value)
    return bytes(result)


def _with_u32(data, offset, value):
    result = bytearray(data)
    struct.pack_into("<I", result, offset, value)
    return bytes(result)


class _LayeredResponse:
    """Small response double supporting Scapy's layer lookup idiom."""

    def __init__(self, *, layers=None, **fields):
        self._layers = {} if layers is None else dict(layers)
        for name, value in fields.items():
            setattr(self, name, value)

    def __contains__(self, layer):
        return layer in self._layers

    def __getitem__(self, layer):
        return self._layers[layer]


class _RecordingSocket:
    def __init__(self):
        self.sent = []

    def send(self, packet):
        self.sent.append(packet)


def _version_response(firmware_version, *, hci_version=0x0B):
    return _LayeredResponse(
        status=0,
        company_identifier=REALTEK_COMPANY_IDENTIFIER,
        hci_version=hci_version,
        hci_subversion=(firmware_version >> 16) & 0xFFFF,
        lmp_subversion=firmware_version & 0xFFFF,
    )


def _cold_rom_version_response():
    return _LayeredResponse(
        status=0,
        company_identifier=REALTEK_COMPANY_IDENTIFIER,
        hci_version=0x0A,
        hci_subversion=0x000B,
        lmp_subversion=0x8761,
    )


def _rom_revision_response(version=0):
    return _LayeredResponse(
        status=0,
        layers={
            HCI_Cmd_Complete_Realtek_Read_ROM_Version: SimpleNamespace(
                version=version
            )
        },
    )


def _download_response(index, *, status=0):
    return _LayeredResponse(
        status=status,
        layers={
            HCI_Cmd_Complete_Realtek_Download: SimpleNamespace(index=index)
        },
    )


def _device_with_address(address):
    device = Hci(0)
    device._bd_address = BDAddress(address)
    device._local_name = b"mock-realtek"
    return device


def _scripted_writer(script, events):
    script = deque(script)

    def write(command, **kwargs):
        assert kwargs.get("timeout") == REALTEK_COMMAND_TIMEOUT
        expected_type, response = script.popleft()
        assert isinstance(command, expected_type)
        events.append(command)
        return response(command) if callable(response) else response

    write.remaining = script
    return write


def test_public_bdaddr_config_has_exact_controller_bytes():
    """The text form is reversed exactly once into HCI/controller byte order."""

    displayed_address = BDAddress("00:11:22:33:44:55")
    assert displayed_address.value == bytes.fromhex("55 44 33 22 11 00")

    config = RealtekConfig().with_bd_address(displayed_address.value)
    expected = bytes.fromhex(
        "55 ab 23 87 09 00 30 00 06 55 44 33 22 11 00"
    )
    assert config.to_bytes() == expected

    parsed = RealtekConfig.parse(expected)
    assert parsed.entries == (
        (RTK_CONFIG_BDADDR_OFFSET, displayed_address.value),
    )
    assert str(BDAddress(parsed.entries[0][1])) == "00:11:22:33:44:55"


def test_config_parse_and_replace_preserves_unrelated_entries():
    base = RealtekConfig(
        (
            (0x000C, b"\xaa\xbb"),
            (RTK_CONFIG_BDADDR_OFFSET, b"oldone"),
            (0x01A4, b"\x10\x20\x30"),
            (RTK_CONFIG_BDADDR_OFFSET, b"oldtwo"),
        )
    )
    parsed = RealtekConfig.parse(base.to_bytes())
    replacement = bytes.fromhex("a8 25 19 f3 38 44")

    updated = parsed.with_bd_address(replacement)

    assert updated.entries == (
        (0x000C, b"\xaa\xbb"),
        (RTK_CONFIG_BDADDR_OFFSET, replacement),
        (0x01A4, b"\x10\x20\x30"),
    )
    assert RealtekConfig.parse(updated.to_bytes()).entries == updated.entries


def test_config_none_is_empty_and_address_is_appended():
    config = RealtekConfig.parse(None)
    assert config.entries == ()
    assert config.to_bytes() == bytes.fromhex("55 ab 23 87 00 00")

    address = bytes.fromhex("06 05 04 03 02 01")
    assert config.with_bd_address(address).entries == (
        (RTK_CONFIG_BDADDR_OFFSET, address),
    )


@pytest.mark.parametrize("length", (0, 1, 5, 7, 255))
def test_config_rejects_non_six_byte_addresses(length):
    with pytest.raises(RealtekFirmwareError, match="six bytes"):
        RealtekConfig().with_bd_address(bytes(length))


@pytest.mark.parametrize(
    "data",
    (
        b"",
        b"\x55\xab\x23\x87\x00",
        _config_blob(b"", magic=0xDEADBEEF),
        _config_blob(b"", declared_length=1),
        _config_blob(b"\x30\x00"),
        _config_blob(b"\x30\x00\x00"),
        _config_blob(b"\x30\x00\x02\xaa"),
    ),
)
def test_config_parser_rejects_malformed_images(data):
    with pytest.raises(RealtekFirmwareError):
        RealtekConfig.parse(data)


@pytest.mark.parametrize(
    "entries",
    (
        ((-1, b"x"),),
        ((0x10000, b"x"),),
        ((0, b""),),
        ((0, bytes(256)),),
    ),
)
def test_config_constructor_rejects_invalid_entries(entries):
    with pytest.raises(RealtekFirmwareError):
        RealtekConfig(entries)


def test_config_encoder_rejects_oversized_payload():
    config = RealtekConfig(tuple((index, bytes(255)) for index in range(255)))
    with pytest.raises(RealtekFirmwareError, match="too large"):
        config.to_bytes()


def test_firmware_parser_selects_rom_patch_and_replaces_trailer():
    version = 0xA1B2C3D4
    first_patch = b"first-aa" + b"ONE!"
    selected_patch = b"second-bb" + b"TWO!"
    firmware = RealtekFirmware(
        _epatch(
            ((1, first_patch), (2, selected_patch)),
            version=version,
        )
    )

    assert firmware.project_id == RTK_PROJECT_ID_8761B
    assert firmware.version == version
    assert tuple(patch.chip_id for patch in firmware.patches) == (1, 2)
    assert firmware.patches[0].payload == (
        first_patch[:-4] + struct.pack("<I", version)
    )
    assert firmware.patch_for_rom(1).payload == (
        selected_patch[:-4] + struct.pack("<I", version)
    )


def test_firmware_project_id_scan_skips_later_extension_instruction():
    # The parser encounters this unknown two-byte extension instruction before
    # it reaches the project-ID instruction.
    firmware = RealtekFirmware(
        _epatch(later_extension_instructions=b"\xaa\xbb\x02\x42")
    )
    assert firmware.project_id == RTK_PROJECT_ID_8761B


def test_firmware_patch_selection_rejects_unknown_rom_revision():
    firmware = RealtekFirmware(_epatch(((2, b"selected" + b"tail"),)))
    with pytest.raises(RealtekFirmwareError, match="no patch"):
        firmware.patch_for_rom(2)


def test_firmware_rejects_bad_signatures():
    valid = _epatch()
    with pytest.raises(RealtekFirmwareError, match="epatch signature"):
        RealtekFirmware(b"NotReal!" + valid[8:])
    with pytest.raises(RealtekFirmwareError, match="extension signature"):
        RealtekFirmware(valid[:-4] + b"bad!")


def test_firmware_rejects_truncated_header():
    with pytest.raises(RealtekFirmwareError, match="header is truncated"):
        RealtekFirmware(b"Realtech" + RTK_EXTENSION_SIGNATURE)


def test_firmware_rejects_missing_or_invalid_project_instruction():
    no_project = _epatch((), project_id=None, later_extension_instructions=b"\x00\xff")
    with pytest.raises(RealtekFirmwareError, match="project id is missing"):
        RealtekFirmware(no_project)

    zero_length = _epatch((), project_id=None, later_extension_instructions=b"\x00\x42")
    with pytest.raises(RealtekFirmwareError, match="extension is invalid"):
        RealtekFirmware(zero_length)

    truncated_value = _epatch(
        (), project_id=None, later_extension_instructions=b"\xaa\x02\x42"
    )
    with pytest.raises(RealtekFirmwareError, match="extension is invalid"):
        RealtekFirmware(truncated_value)


def test_firmware_rejects_truncated_patch_table():
    # Header claims one patch, but the project instruction follows immediately.
    image = (
        b"Realtech"
        + struct.pack("<IH", 0x12345678, 1)
        + bytes((RTK_PROJECT_ID_8761B, 1, 0))
        + RTK_EXTENSION_SIGNATURE
    )
    with pytest.raises(RealtekFirmwareError, match="patch table is truncated"):
        RealtekFirmware(image)


def test_firmware_rejects_too_short_patch():
    with pytest.raises(RealtekFirmwareError, match="patch is too short"):
        RealtekFirmware(_epatch(((1, b"1234567"),)))


def test_firmware_rejects_patch_inside_table():
    image = _epatch()
    patch_offsets_table = 14 + 4  # One chip ID and one patch length precede it.
    image = _with_u32(image, patch_offsets_table, 14)
    with pytest.raises(RealtekFirmwareError, match="patch range is invalid"):
        RealtekFirmware(image)


def test_firmware_rejects_patch_extending_beyond_image():
    image = _epatch()
    patch_lengths_table = 14 + 2  # One chip ID precedes it.
    image = _with_u16(image, patch_lengths_table, 0xFFFF)
    with pytest.raises(RealtekFirmwareError, match="patch range is invalid"):
        RealtekFirmware(image)


def test_loader_uses_environment_directory_and_optional_config(tmp_path, monkeypatch):
    firmware_data = _epatch(((2, b"firmware" + b"tail"),))
    address = bytes.fromhex("55 44 33 22 11 00")
    config_data = RealtekConfig(((0x000C, b"\x01"),)).with_bd_address(address).to_bytes()
    (tmp_path / RTK_FIRMWARE_NAME_8761BU).write_bytes(firmware_data)
    (tmp_path / RTK_CONFIG_NAME_8761BU).write_bytes(config_data)
    monkeypatch.setenv(RTK_FIRMWARE_DIR_ENV, str(tmp_path))

    firmware, config = load_rtl8761bu_images()

    assert firmware.project_id == RTK_PROJECT_ID_8761B
    assert firmware.patch_for_rom(1).chip_id == 2
    assert config.entries == RealtekConfig.parse(config_data).entries


def test_loader_accepts_missing_optional_config(tmp_path, monkeypatch):
    (tmp_path / RTK_FIRMWARE_NAME_8761BU).write_bytes(_epatch())
    monkeypatch.setenv(RTK_FIRMWARE_DIR_ENV, str(tmp_path))

    _, config = load_rtl8761bu_images()
    assert config.entries == ()


def test_loader_rejects_missing_firmware(tmp_path, monkeypatch):
    monkeypatch.setenv(RTK_FIRMWARE_DIR_ENV, str(tmp_path))
    with pytest.raises(RealtekFirmwareError, match=RTK_FIRMWARE_NAME_8761BU):
        load_rtl8761bu_images()


@pytest.mark.parametrize(
    ("length", "expected_lengths", "expected_indices"),
    (
        (0, (0,), (0x80,)),
        (1, (1,), (0x80,)),
        (RTK_FRAGMENT_LENGTH - 1, (RTK_FRAGMENT_LENGTH - 1,), (0x80,)),
        (RTK_FRAGMENT_LENGTH, (RTK_FRAGMENT_LENGTH, 0), (0x00, 0x81)),
        (RTK_FRAGMENT_LENGTH + 1, (RTK_FRAGMENT_LENGTH, 1), (0x00, 0x81)),
    ),
)
def test_download_fragment_boundaries(length, expected_lengths, expected_indices):
    payload = bytes((index & 0xFF) for index in range(length))
    fragments = list(iter_download_fragments(payload))

    assert tuple(index for index, _ in fragments) == expected_indices
    assert tuple(len(fragment) for _, fragment in fragments) == expected_lengths
    assert b"".join(fragment for _, fragment in fragments) == payload
    assert all(len(fragment) <= RTK_FRAGMENT_LENGTH for _, fragment in fragments)


def test_download_fragment_indices_wrap_like_linux_driver():
    payload = b"x" * (129 * RTK_FRAGMENT_LENGTH + 1)
    fragments = list(iter_download_fragments(payload))
    indices = tuple(index for index, _ in fragments)

    assert indices[126:130] == (0x7E, 0x7F, 0x01, 0x82)
    assert all(index < 0x80 for index in indices[:-1])
    assert indices[-1] & 0x80
    assert fragments[-1][1] == b"x"
    assert b"".join(fragment for _, fragment in fragments) == payload


@pytest.mark.parametrize(
    ("command", "expected"),
    (
        (HCI_Cmd_Realtek_Read_ROM_Version(), bytes.fromhex("01 6d fc 00")),
        (HCI_Cmd_Realtek_Drop_Firmware(), bytes.fromhex("01 66 fc 00")),
        (
            HCI_Cmd_Realtek_Download(index=0x81, data=b"\xaa\xbb"),
            bytes.fromhex("01 20 fc 03 81 aa bb"),
        ),
    ),
)
def test_realtek_scapy_commands_have_exact_wire_encoding(command, expected):
    packet = HCI_Hdr() / HCI_Command_Hdr() / command
    assert bytes(packet) == expected


def test_realtek_scapy_download_command_round_trip_preserves_short_fragment():
    wire = bytes.fromhex("01 20 fc 04 82 de ad be")
    parsed = HCI_Hdr(wire)

    assert HCI_Cmd_Realtek_Download in parsed
    assert parsed[HCI_Cmd_Realtek_Download].index == 0x82
    assert parsed[HCI_Cmd_Realtek_Download].data == bytes.fromhex("de ad be")
    assert bytes(parsed) == wire


def test_realtek_scapy_command_complete_parses_status_and_index():
    # HCI command-complete event: packet count, opcode, status, then vendor data.
    wire = bytes.fromhex("04 0e 05 01 20 fc 00 81")
    parsed = HCI_Hdr(wire)

    assert parsed.status == 0
    assert HCI_Cmd_Complete_Realtek_Download in parsed
    assert parsed[HCI_Cmd_Complete_Realtek_Download].index == 0x81


def test_realtek_scapy_read_rom_complete_parses_version():
    wire = bytes.fromhex("04 0e 05 01 6d fc 00 02")
    parsed = HCI_Hdr(wire)

    assert parsed.status == 0
    assert HCI_Cmd_Complete_Realtek_Read_ROM_Version in parsed
    assert parsed[HCI_Cmd_Complete_Realtek_Read_ROM_Version].version == 2


def test_public_address_rejects_nonmatching_realtek_without_dropping_firmware(
    monkeypatch,
):
    original = bytes.fromhex("92 27 41 4c e0 00")
    target = bytes.fromhex("a8 25 19 f3 38 44")
    device = _device_with_address(original)
    firmware = RealtekFirmware(_epatch(version=0x12345678))
    base_config = RealtekConfig().with_bd_address(original)
    commands = []
    drops = []

    def write(command, **kwargs):
        commands.append(command)
        return _version_response(0x11112222)

    monkeypatch.setattr(device, "_write_command", write)
    monkeypatch.setattr(
        device,
        "_write_command_without_response",
        lambda command: drops.append(command),
    )
    monkeypatch.setattr(
        hci_module, "load_rtl8761bu_images", lambda: (firmware, base_config)
    )

    assert device._set_bd_address(target, AddressType.PUBLIC) is False
    assert len(commands) == 1
    assert isinstance(commands[0], HCI_Cmd_Read_Local_Version_Information)
    assert drops == []
    assert device._bd_address.value == original


def test_public_address_success_has_exact_download_sequence_and_readback(monkeypatch):
    original = bytes.fromhex("92 27 41 4c e0 00")
    target = bytes.fromhex("a8 25 19 f3 38 44")
    device = _device_with_address(original)
    firmware = RealtekFirmware(_epatch(version=0x12345678))
    base_config = RealtekConfig(
        ((0x000C, b"\x01\x02"), (RTK_CONFIG_BDADDR_OFFSET, original))
    )
    custom_config = base_config.with_bd_address(target)
    events = []
    downloaded = []

    def accept_download(command):
        downloaded.append((command.index, command.data))
        return _download_response(command.index)

    writer = _scripted_writer(
        (
            (HCI_Cmd_Read_Local_Version_Information, _version_response(firmware.version)),
            (HCI_Cmd_Reset, _LayeredResponse(status=0)),
            (HCI_Cmd_Read_Local_Version_Information, _cold_rom_version_response()),
            (HCI_Cmd_Realtek_Read_ROM_Version, _rom_revision_response(0)),
            (HCI_Cmd_Realtek_Download, accept_download),
            (HCI_Cmd_Read_Local_Version_Information, _version_response(firmware.version)),
        ),
        events,
    )

    def drop(command):
        assert isinstance(command, HCI_Cmd_Realtek_Drop_Firmware)
        events.append(command)

    def initialize():
        events.append("initialize")
        device._bd_address = BDAddress(target)
        return True

    monkeypatch.setattr(device, "_write_command", writer)
    monkeypatch.setattr(device, "_write_command_without_response", drop)
    monkeypatch.setattr(device, "_initialize", initialize)
    monkeypatch.setattr(hci_module, "sleep", lambda _: None)
    monkeypatch.setattr(
        hci_module, "load_rtl8761bu_images", lambda: (firmware, base_config)
    )

    assert device._set_bd_address(target, AddressType.PUBLIC) is True
    assert not writer.remaining
    assert tuple(
        type(event) if event != "initialize" else event for event in events
    ) == (
        HCI_Cmd_Read_Local_Version_Information,
        HCI_Cmd_Realtek_Drop_Firmware,
        HCI_Cmd_Reset,
        HCI_Cmd_Read_Local_Version_Information,
        HCI_Cmd_Realtek_Read_ROM_Version,
        HCI_Cmd_Realtek_Download,
        HCI_Cmd_Read_Local_Version_Information,
        "initialize",
    )
    assert downloaded == [
        (
            0x80,
            firmware.patch_for_rom(0).payload + custom_config.to_bytes(),
        )
    ]
    assert device._bd_address.value == target
    assert device._bd_address_type == AddressType.PUBLIC


def test_rejected_fragment_rolls_back_stock_config_and_verifies_original_address(
    monkeypatch,
):
    original = bytes.fromhex("92 27 41 4c e0 00")
    target = bytes.fromhex("a8 25 19 f3 38 44")
    device = _device_with_address(original)
    firmware = RealtekFirmware(_epatch(version=0x12345678))
    base_config = RealtekConfig(
        ((0x000C, b"\xaa"), (RTK_CONFIG_BDADDR_OFFSET, original))
    )
    custom_config = base_config.with_bd_address(target)
    events = []
    downloaded = []
    download_calls = []

    def reject_download(command):
        downloaded.append((command.index, command.data))
        return _download_response(command.index ^ 1)

    def accept_download(command):
        downloaded.append((command.index, command.data))
        return _download_response(command.index)

    writer = _scripted_writer(
        (
            (HCI_Cmd_Reset, _LayeredResponse(status=0)),
            (HCI_Cmd_Read_Local_Version_Information, _cold_rom_version_response()),
            (HCI_Cmd_Realtek_Read_ROM_Version, _rom_revision_response(0)),
            (HCI_Cmd_Realtek_Download, reject_download),
            (HCI_Cmd_Reset, _LayeredResponse(status=0)),
            (HCI_Cmd_Read_Local_Version_Information, _cold_rom_version_response()),
            (HCI_Cmd_Realtek_Read_ROM_Version, _rom_revision_response(0)),
            (HCI_Cmd_Realtek_Download, accept_download),
            (HCI_Cmd_Read_Local_Version_Information, _version_response(firmware.version)),
        ),
        events,
    )

    def drop(command):
        assert isinstance(command, HCI_Cmd_Realtek_Drop_Firmware)
        events.append(command)

    def initialize():
        events.append("initialize-stock")
        device._bd_address = BDAddress(original)
        return True

    real_download = device._download_realtek_firmware

    def recording_download(firmware_arg, config_arg, expected_address=None):
        download_calls.append((firmware_arg, config_arg, expected_address))
        return real_download(
            firmware_arg, config_arg, expected_address=expected_address
        )

    monkeypatch.setattr(device, "_write_command", writer)
    monkeypatch.setattr(device, "_write_command_without_response", drop)
    monkeypatch.setattr(device, "_initialize", initialize)
    monkeypatch.setattr(device, "_download_realtek_firmware", recording_download)
    monkeypatch.setattr(hci_module, "sleep", lambda _: None)
    monkeypatch.setattr(
        hci_module, "load_rtl8761bu_images", lambda: (firmware, base_config)
    )

    assert (
        device._set_realtek_public_bd_address(
            target, _version_response(firmware.version)
        )
        is False
    )
    assert not writer.remaining
    assert [call[2] for call in download_calls] == [target, original]
    assert download_calls[0][1].entries == custom_config.entries
    assert download_calls[1][1] is base_config
    assert downloaded == [
        (0x80, firmware.patch_for_rom(0).payload + custom_config.to_bytes()),
        (0x80, firmware.patch_for_rom(0).payload + base_config.to_bytes()),
    ]
    assert sum(isinstance(event, HCI_Cmd_Realtek_Drop_Firmware) for event in events) == 2
    assert events[-1] == "initialize-stock"
    assert device._bd_address.value == original
    assert device._bd_address_type == AddressType.PUBLIC


def test_failed_stock_rollback_returns_false_without_masking_original_failure(
    monkeypatch,
):
    original = bytes.fromhex("92 27 41 4c e0 00")
    target = bytes.fromhex("a8 25 19 f3 38 44")
    device = _device_with_address(original)
    firmware = RealtekFirmware(_epatch(version=0x12345678))
    base_config = RealtekConfig().with_bd_address(original)
    calls = []

    def fail_download(firmware_arg, config_arg, expected_address=None):
        calls.append((firmware_arg, config_arg, expected_address))
        if len(calls) == 1:
            raise RealtekFirmwareError("controller rejected Realtek firmware fragment")
        raise RealtekFirmwareError("stock address readback failed")

    monkeypatch.setattr(device, "_download_realtek_firmware", fail_download)
    monkeypatch.setattr(
        hci_module, "load_rtl8761bu_images", lambda: (firmware, base_config)
    )

    assert (
        device._set_realtek_public_bd_address(
            target, _version_response(firmware.version)
        )
        is False
    )
    assert [call[2] for call in calls] == [target, original]
    assert calls[1][1] is base_config
    assert device._bd_address.value == original


def test_public_address_command_timeout_returns_false_without_attribute_error(
    monkeypatch,
):
    target = bytes.fromhex("a8 25 19 f3 38 44")
    device = _device_with_address(bytes.fromhex("92 27 41 4c e0 00"))
    socket = _RecordingSocket()
    timeouts = []
    device._Hci__socket = socket

    def timeout(*, timeout=None):
        timeouts.append(timeout)
        return None

    monkeypatch.setattr(device, "_wait_response", timeout)
    monkeypatch.setattr(
        hci_module,
        "load_rtl8761bu_images",
        lambda: pytest.fail("firmware must not be loaded after the version timeout"),
    )

    assert device._set_bd_address(target, AddressType.PUBLIC) is False
    assert timeouts == [REALTEK_COMMAND_TIMEOUT]
    assert len(socket.sent) == 1
    assert HCI_Cmd_Read_Local_Version_Information in socket.sent[0]


def test_random_address_still_requires_controller_command_support(monkeypatch):
    device = _device_with_address(bytes.fromhex("92 27 41 4c e0 00"))
    commands = []
    monkeypatch.setattr(device, "is_cmd_supported", lambda command: False)
    monkeypatch.setattr(
        device, "_write_command", lambda command, **kwargs: commands.append(command)
    )

    with pytest.raises(HCIUnsupportedCommand) as error:
        device._set_bd_address(
            bytes.fromhex("c6 05 04 03 02 01"), AddressType.RANDOM
        )

    assert error.value.command == "le_set_random_address"
    assert commands == []


def test_random_address_supported_path_uses_standard_hci_command(monkeypatch):
    target = bytes.fromhex("c6 05 04 03 02 01")
    device = _device_with_address(bytes.fromhex("92 27 41 4c e0 00"))
    commands = []
    monkeypatch.setattr(device, "is_cmd_supported", lambda command: True)
    monkeypatch.setattr(
        device,
        "_write_command",
        lambda command, **kwargs: commands.append(command)
        or _LayeredResponse(status=0),
    )
    monkeypatch.setattr(device, "_read_bd_address", lambda: None)

    assert device._set_bd_address(target, AddressType.RANDOM) is True
    assert len(commands) == 1
    assert isinstance(commands[0], HCI_Cmd_LE_Set_Random_Address)
    assert bytes(commands[0]) == target
    assert device._bd_address_type == AddressType.RANDOM
