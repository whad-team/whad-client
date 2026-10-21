"""USB HCI transport for Realtek adapters on systems without Linux HCI sockets."""

from collections import deque
from time import monotonic

import usb.core
import usb.util
from scapy.compat import raw
from scapy.layers.bluetooth import (
    HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Read_Local_Version_Information,
    HCI_Cmd_Reset,
)

from whad.scapy.layers.hci import (
    HCI_Cmd_Realtek_Read_ROM_Version,
    HCI_Cmd_Complete_Realtek_Read_ROM_Version,
    HCI_Cmd_Realtek_Download,
    HCI_Cmd_Complete_Realtek_Download,
)

from .realtek import (
    RealtekFirmwareError, RTK_PROJECT_ID_8761B, RTK_PROJECT_ID_8761C,
    RTK_ROM_LMP_8761A, iter_download_fragments, load_rtl8761bu_images,
    load_rtl8761cu_images,
)


# USB IDs seen for RTL8761B dongles and the RTL8761CUV development board.
REALTEK_USB_IDS = (
    (0x0BDA, 0x8771),
    (0x0BDA, 0xA729),
    (0x0BDA, 0xB771),
    (0x0BDA, 0xC761),
    (0x2550, 0x8761),
)


def usb_identity(device):
    """Return a stable USB selector where the device supplies one."""
    try:
        serial = usb.util.get_string(device, device.iSerialNumber)
    except (ValueError, usb.core.USBError):
        serial = None
    if serial:
        suffix = serial
    else:
        ports = getattr(device, "port_numbers", None)
        suffix = "@{}-{}".format(
            getattr(device, "bus", 0),
            ".".join(str(port) for port in ports) if ports else
            getattr(device, "address", 0),
        )
    return "{:04X}:{:04X}/{}".format(device.idVendor, device.idProduct, suffix)


def find_realtek_usb_devices():
    """Enumerate supported devices without claiming their interfaces."""
    devices = []
    for vendor, product in REALTEK_USB_IDS:
        devices.extend(usb.core.find(
            find_all=True, idVendor=vendor, idProduct=product
        ) or ())
    return devices


class _PacketSplitter:
    """Reassemble HCI events or ACL packets across USB transfers."""

    def __init__(self, packet_type, header_size, length_offset):
        self.packet_type = packet_type
        self.header_size = header_size
        self.length_offset = length_offset
        self.buffer = bytearray()

    def feed(self, data):
        self.buffer.extend(data)
        packets = []
        while len(self.buffer) >= self.header_size:
            if self.packet_type == 0x04:
                payload_length = self.buffer[self.length_offset]
            else:
                payload_length = int.from_bytes(
                    self.buffer[self.length_offset:self.length_offset + 2],
                    "little",
                )
            packet_length = self.header_size + payload_length
            if len(self.buffer) < packet_length:
                break
            packets.append(bytes((self.packet_type,)) + self.buffer[:packet_length])
            del self.buffer[:packet_length]
        return packets


class RealtekUSBTransport:
    """Minimal socket-like adapter used by WHAD's existing HCI device."""

    def __init__(self, identity):
        matches = [device for device in find_realtek_usb_devices()
                   if usb_identity(device) == identity]
        if len(matches) != 1:
            raise RealtekFirmwareError("USB controller identity is missing or ambiguous")
        self.device = matches[0]
        self.interface_number = None
        self.interface_claimed = False
        self.packets = deque()
        self.events = _PacketSplitter(0x04, 2, 1)
        self.acl = _PacketSplitter(0x02, 4, 2)

        try:
            try:
                configuration = self.device.get_active_configuration()
            except usb.core.USBError:
                self.device.set_configuration()
                configuration = self.device.get_active_configuration()
            interface = usb.util.find_descriptor(
                configuration,
                custom_match=lambda item: item.bInterfaceClass == 0xE0
                and item.bInterfaceSubClass == 1
                and item.bInterfaceProtocol == 1
                and item.bAlternateSetting == 0
                and item.bNumEndpoints >= 3,
            )
            if interface is None:
                raise RealtekFirmwareError("USB device has no Bluetooth HCI interface")
            self.interface_number = interface.bInterfaceNumber
            usb.util.claim_interface(self.device, self.interface_number)
            self.interface_claimed = True

            def endpoint(direction, kind):
                return usb.util.find_descriptor(
                    interface,
                    custom_match=lambda item:
                    usb.util.endpoint_direction(item.bEndpointAddress) == direction
                    and usb.util.endpoint_type(item.bmAttributes) == kind,
                )

            self.event_in = endpoint(
                usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_INTR
            )
            self.acl_in = endpoint(
                usb.util.ENDPOINT_IN, usb.util.ENDPOINT_TYPE_BULK
            )
            self.acl_out = endpoint(
                usb.util.ENDPOINT_OUT, usb.util.ENDPOINT_TYPE_BULK
            )
            if any(endpoint is None for endpoint in (
                self.event_in, self.acl_in, self.acl_out
            )):
                raise RealtekFirmwareError("USB HCI endpoints are incomplete")
        except Exception:
            self.close()
            raise

    def send(self, packet):
        data = raw(packet) if not isinstance(packet, bytes) else packet
        if not data:
            raise ValueError("empty HCI packet")
        if data[0] == 0x01:
            # Bluetooth USB transport sends commands over class control OUT.
            self.device.ctrl_transfer(0x20, 0, 0, 0, data[1:], timeout=10000)
        elif data[0] == 0x02:
            self.acl_out.write(data[1:], timeout=10000)
        else:
            raise ValueError("unsupported HCI USB packet type")

    def _read_endpoint(self, endpoint, splitter, timeout_ms):
        try:
            data = endpoint.read(4096, timeout=timeout_ms)
        except usb.core.USBTimeoutError:
            return False
        self.packets.extend(splitter.feed(bytes(data)))
        return bool(data)

    def readable(self, timeout=0.1):
        deadline = monotonic() + timeout
        while not self.packets and monotonic() < deadline:
            self._read_endpoint(self.event_in, self.events, 10)
            if self.packets:
                break
            self._read_endpoint(self.acl_in, self.acl, 10)
        return bool(self.packets)

    def recv(self):
        if not self.readable(10.0):
            raise TimeoutError("USB HCI response timed out")
        return HCI_Hdr(self.packets.popleft())

    def flush(self):
        self.packets.clear()
        self.events.buffer.clear()
        self.acl.buffer.clear()
        for _ in range(32):
            received = self._read_endpoint(self.event_in, self.events, 1)
            received |= self._read_endpoint(self.acl_in, self.acl, 1)
            if not received:
                break
        self.packets.clear()

    def close(self):
        if self.interface_claimed:
            usb.util.release_interface(self.device, self.interface_number)
            self.interface_claimed = False
        self.interface_number = None
        usb.util.dispose_resources(self.device)

    def command(self, command):
        packet = HCI_Hdr()/HCI_Command_Hdr()/command
        self.send(packet)
        deadline = monotonic() + 10.0
        while monotonic() < deadline:
            if not self.readable(min(0.1, deadline - monotonic())):
                continue
            event = HCI_Hdr(self.packets.popleft())
            if event.type == 0x04 and event.code == 0x0E and (
                event.opcode == packet[HCI_Command_Hdr].opcode
            ):
                return event
        raise RealtekFirmwareError("Realtek USB firmware command timed out")

    def load_firmware_if_needed(self):
        """Load bundled firmware only from a verified RTL8761BU/CU ROM."""
        version = self.command(HCI_Cmd_Read_Local_Version_Information())
        if version.status != 0 or version.company_identifier != 0x005D:
            raise RealtekFirmwareError("USB controller is not Realtek")

        firmware_version = (version.hci_subversion << 16) | version.lmp_subversion
        profiles = (
            (RTK_PROJECT_ID_8761B, (0x0A, 0x000B), load_rtl8761bu_images),
            (RTK_PROJECT_ID_8761C, (0x0D, 0x000E), load_rtl8761cu_images),
        )
        for project_id, rom_version, loader in profiles:
            firmware, config = loader()
            if firmware.project_id != project_id:
                raise RealtekFirmwareError("Realtek firmware project ID mismatch")
            if firmware_version == firmware.version:
                return project_id
            if (
                project_id == RTK_PROJECT_ID_8761C
                and version.hci_version == 0x0D
                and version.lmp_subversion != RTK_ROM_LMP_8761A
            ):
                # Keep an already operational C controller running its own
                # patch. Address rewriting still requires the known image.
                return project_id
            if (
                (version.hci_version, version.hci_subversion) != rom_version
                or version.lmp_subversion != RTK_ROM_LMP_8761A
            ):
                continue

            rom = self.command(HCI_Cmd_Realtek_Read_ROM_Version())
            if rom.status != 0 or HCI_Cmd_Complete_Realtek_Read_ROM_Version not in rom:
                raise RealtekFirmwareError("Realtek ROM revision is unavailable")
            patch = firmware.patch_for_rom(
                rom[HCI_Cmd_Complete_Realtek_Read_ROM_Version].version
            )
            for index, fragment in iter_download_fragments(
                patch.payload + config.to_bytes()
            ):
                response = self.command(
                    HCI_Cmd_Realtek_Download(index=index, data=fragment)
                )
                if (
                    response.status != 0
                    or HCI_Cmd_Complete_Realtek_Download not in response
                    or response[HCI_Cmd_Complete_Realtek_Download].index != index
                ):
                    raise RealtekFirmwareError("Realtek firmware fragment rejected")
            version = self.command(HCI_Cmd_Read_Local_Version_Information())
            loaded_version = (version.hci_subversion << 16) | version.lmp_subversion
            if version.status != 0 or loaded_version != firmware.version:
                raise RealtekFirmwareError("Realtek firmware version did not match")
            return project_id
        raise RealtekFirmwareError("USB controller has unsupported firmware state")
