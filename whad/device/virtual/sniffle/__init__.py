"""NCC Sniffle BLE5 sniffer adaptation layer

Supported hardware:
 - SonOff ZigBee 3.0 USB Dongle Plus

This adaptation layer only supports sniffing with Sniffle (for now).
"""
from serial.tools.list_ports import comports

from scapy.layers.bluetooth4LE import BTLE_DATA, BTLE_ADV, BTLE, BTLE_CONNECT_REQ

from whad.device.device import VirtualDevice
from whad.hub import ProtocolHub
from whad.hub.generic import CommandResult
from whad.hub.discovery import Domain, Capability
from whad.hub.ble import Commands, Metadata as BleMetadata, BDAddress, Direction
from whad.hub.ble.chanmap import ChannelMap

from .sniffle_hw import SniffleHW, PacketMessage
from .packet_decoder import AdvertMessage, DataMessage
from .constants import SnifferMode, PhyMode

SUPPORTED_DEVICES = (
    # SonOff ZigBee dongle plus
    (0x10C4, 0xEA60, "ITead", "Sonoff Zigbee 3.0 USB Dongle Plus"),
)

CAPABILITIES = {
    Domain.BtLE : (
        Capability.Sniff | Capability.Scan,
        [Commands.Start, Commands.Stop, Commands.ScanMode, Commands.SniffConnReq,
         Commands.SniffAdv]
    )
}

def get_port_info(port):
    """Find information about a serial port

    :param string port: Target serial port
    """
    for p in comports():
        if p.device == port:
            return p
    return None

def is_device_supported(vid, pid, manufacturer, product):
    """Check if a device is supported by WHAD.
    """
    for devinfo in SUPPORTED_DEVICES:
        _vid, _pid, _manuf, _product = devinfo
        if _vid is not None and _vid != vid:
            continue
        if _pid is not None and _pid != pid:
            continue
        if _manuf is not None and _manuf != manufacturer:
            continue
        if _product is not None and _product != product:
            continue

        # Device is supported.
        return True

    # Device is not supported.
    return False

class SniffleDevice(VirtualDevice):
    """NCC Sniffle virtual device implementation.
    """

    INTERFACE_NAME = "sniffle"

    @classmethod
    def list(cls):
        """
        Returns a list of available Ubertooth devices.
        """
        devices = []
        for uart_dev in comports():
            if is_device_supported(uart_dev.vid, uart_dev.pid, uart_dev.manufacturer,
                                   uart_dev.product):
                dev = SniffleDevice(uart_dev.device)
                devices.append(dev)
        return devices

    @property
    def identifier(self):
        """
        Returns the identifier of the current device (e.g., serial number).
        """
        return self.__port


    def __init__(self, port='/dev/ttyUSB0'):
        super().__init__()
        self.__port = port
        self.__opened = False
        self.__mode = None
        self.__show_empty = False
        self.__hw = None

    def open(self):
        if not self.__opened:
            self.__hw = SniffleHW(self.__port)
            self.__opened = True
            super().open()

    def reset(self):
        """Reset ACM device (unsupported)
        """
        self.__hw.cmd_reset()
        self._dev_id = b"SniffleDev01"
        self._fw_author = b"NCCGroup / Sultan Khan"
        self._fw_version = (1, 10, 0)
        self._fw_url = b"https://github.com/nccgroup/Sniffle"
        self._dev_capabilities = CAPABILITIES

    def close(self):
        """Close device
        """
        # Close serial port
        self.__hw.ser.close()

        # Mark as closed
        self.__opened = False

    def _on_whad_ble_stop(self, _):
        """Called when we receive a WHAD BLE Stop message.
        """
        self.__hw.setup_sniffer()
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_start(self, _):
        """Called when we receive a WHAD BLE Start message.
        """
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_scan_mode(self, scan_mode):
        """Called when we receive a WHAD BLE ScanMode message.
        """
        # Stop previous mode if set
        if self.__mode is not None:
            self.__hw.setup_sniffer()

        if scan_mode.active:
            self.__mode = SnifferMode.ACTIVE_SCAN
        else:
            self.__mode = SnifferMode.PASSIVE_SCAN
        self.__hw.setup_sniffer(
            mode=self.__mode,
            chan=37,
            ext_adv=False,
            coded_phy=False,
            rssi_min=-128
        )
        self.__hw.mark_and_flush()
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_sniff_connreq(self, message):
        """Called when we receive a WHAD BLE SniffMode message.
        """
        if self.__mode is not None:
            self.__hw.setup_sniffer()

        self.__show_empty = message.show_empty_packets
        self.__mode = SnifferMode.CONN_FOLLOW

        target_mac = None
        if message.bd_address.lower() != "ff:ff:ff:ff:ff:ff":
            target_mac = BDAddress(message.bd_address).value

        self.__hw.setup_sniffer(
            mode=SnifferMode.CONN_FOLLOW,
            chan=37,
            hop3=False,
            targ_mac = target_mac,
            ext_adv=True,
            coded_phy=False,
            rssi_min=-128,
            interval_preload=[],
            phy_preload=PhyMode.PHY_1M,
            validate_crc=True
        )
        self._send_whad_command_result(CommandResult.SUCCESS)


    def read(self):
        """Return incoming data
        """
        msg = self.__hw.recv_and_decode()
        if isinstance(msg, AdvertMessage):
            pkt = BTLE_ADV(msg.body)

            # If we are following a connection and receive a connection request,
            # then we send a synchronization notification followed by the connection
            # request.
            if BTLE_CONNECT_REQ in pkt and self.__mode == SnifferMode.CONN_FOLLOW:
                m = self.hub.ble.create_raw_pdu_received(
                    Direction.UNKNOWN,
                    bytes(BTLE(msg.body)),
                    access_address=0x8e89bed6,
                    rssi=msg.rssi,
                    conn_handle=0,
                    crc=msg.crc_rev,
                    channel=msg.chan,
                    crc_validity=True
                )
                self._send_whad_message(m)
                conn_req = pkt[BTLE_CONNECT_REQ]
                # Notify synchronization
                sync = self.hub.ble.create_synchronized(
                    access_address = conn_req.AA,
                    interval=conn_req.interval,
                    increment=conn_req.hop,
                    channel_map=ChannelMap.from_int(int(conn_req.chM)),
                    crc_init=int(conn_req.crc_init)
                )
                self._send_whad_message(sync)
            elif self.__mode != SnifferMode.CONN_FOLLOW:
                # If we are just scanning for devices, report advertisement
                m = self.hub.ble.create_raw_pdu_received(
                    Direction.UNKNOWN,
                    bytes(BTLE(msg.body)),
                    access_address=0x8e89bed6,
                    rssi=msg.rssi,
                    conn_handle=0,
                    crc=msg.crc_rev,
                    channel=msg.chan,
                    crc_validity=True
                )
                self._send_whad_message(m)

        # Or we may also get some data from a sniffed connection
        elif isinstance(msg, DataMessage):

            # Do not report empty packet
            if not self.__show_empty and msg.data_length == 0:
                return

            # And send message from sniffed packet
            m = self.hub.ble.create_raw_pdu_received(
                    Direction.SLAVE_TO_MASTER if msg.data_dir else Direction.MASTER_TO_SLAVE,
                    bytes(BTLE(msg.body)),
                    access_address=msg.aa,
                    rssi=msg.rssi,
                    conn_handle=0,
                    crc=msg.crc_rev,
                    channel=msg.chan,
                    crc_validity=True
                )
            self._send_whad_message(m)
        else:
            print(msg)


    def change_transport_speed(self, speed):
        """Not supported.
        """
