from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from whad import WhadDomain, WhadCapability
from whad.ble.utils.phy import channel_to_frequency, frequency_to_channel, crc, FieldsSize, is_access_address_valid
from whad.hub.ble import Direction, ChannelMap
from whad.hub.generic.cmdresult import CommandResult
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.ble.ble_pb2 import SniffAdv,SniffConnReq, SniffAccessAddress, Start, Stop, SniffActiveConn
from whad.device.virtual.ubertooth.constants import UbertoothId, \
    UbertoothTransfers, UbertoothModulations, UbertoothCommands, \
    UbertoothInternalState, UbertoothModes, UbertoothJammingModes
from whad.scapy.layers.ubertooth import Ubertooth_Hdr,UBERTOOTH_PACKET_TYPES, \
    BTLE_Promiscuous_Access_Address, BTLE_Promiscuous_CRCInit, BTLE_Promiscuous_Hop_Interval, \
    BTLE_Promiscuous_Hop_Increment
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_CONNECT_REQ, BTLE_DATA
from scapy.compat import raw
from usb.core import find, USBError
from usb.util import get_string
from struct import unpack, pack
from time import sleep

import logging
logger = logging.getLogger(__name__)

# Helpers functions
def get_ubertooth(id=0,serial=None):
    '''
    Returns an ubertooth USB object based on index or serial number.
    '''
    devices = list(find(idVendor=UbertoothId.UBERTOOTH_ID_VENDOR, idProduct=UbertoothId.UBERTOOTH_ID_PRODUCT,find_all=True))
    if serial is not None:
        for device in devices:
            if serial.lower() == get_string(device, device.iSerialNumber):
                return (devices.index(device), device)
        # No device found with the corresponding serial, return None
        return None
    else:
        try:
            return (id, devices[id])
        except IndexError:
            return None

class UbertoothDevice(VirtualDevice):

    INTERFACE_NAME = "ubertooth"

    @classmethod
    def list(cls):
        '''
        Returns a list of available Ubertooth devices.
        '''
        available_devices = []
        try:
            for ubertooth in find(idVendor=UbertoothId.UBERTOOTH_ID_VENDOR, idProduct=UbertoothId.UBERTOOTH_ID_PRODUCT,find_all=True):
                available_devices.append(UbertoothDevice(serial=get_string(ubertooth, ubertooth.iSerialNumber)))
        except ValueError as err:
            logger.warning("Cannot access Ubertooth, root privileges may be required.")
        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., serial number).
        '''
        return get_string(self.__ubertooth, self.__ubertooth.iSerialNumber)


    def __init__(self, index=0, serial=None):
        """
        Create device connection
        """
        device = get_ubertooth(index,serial)
        if device is None:
            raise WhadDeviceNotFound()

        self.__opened = False
        self.__address_filter = b"\xFF\xFF\xFF\xFF\xFF\xFF"
        self.__access_address = 0x8e89bed6
        self.__hop_interval = 0
        self.__hop_increment = 0
        self.__channel_map = 0
        self.__crc_init = 0x555555
        self.__channel = 37
        self.__show_advertisements = True
        self.__show_empty_packets = False
        self.__internal_state = UbertoothInternalState.NONE
        self.__index, self.__ubertooth = device
        super().__init__()

    def open(self):
        try:
            self.__ubertooth.set_configuration()
        except USBError as err:
            if err.errno == 13:
                raise WhadDeviceAccessDenied("ubertooth")
            else:
                raise WhadDeviceNotReady()
        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self.__opened = True
        # Ask parent class to run a background I/O thread
        super().open()

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        if not self.__opened:
            raise WhadDeviceNotReady()
        if self.__internal_state != UbertoothInternalState.NONE:
            data = self._ubertooth_ctrl_transfer_in(UbertoothCommands.UBERTOOTH_POLL,512)
            if len(data) > 0:
                packet = Ubertooth_Hdr(data)
                self.__channel = frequency_to_channel(2402+packet.channel)
                if UBERTOOTH_PACKET_TYPES[packet.packet_type] == "LE_PACKET":
                    timestamp = round(packet.clk_100ns/10) # convert into us timestamp
                    rssi = packet.rssi_min - 54
                    if self.__internal_state == UbertoothInternalState.ACCESS_ADDRESS_SNIFFING:
                        access_address = packet[BTLE:].access_addr
                        if is_access_address_valid(access_address):
                            self._send_whad_ble_aa_disc(access_address, timestamp, rssi)
                    else:
                        btle_packet = packet[BTLE:]
                        if self._filter(btle_packet):
                            self._send_whad_ble_raw_pdu(btle_packet, timestamp, rssi)
                        if (
                                self.__internal_state == UbertoothInternalState.NEW_CONNECTION_SNIFFING and
                                BTLE_CONNECT_REQ in btle_packet
                        ):
                            self.__access_address = btle_packet.AA
                            self.__channel_map = btle_packet.chM
                            self.__crc_init = btle_packet.crc_init
                            self.__hop_interval = btle_packet.interval
                            self.__hop_increment = btle_packet.hop
                            self._send_whad_ble_synchronized()
                elif BTLE_Promiscuous_Access_Address in packet:
                    self.__crc_init = 0
                    self.__channel_map = 0
                    self.__hop_interval = 0
                    self.__hop_increment = 0
                    self.__access_address = packet.access_address
                    self._send_whad_ble_synchronized()
                elif BTLE_Promiscuous_CRCInit in packet:
                    self.__crc_init = packet.crc_init
                    self.__channel_map = 0
                    self.__hop_interval = 0
                    self.__hop_increment = 0
                    self._send_whad_ble_synchronized()
                elif BTLE_Promiscuous_Hop_Interval in packet:
                    self.__channel_map = 0x1fffffffff
                    self.__hop_interval = packet.hop_interval
                    self.__hop_increment = 0
                    self._send_whad_ble_synchronized()
                elif BTLE_Promiscuous_Hop_Interval in packet:
                    self.__hop_increment = packet.hop_increment
                    self._send_whad_ble_synchronized()

                else:
                    print(data.hex())
                    packet.show()

    def reset(self):
        self.__internal_state = UbertoothInternalState.NONE
        self.__ubertooth.reset()

        self._set_jam_mode(UbertoothJammingModes.JAM_NONE)
        self._set_modulation(UbertoothModulations.MOD_BT_LOW_ENERGY)
        self._reset_clock()

    def close(self):
        self._soft_reset()
        super().close()

    # Virtual device whad message builder
    def _send_whad_ble_raw_pdu(self, packet, timestamp=None, rssi=None):

        access_address = packet.access_addr
        pdu = raw(packet)[FieldsSize.ACCESS_ADDRESS_SIZE:-FieldsSize.CRC_SIZE]
        sniffed_crc = raw(packet)[-FieldsSize.CRC_SIZE:]
        calculated_crc = crc(pdu,init=self.__crc_init)
        is_crc_valid = calculated_crc == sniffed_crc

        # Create a RawPduReceived message
        msg = self.hub.ble.create_raw_pdu_received(
            Direction.UNKNOWN,
            pdu,
            access_address,
            0,
            crc_validity=is_crc_valid,
            crc=packet.crc,
            channel=self.__channel
        )

        # Set RSSI and timestamp if provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        self._send_whad_message(msg)


    def _send_whad_ble_synchronized(self):
        # Create a Synchronized message
        msg = self.hub.ble.create_synchronized(
            self.__access_address,
            self.__hop_interval,
            self.__hop_increment,
            ChannelMap.from_int(self.__channel_map),
            self.__crc_init
        )

        # Send message
        self._send_whad_message(msg)


    def _send_whad_ble_aa_disc(self, access_address, timestamp, rssi):
        # Create an AccessAddressDiscovered
        msg = self.hub.ble.create_access_address_discovered(
            access_address,
            rssi,
            timestamp
        )

        # Send message
        self._send_whad_message(msg)

    # Virtual device whad message callbacks
    def _on_whad_ble_stop(self, message):
        self._stop()
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_sniff_conn(self, message):
        self.__access_address = message.access_address
        self._set_access_address(self.__access_address)
        self.__internal_state = UbertoothInternalState.EXISTING_CONNECTION_SNIFFING
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_sniff_adv(self, message):
        channel = message.channel
        # Address filtering is performed in python, ubertooth doesn't support it natively for adv only mode
        self.__address_filter = message.bd_address

        self.__access_address = 0x8e89bed6
        self.__crc_init = 0x555555
        self.__show_advertisements = True

        if self._set_channel(channel):
            self.__internal_state = UbertoothInternalState.ADVERTISEMENT_SNIFFING
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_ble_sniff_connreq(self, message):
        channel = message.channel
        self.__address_filter = b"\xFF\xFF\xFF\xFF\xFF\xFF"
        self.__show_empty_packets = message.show_empty_packets
        self.__show_advertisements = message.show_advertisements
        if self._set_channel(channel):
            self.__internal_state = UbertoothInternalState.NEW_CONNECTION_SNIFFING
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_ble_sniff_aa(self, message):
        self.__show_empty_packets = False
        self.__show_advertisements = False
        self.__internal_state = UbertoothInternalState.ACCESS_ADDRESS_SNIFFING
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_start(self, message):
        if self.__internal_state == UbertoothInternalState.ADVERTISEMENT_SNIFFING:
            self._enable_advertisements_sniffing()
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif self.__internal_state == UbertoothInternalState.NEW_CONNECTION_SNIFFING:
            self._enable_connection_sniffing()
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif (
                self.__internal_state == UbertoothInternalState.ACCESS_ADDRESS_SNIFFING or
                self.__internal_state == UbertoothInternalState.EXISTING_CONNECTION_SNIFFING
            ):
            self._enable_promiscuous_mode()
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.ERROR)

    # Software implementation features
    def _filter(self, packet):
        if BTLE_DATA in packet and packet.len == 0 and not self.__show_empty_packets:
            return False
        if BTLE_ADV in packet and not self.__show_advertisements:
            return False
        # No filtering if address is FF:FF:FF:FF:FF:FF
        if self.__address_filter == b"\xFF\xFF\xFF\xFF\xFF\xFF":
            return True
        elif hasattr(packet, "AdvA"):
            return packet.AdvA == self.__address_filter
        else:
            return False

    # Ubertooth low level communication primitives
    def _ubertooth_ctrl_transfer_in(self, request, size, timeout=100):
        try:
            received_data = self.__ubertooth.ctrl_transfer(UbertoothTransfers.CTRL_IN, request, 0, 0, size, timeout=timeout)
            received_data = received_data.tobytes()
            if len(received_data) == 1:
                received_data = b""
        except USBError:
            received_data = b""

        return received_data

    def _ubertooth_ctrl_transfer_out(self, request, value=0, data=None, timeout=100):
        try:
            self.__ubertooth.ctrl_transfer(UbertoothTransfers.CTRL_OUT, request, value, 0, data, timeout=timeout)
            return True
        except USBError:
            return False

    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.BtLE : (
                                (WhadCapability.Sniff | WhadCapability.Jam),
                                [SniffAdv, SniffConnReq, SniffAccessAddress, SniffActiveConn, Start, Stop]
            )
        }
        return capabilities

    def _get_serial_number(self):
        serial_number = self._ubertooth_ctrl_transfer_in(UbertoothCommands.UBERTOOTH_GET_SERIAL, 17)
        return serial_number

    def _get_url(self):
        url = "https://github.com/greatscottgadgets/ubertooth"
        return url.encode("utf-8")

    def _get_manufacturer(self):
        return get_string(self.__ubertooth, self.__ubertooth.iManufacturer).encode("utf-8")

    def _get_firmware_version(self):
        firmware_version = self._ubertooth_ctrl_transfer_in(UbertoothCommands.UBERTOOTH_GET_REV_NUM,20)[2:].decode("utf-8")
        if "git" in firmware_version:
            try:
                major, minor, revision = 1, 7, int(firmware_version.split("-")[1], 16)
            except ValueError:
                major, minor, revision = 1, 7, 0
        else:
            major, minor, revision = firmware_version.split("-")
            major, minor, revision = int(major), int(minor), int(revision.replace("R",""))
        return (major, minor, revision)

    # Ubertooth commands
    def _set_modulation(self, modulation=UbertoothModulations.MOD_BT_LOW_ENERGY):
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_SET_MOD, modulation)

    def _stop(self):
        self.__internal_state = UbertoothInternalState.NONE
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_STOP)

    def _set_jam_mode(self, mode=UbertoothJammingModes.JAM_NONE):
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_JAM_MODE, mode)

    def _reset_clock(self):
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_SET_CLOCK, data=b"\x00\x00\x00\x00\x00\x00")

    def _set_crc_checking(self, enable=True):
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_SET_CRC_VERIFY, int(enable))

    def _set_target(self, address=b"\x00\x00\x00\x00\x00\x00"):
        data = address + b"\x30"
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_BTLE_SET_TARGET, data=data)

    def _set_channel(self, channel=37):
        frequency = channel_to_frequency(channel)
        if frequency is not None:
            self.__channel = channel
            self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_SET_CHANNEL, frequency)
            return True
        else:
            return False

    def _get_channel(self):
        frequency = unpack('H', self._ubertooth_ctrl_transfer_in(UbertoothCommands.UBERTOOTH_GET_CHANNEL, 2))[0]
        return frequency_to_channel(frequency)

    def _set_access_address(self, access_address):
        data = pack("<I", access_address)
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_SET_ACCESS_ADDRESS, data=data)

    def _get_access_address(self):
        access_address = unpack("<I",self._ubertooth_ctrl_transfer_in(UbertoothCommands.UBERTOOTH_GET_ACCESS_ADDRESS, 4))[0]
        return access_address

    def _enable_promiscuous_mode(self):
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_BTLE_PROMISC)

    def _enable_advertisements_sniffing(self):
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_BTLE_SNIFFING, 0)

    def _enable_connection_sniffing(self):
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_BTLE_SNIFFING, 2)

    def _soft_reset(self):
        self._ubertooth_ctrl_transfer_out(UbertoothCommands.UBERTOOTH_RESET)
