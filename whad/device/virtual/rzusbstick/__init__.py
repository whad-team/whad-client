from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from whad import WhadDomain, WhadCapability

from whad.hub.generic.cmdresult import CommandResult
from whad.hub.dot15d4 import Commands

from whad.device.virtual.rzusbstick.constants import RZUSBStickInternalStates, \
    RZUSBStickId, RZUSBStickModes, RZUSBStickEndPoints, RZUSBStickCommands, \
    RZUSBStickResponses
from usb.core import find, USBError, USBTimeoutError
from usb.util import get_string
from struct import unpack, pack
from time import sleep

# Helpers functions
def get_rzusbstick(id=0,bus=None, address=None):
    '''
    Returns a RZUSBStick USB object based on index or bus and address.
    '''
    devices = list(find(idVendor=RZUSBStickId.RZUSBSTICK_ID_VENDOR, idProduct=RZUSBStickId.RZUSBSTICK_ID_PRODUCT,find_all=True))
    if bus is not None and address is not None:
        for device in devices:
            if device.bus == bus and device.address == address:
                return (devices.index(device), device)
        # No device found with the corresponding bus/address, return None
        return None
    else:
        try:
            return (id, devices[id])
        except IndexError:
            return None

class RZUSBStickDevice(VirtualDevice):

    INTERFACE_NAME = "rzusbstick"

    @classmethod
    def list(cls):
        '''
        Returns a list of available RZUSBStick devices.
        '''
        available_devices = []
        for rzusbstick in find(idVendor=RZUSBStickId.RZUSBSTICK_ID_VENDOR, idProduct=RZUSBStickId.RZUSBSTICK_ID_PRODUCT,find_all=True):
            available_devices.append(RZUSBStickDevice(bus=rzusbstick.bus, address=rzusbstick.address))
        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in format "<bus>-<address>").
        '''
        return str(self.__rzusbstick.bus)+"-"+str(self.__rzusbstick.address)


    def __init__(self, index=0, bus=None, address=None):
        """
        Create device connection
        """
        device = get_rzusbstick(index,bus=bus,address=address)
        if device is None:
            raise WhadDeviceNotFound

        self.__opened = False
        self.__opened_stream = False
        self.__channel = 11
        self.__future_channel = 11
        self.__internal_state = RZUSBStickInternalStates.NONE
        self.__index, self.__rzusbstick = device
        super().__init__()

    def open(self):
        try:
            self.__rzusbstick.set_configuration()
        except USBError as err:
            if err.errno == 13:
                raise WhadDeviceAccessDenied("rzusbstick")
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
        if self.__opened_stream:
            try:
                data = self.__rzusbstick_read_packet()
            except USBTimeoutError:
                data = b""
            if data is not None and len(data) >= 1:
                if data[0] == RZUSBStickResponses.RZ_AIRCAPTURE_DATA and len(data) >= 10:
                    self.__input_header = data[:9]
                    self.__input_buffer = data[9:]
                    self.__input_buffer_length = data[1] - 9
                elif len(self.__input_header) > 0:
                    self.__input_buffer += data
                else:
                    self.__input_buffer = b""
                    self.__input_buffer_length = 0
                    self.__input_header = b""

                if len(self.__input_header) == 9 and self.__input_buffer_length == len(self.__input_buffer):
                    rssi = 3 * self.__input_header[6] - 91
                    valid_fcs = (self.__input_header[7] == 0x01)
                    packet = self.__input_buffer[:-1]
                    link_quality_indicator = self.__input_buffer[-1]
                    self._send_whad_zigbee_raw_pdu(packet, rssi=rssi, is_fcs_valid=valid_fcs)

    def reset(self):
        self.__rzusbstick.reset()

    def close(self):
        super().close()

    # Virtual device whad message builder
    def _send_whad_zigbee_raw_pdu(self, packet, rssi=None, is_fcs_valid=None, timestamp=None):
        pdu = packet[:-2]
        fcs = unpack("H",packet[-2:])[0]

        # Create a RawPduReceived message
        msg = self.hub.dot15d4.create_raw_pdu_received(
            self.__channel,
            pdu,
            fcs,
            fcs_validity=is_fcs_valid
        )

        # Set timestamp and RSSI if provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message

        self._send_whad_message(msg)


    # Virtual device whad message callbacks
    def _on_whad_dot15d4_stop(self, message):
        if self._stop():
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_dot15d4_send_raw(self, message):
        channel = message.channel

        if self._set_channel(channel):
            packet = message.pdu + pack("H",message.fcs)
            success = self._send_packet(packet)
        else:
            success = False
        self._send_whad_command_result(CommandResult.SUCCESS if success else CommandResult.ERROR)

    def _on_whad_dot15d4_sniff(self, message):
        channel = message.channel
        self.__future_channel = channel
        self.__internal_state = RZUSBStickInternalStates.SNIFFING
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_start(self, message):
        self.__input_buffer = b""
        self.__input_buffer_length = 0
        self.__input_header = b""
        if self._start():
            if self.__future_channel != self.__channel:
                self._set_channel(self.__future_channel)
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.ERROR)

    # RZUSBStick low level communication primitives

    def __rzusbstick_read_packet(self, timeout=200):
        return bytes(self.__rzusbstick.read(RZUSBStickEndPoints.RZ_PACKET_ENDPOINT, self.__rzusbstick.bMaxPacketSize0, timeout=timeout))

    def _rzusbstick_read_response(self, timeout=200):
        return bytes(self.__rzusbstick.read(RZUSBStickEndPoints.RZ_RESPONSE_ENDPOINT, self.__rzusbstick.bMaxPacketSize0, timeout=timeout))

    def _rzusbstick_send_command(self, command, data=b"", timeout=200):
        data = [command] + list(data)
        self.__rzusbstick.write(RZUSBStickEndPoints.RZ_COMMAND_ENDPOINT, data, timeout=timeout)
        return self._rzusbstick_read_response()[0] == RZUSBStickResponses.RZ_RESP_SUCCESS

    # Discovery related functions
    def _get_capabilities(self):
        if "KILLERB" in self.__rzusbstick.product:
            capabilities = {
                WhadDomain.Dot15d4 : (
                                    (WhadCapability.Sniff | WhadCapability.Inject),
                                    [Commands.Sniff, Commands.Send, Commands.Start, Commands.Stop]
                )
            }
        else:
            capabilities = {
                WhadDomain.Dot15d4 : (
                                    (WhadCapability.Sniff),
                                    [Commands.Sniff, Commands.Start, Commands.Stop]
                )
            }

        return capabilities

    def _get_manufacturer(self):
        if "KILLERB" in self.__rzusbstick.product:
            return "Joshua Wright (KillerBee version)".encode('utf-8')
        else:
            return (self.__rzusbstick.manufacturer + "(Factory version)").encode('utf-8')

    def _get_serial_number(self):
        return bytes.fromhex(
                                self.__rzusbstick.serial_number[:-1] +
                                "{:04x}".format(self.__rzusbstick.bus)  +
                                "{:04x}".format(self.__rzusbstick.address)
        )

    def _get_firmware_version(self):
        return (1, 0, 0)

    def _get_url(self):
        if "KILLERB" in self.__rzusbstick.product:
            return "https://github.com/riverloopsec/killerbee".encode('utf-8')
        else:
            return "https://www.microchip.com/en-us/development-tool/ATAVRRZUSBSTICK".encode('utf-8')

    # RZUSBStick commands

    def _stop(self):
        stream_closed = self._close_stream()
        stopped = self._set_mode(RZUSBStickModes.RZ_MODE_NONE)
        return stream_closed and stopped

    def _start(self):
        started = self._set_mode(RZUSBStickModes.RZ_MODE_AIRCAPTURE)
        stream_enabled = self._open_stream()
        return started and stream_enabled

    def _set_mode(self, mode=RZUSBStickModes.RZ_MODE_NONE):
        return self._rzusbstick_send_command(RZUSBStickCommands.RZ_SET_MODE, data=[mode])

    def _set_channel(self, channel=11):
        if channel < 11 or channel > 26:
            return False
        self._close_stream()
        success = self._rzusbstick_send_command(RZUSBStickCommands.RZ_SET_CHANNEL, data=[channel])
        if success:
            self.__channel = channel
        self._open_stream()
        return success

    def _get_channel(self):
        return self.__channel

    def _enable_jamming(self):
        return self._rzusbstick_send_command(RZUSBStickCommands.RZ_JAMMER_ON)

    def _disable_jamming(self):
        return self._rzusbstick_send_command(RZUSBStickCommands.RZ_JAMMER_OFF)

    def _open_stream(self):
        if not self.__opened_stream:
            success = self._rzusbstick_send_command(RZUSBStickCommands.RZ_OPEN_STREAM)
            self.__opened_stream = success
        return self.__opened_stream

    def _close_stream(self):
        if self.__opened_stream:
            success = self._rzusbstick_send_command(RZUSBStickCommands.RZ_CLOSE_STREAM)
            self.__opened_stream = not success
            return True
        return False

    def _send_packet(self, data):
        if len(data) >= 1 and len(data) <= 125:
            self._close_stream()
            success = self._rzusbstick_send_command(RZUSBStickCommands.RZ_INJECT_FRAME, bytes([len(data)])+data, timeout=700)
            self._open_stream()
            return success
