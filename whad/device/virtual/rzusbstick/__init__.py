from whad.exceptions import WhadDeviceNotFound
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from whad import WhadDomain, WhadCapability
from whad.protocol.generic_pb2 import ResultCode
from whad.protocol.zigbee.zigbee_pb2 import Sniff, Send, Start, Stop
from whad.device.virtual.rzusbstick.constants import RZUSBStickInternalStates, \
    RZUSBStickId, RZUSBStickModes, RZUSBStickEndPoints, RZUSBStickCommands
from usb.core import find, USBError
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

class RZUSBStick(VirtualDevice):

    INTERFACE_NAME = "rzusbstick"

    @classmethod
    def list(cls):
        '''
        Returns a list of available RZUSBStick devices.
        '''
        available_devices = []
        for rzusbstick in find(idVendor=RZUSBStickId.RZUSBSTICK_ID_VENDOR, idProduct=RZUSBStickId.RZUSBSTICK_ID_PRODUCT,find_all=True):
            available_devices.append(RZUSBStick(bus=rzusbstick.bus, address=rzusbstick.address))
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
        self.__internal_state = RZUSBStickInternalStates.NONE
        self.__index, self.__rzusbstick = device
        super().__init__()

    def open(self):
        self.__rzusbstick.set_configuration()
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
        self.__input_buffer = b""
        self.__input_buffer_length = 0
        if self.__opened_stream:
            data = self.__rzusbstick_read_packet()
            if data is not None and len(data) >= 1:
                if data[0] == RZUSBStickResponses.RZ_AIRCAPTURE_DATA and len(data) >= 10:
                    self.__input_buffer = data[9:]
                    self.__input_buffer_length = data[1]
    def reset(self):
        self.__rzusbstick.reset()

    def close(self):
        super().close()

    # Virtual device whad message builder

    # Virtual device whad message callbacks
    def _on_whad_zigbee_stop(self, message):
        if self._stop():
            self._send_whad_command_result(ResultCode.SUCCESS)
        else:
            self._send_whad_command_result(ResultCode.ERROR)

    def _on_whad_zigbee_sniff(self, message):
        channel = message.channel

        if self._set_channel(channel):
            self.__internal_state = RZUSBStickInternalStates.SNIFFING
            self._send_whad_command_result(ResultCode.SUCCESS)
        else:
            self._send_whad_command_result(ResultCode.PARAMETER_ERROR)

    def _on_whad_zigbee_start(self, message):
        if self._start():
            self._send_whad_command_result(ResultCode.SUCCESS)
        else:
            self._send_whad_command_result(ResultCode.ERROR)

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
                WhadDomain.Zigbee : (
                                    (WhadCapability.Sniff | WhadCapability.Inject),
                                    [Sniff, Send, Start, Stop]
                )
            }
        else:
            capabilities = {
                WhadDomain.Zigbee : (
                                    (WhadCapability.Sniff),
                                    [Sniff, Start, Stop]
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
            data += b"\x00\x00" # FCS bytes
            return self._rzusbstick_send_command(RZUSBStickCommands.RZ_INJECT_FRAME, bytes([len(data)+data]))
