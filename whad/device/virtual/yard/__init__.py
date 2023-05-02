from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.device.virtual.yard.constants import YardStickOneId, YardStickOneEndPoints, \
    YardApplications, YardSystemCommands, YardRadioStructure, YardRFStates, YardMemoryRegisters
from whad.helpers import message_filter,is_message_type
from whad import WhadDomain, WhadCapability
from whad.protocol.generic_pb2 import ResultCode
from usb.core import find, USBError, USBTimeoutError
from usb.util import get_string
from struct import unpack, pack
from time import sleep
from queue import Queue, Empty

# Helpers functions
def get_yardstickone(id=0,bus=None, address=None):
    '''
    Returns a YardStickOne USB object based on index or bus and address.
    '''
    devices = list(find(idVendor=YardStickOneId.YARD_ID_VENDOR, idProduct=YardStickOneId.YARD_ID_PRODUCT,find_all=True))
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

class YardStickOneDevice(VirtualDevice):

    INTERFACE_NAME = "yardstickone"

    @classmethod
    def list(cls):
        '''
        Returns a list of available RZUSBStick devices.
        '''
        available_devices = []
        for yard in find(idVendor=YardStickOneId.YARD_ID_VENDOR, idProduct=YardStickOneId.YARD_ID_PRODUCT,find_all=True):
            available_devices.append(YardStickOneDevice(bus=yard.bus, address=yard.address))
        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in format "<bus>-<address>").
        '''
        return str(self.__yard.bus)+"-"+str(self.__yard.address)


    def __init__(self, index=0, bus=None, address=None):
        """
        Create device connection
        """
        device = get_yardstickone(index,bus=bus,address=address)
        if device is None:
            raise WhadDeviceNotFound
        self.__opened_stream = False
        self.__in_buffer = b""
        self.__queue = Queue()
        self.__opened = False
        self.__index, self.__yard = device
        super().__init__()

    def open(self):
        try:
            self.__yard.set_configuration()
        except USBError as err:
            if err.errno == 13:
                raise WhadDeviceAccessDenied("yardstickone")
            else:
                raise WhadDeviceNotReady()
        self.reset()
        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self.__opened_stream = True
        self.__opened = True

        self.radio_structure = YardRadioStructure(self._poke, self._peek)
        print(self.radio_structure)
        self._set_idle_mode()
        # Ask parent class to run a background I/O thread
        super().open()

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        if not self.__opened:
            raise WhadDeviceNotReady()

        if False:
            try:
                data = self._yard_read_response()
                self.__in_buffer += data
                print(self.__in_buffer)
                if self.__in_buffer.startswith(b"@"):
                    if len(self.__in_buffer) >= 3:
                        size = unpack("<H", self.__in_buffer[3:5])[0]
                        if len(self.__in_buffer) >= 5 + size:
                            app = self.__in_buffer[1]
                            verb = self.__in_buffer[2]
                            data = self.__in_buffer[5:5+size]
                            self.__queue.put((app, verb, data))
                            self.__in_buffer = self.__in_buffer[5+size:]

            except USBTimeoutError:
                pass

    def reset(self):
        value = self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.RESET,
            b"RESET_NOW\x00"
        )

    def close(self):
        super().close()

    # Yard Stick One low level communication primitives

    def _yard_read_response(self, timeout=500):
        try:
            response = bytes(self.__yard.read(YardStickOneEndPoints.IN_ENDPOINT, 500, timeout=timeout))
            if len(response) >= 3:
                size = unpack("<H", response[3:5])[0]
                if len(response) >= 5 + size:
                    app = response[1]
                    verb = response[2]
                    data = response[5:5+size]
                    return app, verb, data
        except USBTimeoutError:
            response = (None, None, None)
        return response

    def _yard_send_command(self, app, command, data=b"", timeout=500):
        message = bytes([app, command]) + pack("<H", len(data)) + data
        recv_app, recv_verb, recv_data = None, None, None
        while recv_app != app and recv_verb != command:
            print(">", message.hex())
            self.__yard.write(YardStickOneEndPoints.OUT_ENDPOINT, message, timeout=timeout)
            recv_app, recv_verb, recv_data = self._yard_read_response()
        return recv_data

    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.Phy : (
                                (WhadCapability.Sniff),
                                []
            )
        }

        return capabilities

    def _get_manufacturer(self):
        return get_string(self.__yard, self.__yard.iManufacturer).encode('utf-8')

    def _get_serial_number(self):

        return bytes.fromhex(
                                self.__yard.serial_number +
                                "{:04x}".format(self.__yard.bus)  +
                                "{:04x}".format(self.__yard.address)
        )

    def _get_firmware_version(self):
        response = self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.BUILDTYPE
        )
        revision = int(response.split(b" r")[1][:-1])
        return (revision, 0, 0)

    def _get_url(self):
        #print(self._peek(0xdf00, 0x3e).hex())
        return "https://github.com/atlas0fd00m/rfcat".encode('utf-8')

    def _peek(self, address, size):
        return self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.PEEK,
            pack("<HH", size, address)
        )

    def _poke(self, address, data=b""):
        return self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.POKE,
            pack("<H", address) + data
        )

    def _set_rf_mode(self, mode):
        self._rf_mode = mode
        return self._yard_send_command(
            YardApplications.SYSTEM,
            YardSystemCommands.RFMODE,
            bytes([mode])
        )

    def _set_tx_mode(self):
        self._set_rf_mode(YardRFStates.STX)

    def _set_rx_mode(self):
        self._set_rf_mode(YardRFStates.SRX)

    def _set_idle_mode(self):
        self._set_rf_mode(YardRFStates.SIDLE)

    def _strobe_tx_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.STX]))

    def _strobe_rx_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.SRX]))

    def _strobe_idle_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.SIDLE]))

    def _strobe_cal_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.SCAL]))

    def _strobe_fstxon_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([YardRFStates.SFSTXON]))

    def _strobe_return_mode(self):
        self._poke(YardMemoryRegisters.RFST, bytes([self._rf_mode]))
