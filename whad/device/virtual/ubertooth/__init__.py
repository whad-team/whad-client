from whad.exceptions import WhadDeviceNotFound
from whad.device.virtual import VirtualDevice
from whad.protocol.whad_pb2 import Message
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from whad import WhadDomain, WhadCapability
from whad.domain.ble.utils.phy import channel_to_frequency, frequency_to_channel
from whad.protocol.generic_pb2 import ResultCode
from whad.device.virtual.ubertooth.constants import UBERTOOTH_ID_VENDOR, UBERTOOTH_ID_PRODUCT, \
    CTRL_IN, CTRL_OUT, UBERTOOTH_POLL, UBERTOOTH_GET_SERIAL, UBERTOOTH_GET_REV_NUM, \
    MOD_BT_LOW_ENERGY, UBERTOOTH_SET_MOD, UBERTOOTH_STOP, UBERTOOTH_JAM_MODE, JAM_NONE, \
    JAM_CONTINUOUS, UBERTOOTH_SET_CLOCK, UBERTOOTH_SET_CRC_VERIFY, UBERTOOTH_RESET, \
    UBERTOOTH_BTLE_SNIFFING, UBERTOOTH_BTLE_PROMISC, UBERTOOTH_GET_ACCESS_ADDRESS, \
    UBERTOOTH_SET_ACCESS_ADDRESS, UBERTOOTH_SET_CHANNEL, UBERTOOTH_GET_CHANNEL, UBERTOOTH_BTLE_SET_TARGET
from whad.protocol.ble.ble_pb2 import SniffAdv, Start, Stop
from usb.core import find, USBError
from usb.util import get_string
from struct import unpack, pack

# Helpers functions
def get_ubertooth(id=0,serial=None):
    '''
    Returns an ubertooth USB object based on index or serial number.
    '''
    devices = list(find(idVendor=UBERTOOTH_ID_VENDOR, idProduct=UBERTOOTH_ID_PRODUCT,find_all=True))
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
        for ubertooth in find(idVendor=UBERTOOTH_ID_VENDOR, idProduct=UBERTOOTH_ID_PRODUCT,find_all=True):
            available_devices.append(UbertoothDevice(serial=get_string(ubertooth, ubertooth.iSerialNumber)))
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
            raise WhadDeviceNotFound

        self.__opened = False
        self.__index, self.__ubertooth = device
        super().__init__()

    def open(self):
        self.__ubertooth.set_configuration()
        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self._set_modulation(MOD_BT_LOW_ENERGY)
        self._set_jam_mode(JAM_NONE)
        self.__opened = True
        # Ask parent class to run a background I/O thread
        super().open()

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        if not self.__opened:
            raise WhadDeviceNotReady()
        data = self._ubertooth_ctrl_transfer_in(UBERTOOTH_POLL,512)
        if len(data) > 0:
            print(data.hex())

    def reset(self):
        self.__ubertooth.reset()

    # Virtual device whad message callbacks
    def _on_whad_ble_stop(self, message):
        self._stop()
        self.send_whad_command_result(ResultCode.SUCCESS)

    # Ubertooth low level communication primitives
    def _ubertooth_ctrl_transfer_in(self, request, size, timeout=100):
        try:
            received_data = self.__ubertooth.ctrl_transfer(CTRL_IN, request, 0, 0, size, timeout=timeout)
            received_data = received_data.tobytes()[1:]

        except USBError:
            received_data = b""

        return received_data

    def _ubertooth_ctrl_transfer_out(self, request, value=0, data=None, timeout=100):
        self.__ubertooth.ctrl_transfer(CTRL_OUT, request, value, 0, data, timeout=timeout)

    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.BtLE : (
                                (WhadCapability.Sniff | WhadCapability.Jam),
                                [SniffAdv, Start, Stop]
            )
        }
        return capabilities

    def _get_serial_number(self):
        serial_number = self._ubertooth_ctrl_transfer_in(UBERTOOTH_GET_SERIAL, 17)
        return serial_number

    def _get_url(self):
        url = "https://github.com/greatscottgadgets/ubertooth"
        return url.encode("utf-8")

    def _get_manufacturer(self):
        return get_string(self.__ubertooth, self.__ubertooth.iManufacturer).encode("utf-8")

    def _get_firmware_version(self):
        firmware_version = self._ubertooth_ctrl_transfer_in(UBERTOOTH_GET_REV_NUM,20)[2:].decode("utf-8")
        major, minor, revision = firmware_version.split("-")
        return (int(major), int(minor), int(revision.replace("R","")))

    # Ubertooth commands
    def _set_modulation(self, modulation=MOD_BT_LOW_ENERGY):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_SET_MOD, modulation)

    def _stop(self):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_STOP)

    def _set_jam_mode(self, mode=JAM_NONE):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_JAM_MODE, mode)

    def _reset_clock(self):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_SET_CLOCK, data=b"\x00\x00\x00\x00\x00\x00")

    def _set_crc_checking(self, enable=True):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_SET_CRC_VERIFY, int(enable))

    def _set_target(self, address="00:00:00:00:00:00"):
        data = bd_addr_to_bytes(address)[::-1] + b"\x30"
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_BTLE_SET_TARGET, data=data)

    def _set_channel(self, channel=37):
        frequency = channel_to_frequency(channel)
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_SET_CHANNEL, frequency)

    def _get_channel(self):
        frequency = unpack('H', self._ubertooth_ctrl_transfer_in(UBERTOOTH_GET_CHANNEL, 2))[0]
        return frequency_to_channel(frequency)

    def _set_access_address(self, access_address):
        data = pack("<I", access_address)
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_SET_ACCESS_ADDRESS, data=data)

    def _get_access_address(self):
        access_address = unpack("<I",self._ubertooth_ctrl_transfer_in(UBERTOOTH_GET_ACCESS_ADDRESS, 4))[0]
        return access_address

    def _enable_promiscuous_mode(self):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_BTLE_PROMISC)

    def _enable_advertisements_sniffing(self):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_BTLE_SNIFFING, 0)

    def _enable_connection_sniffing(self):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_BTLE_SNIFFING, 2)

    def _soft_reset(self):
        self._ubertooth_ctrl_transfer_out(UBERTOOTH_RESET)
