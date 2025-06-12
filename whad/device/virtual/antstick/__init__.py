"""
ANT Stick adaptation layer for WHAD.
"""
import logging
from threading import  Lock
from time import sleep, time

from usb.util import find_descriptor, endpoint_direction, ENDPOINT_IN, ENDPOINT_OUT
from usb.core import find, USBError, USBTimeoutError
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device import VirtualDevice
from whad.hub.ant import Commands as AntCommands

from whad.scapy.layers.antstick import ANTStick_Message, ANTStick_Command_Request_Message, \
    ANTStick_Requested_Message_Serial_Number, ANTStick_Requested_Message_ANT_Version
from whad.device.virtual.antstick.constants import AntStickIds

logger = logging.getLogger(__name__)

def get_antstick(index=0, bus=None, address=None):
    '''
    Returns an ANTStick USB object based on index or bus & address.
    '''
    devices = list(find(idVendor=AntStickIds.ANTSTICK_ID_VENDOR,
                        idProduct=AntStickIds.ANTSTICK_ID_PRODUCT,find_all=True)) 

    devices += list(find(idVendor=AntStickIds.ANTSTICK_ID_VENDOR,
                        idProduct=AntStickIds.ANTSTICK2_ID_PRODUCT,find_all=True))

    if bus is not None and address is not None:
        for device in devices:
            if device.bus == bus and device.address == address:
                return (devices.index(device), device)
        # No device found with the corresponding bus/address, return None
        return None

    try:
        return (index, devices[index])
    except IndexError:
        return None



class ANTStickDevice(VirtualDevice):
    """ANTStick virtual device implementation.
    """

    INTERFACE_NAME = "antstick"

    @classmethod
    def list(cls):
        '''
        Returns a list of available ANTStick devices.
        '''
        available_devices = []
        try:
            for antstick in (
                list(find(
                    idVendor=AntStickIds.ANTSTICK_ID_VENDOR,
                    idProduct=AntStickIds.ANTSTICK_ID_PRODUCT,
                    find_all=True
                )) + 
                list(find(
                    idVendor=AntStickIds.ANTSTICK_ID_VENDOR,
                    idProduct=AntStickIds.ANTSTICK2_ID_PRODUCT,
                    find_all=True
                ))
            ):
                available_devices.append(ANTStickDevice(bus=antstick.bus, address=antstick.address))
        except ValueError:
            logger.warning("Cannot access ANTStick, root privileges may be required.")

        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in
        format "<bus>-<address>").
        '''
        return str(self.__antstick.bus)+"-"+str(self.__antstick.address)


    def __init__(self, index=0, bus=None, address=None):
        """
        Create device connection
        """
        device = get_antstick(index,bus=bus,address=address)
        if device is None:
            raise WhadDeviceNotFound
        _, self.__antstick = device
        self.__lock = Lock()
        super().__init__()

    def reset(self):
        self.__antstick.reset()

    def _configure_endpoints(self):
        # Code from openant project
        cfg = self.__antstick.get_active_configuration()
        intf = cfg[(0, 0)]

        self.__out_endpoint = find_descriptor(
            intf,
            # match the first OUT endpoint
            custom_match=lambda e: endpoint_direction(e.bEndpointAddress)
            == ENDPOINT_OUT,
        )

        self.__in_endpoint = find_descriptor(
            intf,
            # match the first OUT endpoint
            custom_match=lambda e: endpoint_direction(e.bEndpointAddress)
            == ENDPOINT_IN,
        )



    def open(self):
        # Try detach any kernel driver
        if self.__antstick.is_kernel_driver_active(0):
            self.__antstick.detach_kernel_driver(0)
        try:
            self.__antstick.set_configuration()
        except USBError as err:
            if err.errno == 13:
                raise WhadDeviceAccessDenied("antstick") from err
            raise WhadDeviceNotReady() from err

        self.__antstick.reset()
        self._configure_endpoints()

        print("serial: ", self._get_serial_number())

        print("ant_ver: ",self._get_ant_version())

        self._dev_id = None
        #self._fw_author = self._get_manufacturer()
        #self._fw_url = self._get_url()
        #self._fw_version = self._get_firmware_version()
        #self._dev_capabilities = self._get_capabilities()

    def _get_serial_number(self):
        response = self._antstick_send_command(ANTStick_Command_Request_Message(message_id_req=0x61))
        if ANTStick_Requested_Message_Serial_Number in response:
            return response.serial_number
        return None        


    def _get_ant_version(self):
        response = self._antstick_send_command(ANTStick_Command_Request_Message(message_id_req=0x3E))
        if ANTStick_Requested_Message_ANT_Version in response:
            return response.version
        return None     

    def _antstick_send_command(self, command, timeout=200, no_response=False):
        data = bytes(ANTStick_Message() / command)
        with self.__lock:
            try:
                self.__antstick.write(self.__out_endpoint,
                                     data, timeout=timeout)
            except USBTimeoutError:
                return False
            response = self._antstick_read_response()

        # If we have a response, return it
        if not no_response:
            return response

        # Success
        return True

    def _antstick_read_response(self, timeout=200):
        try:
            msg = bytes(self.__antstick.read(self.__in_endpoint,
                                             64, timeout=timeout))
            print("< ", msg.hex())
            ANTStick_Message(msg).show()
            return ANTStick_Message(msg)
        except USBTimeoutError:
            return None

if __name__ == '__main__':
    print(ANTStickDevice.list())