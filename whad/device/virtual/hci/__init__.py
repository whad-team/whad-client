from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from scapy.layers.bluetooth import BluetoothUserSocket, BluetoothSocketError, \
    HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Reset, HCI_Cmd_Set_Event_Mask
from whad.device.virtual.hci.hciconfig import HCIConfig
from select import select
from os import read, write
from time import sleep
from queue import Queue

def get_hci(self, index=0):
    '''
    Returns an HCI socket based on adapter index.
    '''
    try:
        socket = BluetoothUserSocket(index)
        return socket
    except BluetoothSocketError as err:
        try:
            HCIConfig.down(index)
            socket = BluetoothUserSocket(index)
            return socket
        except BluetoothSocketError as err:
            return None



class HCIDevice(VirtualDevice):

    INTERFACE_NAME = "hci"

    @classmethod
    def list(cls):
        '''
        Returns a list of available HCI devices.
        '''
        available_devices = []
        devices_ids = HCIConfig.list()
        for device_id in devices_ids:
            available_devices.append(HCIDevice(index=device_id))
        return available_devices

    def __init__(self, index=0):
        self.__index = index
        self.__socket = None
        self.__fileno = None
        self.__opened = False
        self.__hci_responses = Queue()
        super().__init__()

    @property
    def identifier(self):
        '''
        Returns the identifier of the device (e.g., index).
        '''
        return "hci" + str(self.__index)


    def open(self):
        """
        Open device.
        """
        if not self.__opened:
            self.__socket = get_hci(self.__index)
            self.__opened = True

            # Ask parent class to run a background I/O thread
            super().open()

    def close(self):
        """
        Close current device.
        """
        # Ask parent class to stop I/O thread
        super().close()

        # Close underlying device.
        self.__socket.close()
        self.__fileno = None
        self.__opened = False


    def write(self, data):
        """
        Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes data: Data to write
        :returns: number of bytes written to the device
        """
        if not self.__opened:
            raise WhadDeviceNotReady()
        self.__socket.send(data)

    def read(self):
        """
        Fetches data from the device, if there is any data to read. We call select()
        to make sure data is waiting to be read before reading it.
        """

        if not self.__opened:
            raise WhadDeviceNotReady()

        if self.__socket.readable():
            event = self.__socket.recv()
            if event.type == 0x4 and event.code == 0xe:
                self.__hci_responses.put(event)
            else:
                print(event)


    def _wait_response(self, timeout=None):
        response = self.__hci_responses.get(block=True, timeout=timeout)
        return response

    def _write_command(self, command):
        """
        Writes an HCI command and returns the response.
        """
        hci_command = HCI_Hdr()/HCI_Command_Hdr()/command
        self.__socket.send(hci_command)
        response = self._wait_response()
        while response.opcode != hci_command.opcode:
            response = self._wait_response()
        return response

    def reset(self):
        self._reset()
        self._dev_id = b"\xFF"*16
        self._fw_author = b"coucou"
        self._fw_url = b"coucou"
        self._fw_version = (1,2,3)
        self._dev_capabilities = {}

    def _reset(self):
        print(self.__socket.fileno())
        print(self._write_command(HCI_Cmd_Reset()))
        print(self._write_command(HCI_Cmd_Set_Event_Mask(mask=b"\xFF\xFF\xFB\xFF\x07\xF8\xBF\x3D")))
