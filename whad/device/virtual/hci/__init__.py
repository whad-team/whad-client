from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.protocol.ble.ble_pb2 import SetBdAddress
from whad import WhadDomain
from scapy.layers.bluetooth import BluetoothUserSocket, BluetoothSocketError, \
    HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Reset, HCI_Cmd_Set_Event_Filter, \
    HCI_Cmd_Connect_Accept_Timeout, HCI_Cmd_Set_Event_Mask, HCI_Cmd_LE_Host_Supported, \
    HCI_Cmd_Read_BD_Addr, HCI_Cmd_Complete_Read_BD_Addr
from whad.device.virtual.hci.hciconfig import HCIConfig
from whad.device.virtual.hci.constants import LE_STATES, ADDRESS_MODIFICATION_VENDORS
from whad.scapy.layers.hci import HCI_Cmd_Read_Local_Version_Information, \
    HCI_Cmd_Complete_Read_Local_Version_Information, HCI_VERSIONS, BT_MANUFACTURERS, \
    HCI_Cmd_Read_Local_Name, HCI_Cmd_Complete_Read_Local_Name, HCI_Cmd_LE_Read_Supported_States, \
    HCI_Cmd_Complete_LE_Read_Supported_States, HCI_Cmd_CSR_Write_BD_Address, HCI_Cmd_CSR_Reset, \
    HCI_Cmd_TI_Write_BD_Address, HCI_Cmd_BCM_Write_BD_Address, HCI_Cmd_Zeevo_Write_BD_Address, \
    HCI_Cmd_Ericsson_Write_BD_Address, HCI_Cmd_ST_Write_BD_Address
from select import select
from os import read, write
from time import sleep
from queue import Queue

def get_hci(index):
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

    def __init__(self, index):
        super().__init__()
        self.__index = index
        self.__socket = None
        self.__opened = False
        self.__hci_responses = Queue()
        self._dev_capabilities = None
        self._bd_address = None
        self._fw_version = None
        self._fw_url = None
        self._fw_author = None
        self._dev_id = None
        self._manufacturer = None

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
            if self.__socket is None:
                raise WhadDeviceNotReady()
            self.__opened = True

            # Ask parent class to run a background I/O thread
            super().open()
            if not self._initialize():
                raise WhadDeviceNotReady()

    def close(self):
        """
        Close current device.
        """
        # Ask parent class to stop I/O thread
        super().close()

        # Close underlying device.
        self.__socket.close()
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
        try:
            if self.__socket is not None and self.__socket.readable():
                event = self.__socket.recv()
                if event.type == 0x4 and event.code == 0xe:
                    self.__hci_responses.put(event)
                else:
                    print(event)
        except (BrokenPipeError, OSError):
            print("Error, waiting...")
            sleep(1)

    def _wait_response(self, timeout=None):
        response = self.__hci_responses.get(block=True, timeout=timeout)
        return response

    def _write_command(self, command, wait_response=True):
        """
        Writes an HCI command and returns the response.
        """
        hci_command = HCI_Hdr()/HCI_Command_Hdr()/command
        self.__socket.send(hci_command)
        if wait_response:
            response = self._wait_response()
            while response.opcode != hci_command.opcode:
                response = self._wait_response()
        else:
            response = None
        return response

    def reset(self):
        self.__bd_address = self._read_BD_address()
        self.__local_name = self._read_local_name()
        self._fw_version, self._manufacturer = self._read_local_version_information()
        self._fw_author = self._manufacturer
        self._dev_id = self._generate_dev_id()
        self._fw_url = b"<unknown>"
        self._dev_capabilities = self._get_capabilities()

    def _generate_dev_id(self):
        devid = (bytes.fromhex(self.__bd_address.replace(":","")) + self.__local_name)[:16]
        print(devid)
        if len(devid) < 16:
            devid += b"\x00" * (16 - len(devid))
        return devid

    def _get_capabilities(self):
        supported_states = self._read_LE_supported_states()
        _, self._manufacturer = self._read_local_version_information()
        capabilities = 0
        supported_commands = []
        for state in supported_states:
            name, cap, commands = state
            capabilities = capabilities | cap
            supported_commands += commands

        if self._manufacturer in ADDRESS_MODIFICATION_VENDORS:
            supported_commands += [SetBdAddress]

        supported_commands = list(set(supported_commands))
        capabilities = {
            WhadDomain.BtLE : (
                                capabilities,
                                supported_commands
            )
        }
        return capabilities

    def _reset(self):
        """
        Reset HCI device.
        """
        response = self._write_command(HCI_Cmd_Reset())
        return response.status == 0x00


    def _set_event_filter(self, type=0):
        """
        Configure HCI device event filter.
        """
        response = self._write_command(HCI_Cmd_Set_Event_Filter(type=type))
        return response.status == 0x00

    def _set_event_mask(self, mask=b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d"):
        """
        Configure HCI device event mask.
        """
        response = self._write_command(HCI_Cmd_Set_Event_Mask(mask=mask))
        return response.status == 0x00

    def _set_connection_accept_timeout(self, timeout=32000):
        """
        Configure HCI device connection accept timeout.
        """
        response = self._write_command(HCI_Cmd_Connect_Accept_Timeout(timeout=timeout))
        return response.status == 0x00

    def _indicates_LE_support(self):
        """
        Indicates to HCI Device that the Host supports Low Energy mode.
        """
        response = self._write_command(HCI_Cmd_LE_Host_Supported())
        return response.status == 0x00

    def _initialize(self):
        """
        Initialize HCI Device and returns boolean indicating if it can be used by WHAD.
        """
        success = (
                self._reset() and
                self._set_event_filter(0) and
                self._set_connection_accept_timeout(32000) and
                self._set_event_mask(b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d") and
                self._indicates_LE_support()
        )

        return success

    def _read_BD_address(self):
        """
        Read BD Address used by the HCI device.
        """
        response = self._write_command(HCI_Cmd_Read_BD_Addr())
        if response.status == 0x00 and HCI_Cmd_Complete_Read_BD_Addr in response:
            return response.addr
        return None

    def _read_local_name(self):
        """
        Read local name used by the HCI device.
        """
        response = self._write_command(HCI_Cmd_Read_Local_Name())
        if response.status == 0x00 and HCI_Cmd_Complete_Read_Local_Name in response:
            return response.local_name
        return None

    def _read_local_version_information(self):
        """
        Read local version information used by the HCI device.
        """
        response = self._write_command(HCI_Cmd_Read_Local_Version_Information())
        if response.status == 0x00 and HCI_Cmd_Complete_Read_Local_Version_Information in response:
            version = [int(v) for v in HCI_VERSIONS[response.hci_version].split(".")]
            version += [response.hci_subversion]
            manufacturer = BT_MANUFACTURERS[response.company_identifier].encode("utf-8")
            return version, manufacturer
        return None

    def _read_LE_supported_states(self):
        """
        Returns the list of Bluetooth Low Energy states supported by the HCI device.
        """
        response = self._write_command(HCI_Cmd_LE_Read_Supported_States())
        if response.status == 0x00 and HCI_Cmd_Complete_LE_Read_Supported_States in response:
            states = []
            for bit_position, state in LE_STATES.items():
                if response.supported_states & (1 << bit_position) != 0:
                    states.append(state)
            return states
        else:
            return None

    def _set_BD_address(self, bd_address="11:22:33:44:55:66"):
        """
        Modify the BD address (if supported by the HCI device).
        """
        if self._dev_capabilities is None:
            self._dev_capabilities = self._get_capabilities()

        if SetBdAddress in self._dev_capabilities[WhadDomain.BtLE][1]:
            print("Address modification supported !")
            if self._manufacturer == b'Qualcomm Technologies International, Ltd. (QTIL)':
                # Keep in cache existing devices
                existing_devices = devices = HCIConfig.list()

                # Write BD address and reset with vendor specific commands
                self._write_command(HCI_Cmd_CSR_Write_BD_Address(addr=bd_address), wait_response=False)
                self._write_command(HCI_Cmd_CSR_Reset(), wait_response=False)
                # We are forced to close the socket and reopen it here...
                self.__socket.close()
                # Add a delay to prevent error
                sleep(0.5)

                # The index may have changed, find it automatically and reconfigure self.__index
                success = False
                while not success:
                    devices = HCIConfig.list()
                    if self.__index not in devices:
                        for i in existing_devices:
                            if i != self.__index:
                                devices.remove(i)
                        if len(devices) > 0:
                            self.__index = devices[0]
                            success = True

                # If all goes right, we should be able to open a new socket
                self.__socket = get_hci(self.__index)
                # Initialize a new socket
                self._initialize()

            else:
                # For the other manufacturers, we only need to pick the right command and perform a reset
                BD_ADDRESS_MODIFICATION_MAP = {
                    b'Texas Instruments Inc.' : HCI_Cmd_TI_Write_BD_Address,
                    b'Broadcom Corporation' : HCI_Cmd_BCM_Write_BD_Address,
                    b'Zeevo, Inc.' : HCI_Cmd_Zeevo_Write_BD_Address,
                    b'Ericsson Technology Licensing' : HCI_Cmd_Ericsson_Write_BD_Address,
                    b'Integrated System Solution Corp.' : HCI_Cmd_Ericsson_Write_BD_Address,
                    b'ST Microelectronics' : HCI_Cmd_ST_Write_BD_Address
                }
                command = BD_ADDRESS_MODIFICATION_MAP[self._manufacturer]
                self._write_command(command, wait_response=False)
                self._reset()

            # Check the modification success and re-generate device ID
            self.__bd_address = self._read_BD_address()
            self._dev_id = self._generate_dev_id()
            return self._bd_address == bd_address

        else:
            print("Address modification not supported.")
            return False
