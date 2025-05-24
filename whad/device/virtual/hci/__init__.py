"""
Host/controller interface adaptation layer.
"""
import logging
from time import sleep
from queue import Queue, Empty
from struct import unpack

# Scapy layers for HCI
from scapy.layers.bluetooth import BluetoothSocketError, BluetoothUserSocket, \
    HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Reset, HCI_Cmd_Set_Event_Filter, \
    HCI_Cmd_Set_Event_Mask, HCI_Cmd_Write_LE_Host_Support, \
    HCI_Cmd_Read_BD_Addr, HCI_Cmd_Complete_Read_BD_Addr, HCI_Cmd_LE_Set_Scan_Enable, \
    HCI_Cmd_LE_Set_Scan_Parameters, HCI_Cmd_LE_Create_Connection, HCI_Cmd_Disconnect, \
    HCI_Cmd_LE_Set_Advertise_Enable, HCI_Cmd_LE_Set_Advertising_Data, \
    HCI_Event_Disconnection_Complete, HCI_Cmd_LE_Set_Scan_Response_Data, \
    HCI_Cmd_LE_Set_Random_Address, HCI_Cmd_LE_Long_Term_Key_Request_Reply, \
    HCI_Cmd_LE_Enable_Encryption, HCI_Cmd_LE_Set_Advertising_Parameters, \
    HCI_Cmd_LE_Read_Buffer_Size_V1, HCI_Cmd_Read_Local_Name, HCI_Cmd_Complete_Read_Local_Name, \
    HCI_Cmd_Complete_Read_Local_Version_Information, HCI_Cmd_Read_Local_Version_Information, \
    HCI_Cmd_Write_Connect_Accept_Timeout, HCI_Cmd_LE_Read_Local_Supported_Features, \
    HCI_Cmd_LE_Read_Filter_Accept_List_Size, HCI_Cmd_LE_Clear_Filter_Accept_List, \
    EIR_Hdr

from whad.scapy.layers.bluetooth import HCI_Cmd_LE_Complete_Read_Buffer_Size, \
    HCI_Cmd_Read_Buffer_Size, HCI_Cmd_Complete_Read_Buffer_Size, HCI_Cmd_LE_Set_Event_Mask, \
    HCI_Cmd_Read_Local_Supported_Commands, HCI_Cmd_Complete_Supported_Commands, \
    HCI_Cmd_Read_Local_Supported_Features, HCI_Cmd_Complete_Supported_Features, \
    HCI_Cmd_LE_Complete_Read_Filter_Accept_List_Size, HCI_Cmd_LE_Complete_Supported_Features, \
    HCI_Cmd_LE_Write_Suggested_Default_Data_Length, HCI_Cmd_LE_Read_Suggested_Default_Data_Length, \
    HCI_Cmd_LE_Complete_Suggested_Default_Data_Length, HCI_Cmd_Write_Simple_Pairing_Mode, \
    HCI_Cmd_Write_Default_Link_Policy_Settings, HCI_Cmd_LE_Read_Advertising_Physical_Channel_Tx_Power, \
    HCI_Cmd_Complete_LE_Advertising_Tx_Power_Level

# Whad
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied, \
    WhadDeviceUnsupportedOperation, WhadDeviceError
from whad.device import VirtualDevice

# Whad hub
from whad.hub.discovery import Domain
from whad.hub.generic.cmdresult import CommandResult
from whad.hub.discovery import Capability
from whad.hub.ble import Direction as BleDirection, Commands, AddressType, BDAddress

# Whad custom layers
from whad.scapy.layers.hci import HCI_VERSIONS, BT_MANUFACTURERS, \
    HCI_Cmd_LE_Read_Supported_States, \
    HCI_Cmd_Complete_LE_Read_Supported_States, HCI_Cmd_CSR_Write_BD_Address, HCI_Cmd_CSR_Reset, \
    HCI_Cmd_TI_Write_BD_Address, HCI_Cmd_BCM_Write_BD_Address, HCI_Cmd_Zeevo_Write_BD_Address, \
    HCI_Cmd_Ericsson_Write_BD_Address, HCI_Cmd_ST_Write_BD_Address, \
    HCI_Cmd_LE_Set_Host_Channel_Classification

from whad.device.virtual.hci.converter import HCIConverter
from whad.device.virtual.hci.hciconfig import HCIConfig
from whad.device.virtual.hci.constants import LE_STATES, ADDRESS_MODIFICATION_VENDORS, \
    HCIInternalState

logger = logging.getLogger(__name__)

def get_hci(index):
    '''
    Returns an HCI socket based on adapter index.
    '''
    try:
        logger.debug("Creating bluetooth socket ...")
        socket = BluetoothUserSocket(index)
        logger.debug("Bluetooth socket successfully created.")
        return socket
    except BluetoothSocketError:
        logger.debug("An error occured while creating bluetooth socket")
        try:
            logger.debug("Shutting down HCI interface #%d", index)
            HCIConfig.down(index)
            logger.debug("HCI interface %d shut down, creating Bluetooth socket ...", index)
            socket = BluetoothUserSocket(index)
            logger.debug("Bluetooth socket successfully created.")
            return socket
        except BluetoothSocketError as err:
            logger.debug(err)
            logger.debug("Cannot create Bluetooth socket !")
            return None
        except PermissionError as perm_err:
            logger.debug("WHAD device hci%d cannot be accessed.", index)
            raise WhadDeviceAccessDenied(f"hci{index}") from perm_err
    except PermissionError as perm_err:
        logger.debug("WHAD device hci%d cannot be accessed.", index)
        raise WhadDeviceAccessDenied(f"hci{index}") from perm_err

def compute_max_time(length: int, datarate: int) -> int:
    """Compute the maximum transmission time for a given PDU length and
    datarate.

    Prefix is 80 bits (header + CRC), suffix is some kind of security margin.
    """
    return int(((80 + length*8 + 32)/datarate)*1000000.0)

class HCIUnsupportedCommand(Exception):
    """Raised when an HCI command requirement is not met by hardware.
    """
    def __init__(self, command):
        super().__init__()
        self.command = command

    def __repr__(self):
        return f"HCIUnsupportedCommand(cmd='{self.command}')"

class HCIUnsupportedFeature(Exception):
    """Raised when an HCI feature requirement is not met by hardware.
    """
    def __init__(self, feature):
        super().__init__()
        self.__feature = feature

    def __repr__(self):
        return f"HCIUnsupportedFeature(feature='{self.__feature}')"

class HCIUnsupportedLEFeature(Exception):
    """Raised when an HCI LE feature requirement is not met by hardware.
    """
    def __init__(self, feature):
        super().__init__()
        self.__feature = feature

    def __repr__(self):
        return f"HCIUnsupportedLEFeature(feature='{self.__feature}')"

class req_cmd:
    """HCI Decorator to handle command requirements.

    Normally, we query an HCI interface to retrieve the list of its supported
    commands, following the recommended initialization procedure
    (Vol6, part D, section 1).

    We need to check that all the required commands are supported by the target
    hardware before starting a specific procedure, and this decorator provides
    a way to declare one or more required commands for a decorated method of
    HCIDevice, and blocks its execution if at least one of them is not provided
    by the target hardware.
    """

    def __init__(self, *args):
        """Save any string argument as a required HCI command.
        """
        self.__requires = []
        for arg in args:
            if isinstance(arg, str):
                self.__requires.append(arg)

    def __call__(self, method):
        """Called to decorate the actual method.
        """
        requirements = self.__requires
        def _wrap(self, *args, **kwargs):
            # check our requirements are met
            for command in requirements:
                if not self.is_cmd_supported(command):
                    raise HCIUnsupportedCommand(command)

            # If all requirements are met, forward
            return method(self, *args, **kwargs)
        return _wrap

class req_feature:
    """HCI decorator to handle command feature requirement.
    """
    def __init__(self, *args):
        self.__requires = []
        for arg in args:
            if isinstance(arg, str):
                self.__requires.append(arg)
    
    def __call__(self, method):
        """Called to decorate the actual method.
        """
        requirements = self.__requires
        def _wrap(self, *args, **kwargs):
            # check our requirements are met
            for feature in requirements:
                if not self.is_feature_supported(feature):
                    raise HCIUnsupportedFeature(feature)

            # If all requirements are met, forward
            return method(self, *args, **kwargs)
        return _wrap   

class le_only(req_feature):
    """Requires a LE-enabled controller
    """
    def __init__(self, *args):
        super().__init__("le_supported_controller")
        self.__requires = []
        for arg in args:
            if isinstance(arg, str):
                self.__requires.append(arg)

    def __call__(self, method):
        requirements = self.__requires
        def _wrap(self, *args, **kwargs):
            # check our requirements are met
            for feature in requirements:
                if not self.is_le_feature_supported(feature):
                    raise HCIUnsupportedLEFeature(feature)

            # If all requirements are met, forward
            return method(self, *args, **kwargs)
        
        # Wrap with LE-enabled controller check (tested first)
        return super().__init__(_wrap)

class HCIDevice(VirtualDevice):
    """Host/controller interface virtual device implementation.
    """

    INTERFACE_NAME = "hci"

    PHY_1M = 1000000
    PHY_2M = 2000000

    @classmethod
    def list(cls):
        '''
        Returns a list of available HCI devices.
        '''
        available_devices = {}
        devices_ids = HCIConfig.list()
        for device_id in devices_ids:
            available_devices[device_id] = HCIDevice(index=device_id)

        return available_devices

    def __init__(self, index):
        super().__init__(index=index)
        self.__converter = HCIConverter(self)
        self.__index = index
        self.__socket = None
        self.__internal_state = HCIInternalState.NONE
        self.__opened = False
        self.__hci_responses = Queue()
        self._dev_capabilities = None
        self._local_name = None
        self._advertising = False
        self._bd_address = None
        self._bd_address_type = AddressType.RANDOM
        self._fw_version = None
        self._fw_url = None
        self._fw_author = None
        self._dev_id = None
        self._manufacturer = None
        self._cached_scan_data = None
        self._cached_scan_response_data = None
        self.__timeout = 1.0
        self._connected = False
        self.__closing = False
        self.__local_supp_cmds = None

        # Data PDU Length management
        self.__datarate = HCIDevice.PHY_1M
        self.__conn_max_tx_octets = 27
        self.__conn_max_tx_time = 0x148
        self.__conn_max_tx_time_uncoded = 328
        self.__conn_max_tx_time_coded = 2704
        self.__conn_max_rx_octets = 27
        self.__conn_max_rx_time = 0x148
        self.__supported_max_tx_octets = 27
        self.__supported_max_tx_time = 0x148
        self.__supported_max_rx_octets = 27
        self.__supported_max_rx_time = 0x148
        self._active_handles = []

        # Classic Features
        self.__features = None

        # LE Features
        self.__le_features = None

        # LE Filter Accept
        self.__fa_size = 0
        self.__fa_entries = []

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
            # Open a Bluetooth user socket
            self.__socket = get_hci(self.__index)
            if self.__socket is None:
                # An error occured, raising error
                logger.error("Whad device is not ready.")
                raise WhadDeviceNotReady()

            # Flush HCI interface
            logger.debug("[%s] Flushing HCI interface ...", self.interface)
            self.__socket.flush()

            # Mark as opened
            self.__opened = True

            # Ask parent class to run a background I/O thread
            super().open()

            # Initialize this HCI interface
            if not self._initialize():
                raise WhadDeviceNotReady()

    def close(self):
        """
        Close current device.
        """
        # Avoid recursion that may occur due to super().close()
        if self.__closing:
            return

        # Marking device as in closing process
        self.__closing = True

        # Disconnect if necessary
        for handle in self._active_handles:
            self._disconnect(handle)
        # Ask parent class to stop I/O thread
        logger.debug("Stopping background IO threads ...")
        super().close()

        # Close underlying device.
        if self.__socket is not None:
            logger.debug("Closing Bluetooth socket ...")
            self.__socket.close()
            del self.__socket
            self.__socket = None
        self.__opened = False

        # Closing process done.
        self.__closing = False


    def write(self, data):
        """
        Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes data: Data to write
        :return: number of bytes written to the device
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
            if self.__socket is not None and self.__socket.readable(0.1):
                event = self.__socket.recv()
                if event.type == 0x4 and event.code in (0xe, 0xf, 0x13):
                    self.__hci_responses.put(event)
                else:
                    messages = self.__converter.process_event(event)
                    if messages is not None:
                        for message in messages:
                            self._send_whad_message(message)

                    # Wrong ! HCI interface is still back to advertising once a
                    # connection closed.
                    #
                    # If the connection is stopped and peripheral mode is started,
                    # automatically re-enable advertising based on cached data
                    if HCI_Event_Disconnection_Complete in event:
                        logger.debug("[hci] Disconnection complete")
                    if HCI_Event_Disconnection_Complete in event and \
                            self.__internal_state == HCIInternalState.PERIPHERAL:

                        # If advertising was not enabled, skip
                        if not self._advertising:
                            return

                        if not self._read_advertising_physical_channel_tx_power():
                            logger.error("[%s] Cannot read advertising physical channel Tx power", self.interface)

                        # if data are cached, configure them
                        if self._cached_scan_data is not None:
                            # We can't wait for response because we are in the
                            # reception loop context
                            success = self._set_advertising_data(self._cached_scan_data,
                                                                 wait_response=True)

                            # Raise an error if we cannot set the advertising data.
                            if not success:
                                logger.error("[hci] cannot set advertising data!")
                                raise WhadDeviceNotReady()

                        if self._cached_scan_response_data is not None:
                            success = self._set_scan_response_data(
                                self._cached_scan_response_data, wait_response=True
                            )

                            # Raise an error if we cannot set the scan response data.
                            if not success:
                                logger.error("[hci] cannot set scan response data!")
                                raise WhadDeviceNotReady()

                        # We need to artificially disable advertising indicator
                        # to prevent cached operation
                        self._advertising = False
                        self._set_advertising_mode(True, wait_response=True)


        except (BrokenPipeError, OSError) as err:
            print(err)
            logger.error("Error, waiting...")
            sleep(1)

    def _wait_response(self, timeout=None):
        response = None
        try:
            response = self.__hci_responses.get(block=True, timeout=timeout)
        except Empty:
            logger.debug("[hci] device did not respond")
        return response

    def _write_packet(self, packet):
        """
        Writes an HCI packet.
        """
        logger.debug("[hci] sending packet ...")
        self.__socket.send(packet)

        # Wait for response
        logger.debug("[hci] waiting for response (timeout: %s)...", self.__timeout)
        response = self._wait_response(timeout=self.__timeout)
        if response is None:
            logger.debug("[hci][%s] timeout reached when sending packet", self.interface)
            return False

        logger.debug("[hci] response code: 0x%04x", response.code)
        while response.code != 0x13:
            logger.debug("[hci] waiting for response ...")
            response = self._wait_response(timeout=self.__timeout)
            if response is None:
                logger.debug("[hci][%s] wait_response returned None !", self.interface)
                return False
            logger.debug("[hci] response code: 0x%04x", response.code)
        return response.num_handles == 1 and response.num_completed_packets_list[0] == 1

    def _write_command(self, command, wait_response=True):
        """
        Writes an HCI command and returns the response.
        """
        hci_command = HCI_Hdr()/HCI_Command_Hdr()/command
        logger.debug("[%s][write_command] Sending HCI command to user socket ...", self.interface)
        self.__socket.send(hci_command)
        logger.debug("[%s][write_command] Command sent.", self.interface)
        #if wait_response:
        if 1:
            logger.debug("[%s][write_command] Waiting for response ...", self.interface)
            response = self._wait_response()
            while response.opcode != hci_command[HCI_Command_Hdr].opcode:
                logger.debug("[%s][write_command] Received response with opcode %d", self.interface, response.opcode)
                response = self._wait_response()
            logger.debug("[%s][write_command] Response received.", self.interface)
            
            if response is not None:
                logger.debug("[%s] HCI write command returned status %d",
                            self.interface, response.status)
        else:
            logger.debug("[%s] HCI write command returned (non-blocking)", self.interface)
            response = None
        
        return response

    def reset(self):
        """
        self._bd_address = self._read_bd_address()
        self._local_name = self._read_local_name()
        """
        self._initialize()
        self._read_local_name()
        self._fw_version, self._manufacturer = self._read_local_version_information()
        self._fw_author = self._manufacturer
        self._dev_id = self._generate_dev_id()
        self._fw_url = b"<unknown>"
        self._dev_capabilities = self._get_capabilities()

    def _generate_dev_id(self):
        devid = (self._bd_address.value + self._local_name)[:16]
        if len(devid) < 16:
            devid += b"\x00" * (16 - len(devid))
        return devid

    def _get_capabilities(self):
        supported_states = self._read_le_supported_states()

        capabilities = 0
        supported_commands = []
        for state in supported_states:
            _, cap, commands = state
            capabilities = capabilities | cap
            supported_commands += commands

        supported_commands += [Commands.SetBdAddress]

        supported_commands = list(set(supported_commands))
        capabilities = {
            Domain.BtLE : (
                                capabilities | Capability.NoRawData,
                                supported_commands
            )
        }
        return capabilities

    def is_cmd_supported(self, cmd: str) -> bool:
        """Determine if a specific LE command is supported by the HCI interface.

        :param cmd: Command to test
        :type cmd: str
        :return: True if command is supported, False otherwise
        :rtype: bool
        """
        if cmd in self.__local_supp_cmds.supported_commands.names:
            return getattr(self.__local_supp_cmds.supported_commands, cmd)
        return False

    def is_feature_supported(self, feature: str) -> bool:
        """Determine if a specific feature is supported by the HCI interface.

        :param feature: Feature to test
        :type feature: str
        :return: True if feature is supported, False otherwise
        :rtype: bool
        """
        if feature in self.__features.lmp_features.names:
            return getattr(self.__features.lmp_features, feature)
        return False
    
    def is_le_feature_supported(self, feature: str) -> bool:
        """Determine if a specific feature is supported by the HCI interface.

        :param feature: Feature to test
        :type feature: str
        :return: True if feature is supported, False otherwise
        :rtype: bool
        """
        if feature in self.__le_features.le_features.names:
            return getattr(self.__le_features.le_features, feature)
        return False

    def _reset(self):
        """
        Reset HCI device.
        """
        logger.debug("[%s] Resetting interface ...", self.interface)
        response = self._write_command(HCI_Cmd_Reset())
        return response is not None and response.status == 0x0

    @req_cmd("read_buffer_size")
    def _read_buffer_size(self):
        """Read HCI device default buffer size and update max ACL length.
        """
        logger.debug("[%s] Reading HCI ACL buffer size ...", self.interface)
        response = self._write_command(HCI_Cmd_Read_Buffer_Size())

        if response is not None and response.status == 0x0:
            if HCI_Cmd_Complete_Read_Buffer_Size in response:
                if response.acl_pkt_len > 0:
                    # Update HCI MTU
                    logger.debug("[%s] ACL buffer length: %d", self.interface, response.acl_pkt_len)
                    self.__conn_max_tx_octets = response.acl_pkt_len
                    return True

        logger.debug("[%s] Failed reading ACL buffer size !", self.interface)
        return False

    @req_cmd("le_read_buffer_size_v1")
    def _le_read_buffer_size(self):
        """Read HCI device LE buffer size and update max ACL length.
        """
        logger.debug("[%s] Reading HCI LE ACL buffer size v1 ...", self.interface)
        response = self._write_command(HCI_Cmd_LE_Read_Buffer_Size_V1())
        if response is not None and response.status == 0x0:
            if HCI_Cmd_LE_Complete_Read_Buffer_Size in response:
                if response.acl_pkt_len > 0:
                    # Update HCI MTU
                    logger.debug("[%s] LE ACL buffer length: %d", self.interface,
                                 response.acl_pkt_len)
                    self.__conn_max_tx_octets = response.acl_pkt_len
                    return True
                else:
                    logger.debug("[%s] LE ACL buffer is 0, fallback to default ACL buffer")
                    return self._read_buffer_size()
        
        logger.debug("[%s] Failed reading LE ACL buffer size v1 !", self.interface)
        return False
    
    def read_local_supported_commands(self):
        """Read local adapter supported commands.
        """
        logger.debug("[%s] Reading HCI local supported commands ...", self.interface)
        response = self._write_command(HCI_Cmd_Read_Local_Supported_Commands())
        if response is not None and response.status == 0x0:
            if HCI_Cmd_Complete_Supported_Commands in response:
                logger.debug("[%s] Local supported commands cached.", self.interface)
                self.__local_supp_cmds = response[HCI_Cmd_Complete_Supported_Commands]
                return True
            
        logger.debug("[%s] Failed reading supported commands !", self.interface)
        return False   

    @req_cmd("read_local_supported_features")
    def read_local_supported_features(self):
        """Query the HCI interface to retrieve its supported features.
        """
        logger.debug("[%s] Reading HCI local supported features ...", self.interface)
        response = self._write_command(HCI_Cmd_Read_Local_Supported_Features())
        if response is not None and HCI_Cmd_Complete_Supported_Features in response:
            logger.debug("[%s] Local supported features cached.", self.interface)
            self.__features = response[HCI_Cmd_Complete_Supported_Features]
            return True
        
        logger.debug("[%s] Failed reading supported features !", self.interface)
        return False

    @req_cmd("le_read_local_supported_features")
    def read_local_le_supported_features(self):
        """Read local LE supported features
        """
        logger.debug("[%s] Reading HCI LE local supported features ...", self.interface)
        response = self._write_command(HCI_Cmd_LE_Read_Local_Supported_Features())
        if response is not None and HCI_Cmd_LE_Complete_Supported_Features in response:
            logger.debug("[%s] Local LE supported features cached.", self.interface)
            self.__le_features = response[HCI_Cmd_LE_Complete_Supported_Features]
            return True
        
        logger.debug("[%s] Failed reading LE supported features !", self.interface)
        return False

    @req_cmd("set_event_filter")
    def _set_event_filter(self, filter_type=0):
        """
        Configure HCI device event filter.
        """
        logger.debug("[%s] Setting HCI Event Filter to type %d", self.interface, filter_type)
        response = self._write_command(HCI_Cmd_Set_Event_Filter(type=filter_type))
        return response is not None and response.status == 0x00

    @req_cmd("set_event_mask")
    def _set_event_mask(self, mask=b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d"):
        """
        Configure HCI device event mask.
        """
        logger.debug("[%s] Setting HCI Event Mask to %s", self.interface, mask.hex())
        response = self._write_command(HCI_Cmd_Set_Event_Mask(mask=mask))
        return response is not None and response.status == 0x00

    @req_cmd("le_set_event_mask")
    def _le_set_event_mask(self, mask=b"\x1f\x00\x00\x00\x00\x00\x00\x00"):
        """Configure HCI LE event mask.
        """
        logger.debug("[%s] Setting HCI LE Event Mask to %s", self.interface, mask.hex())
        response = self._write_command(HCI_Cmd_LE_Set_Event_Mask())
        return response is not None and response.status == 0x00

    @req_cmd("write_connection_accept_timeout")
    def _set_connection_accept_timeout(self, timeout=32000):
        """
        Configure HCI device connection accept timeout.
        """
        logger.debug("[%s] Setting connection timeout to %d", self.interface, timeout)
        response = self._write_command(HCI_Cmd_Write_Connect_Accept_Timeout(timeout=timeout))
        return response is not None and response.status == 0x00

    @req_cmd("write_le_host_support")
    def indicates_le_support(self):
        """
        Indicates to HCI Device that the Host supports Low Energy mode.
        """
        logger.debug("[%s] Write LE Host support (simulatenous mode not supported)", self.interface)
        response = self._write_command(HCI_Cmd_Write_LE_Host_Support(supported=1, unused=0))
        return response is not None and response.status == 0x00

    @req_cmd("le_write_suggested_default_data_length",
             "le_read_suggested_default_data_length")
    def configure_data_length(self):
        """Negociate ACL data length.
        """
        # If our controller supports LE Data Length Update, suggest an intermediate
        # size and compute time
        if self.is_le_feature_supported("data_packet_length_extension"):
            suggested_max_tx_octets = 64
            suggested_max_tx_time = compute_max_time(suggested_max_tx_octets, self.__datarate)
        else:
            suggested_max_tx_octets = 27
            suggested_max_tx_time = 0x148

        # Send suggested default data length first
        logger.debug("[%s] HCI Write Suggested Default Data Length (max TX octets:%d, max Tx time: %d)",
                     self.interface, self.__conn_max_tx_octets, self.__conn_max_tx_time)
        response = self._write_command(HCI_Cmd_LE_Write_Suggested_Default_Data_Length(
            max_tx_octets=suggested_max_tx_octets,
            max_tx_time=suggested_max_tx_time
        ))
        if response is not None and response.status == 0x00:
            logger.debug("[%s] Suggested Default Data Length successfully sent.", self.interface)
        else:
            logger.debug("[%s] Failed sending Suggested Default Data Length !", self.interface)

        # Read suggested default data length from controller
        logger.debug("[%s] Reading local Suggested Default Data Length ...", self.interface)
        response = self._write_command(HCI_Cmd_LE_Read_Suggested_Default_Data_Length())
        if response is not None and HCI_Cmd_LE_Complete_Suggested_Default_Data_Length in response:
            # Check if reported data length is greater than 27, if so we need to
            # ensure the controller supports the Data Length Extension and follow
            # this procedure.
            answer = response[HCI_Cmd_LE_Complete_Suggested_Default_Data_Length]
            logger.debug(
                "[%s] Suggested Default Data Length read (max_tx_octets:%d, max_tx_time: %d)",
                self.interface, answer.max_tx_octets, answer.max_tx_time
            )
            return True

        logger.debug("[%s] Failed reading Suggested Default Data Length !", self.interface)
        return False

    def write_simple_pairing_mode(self, enable: bool = True) -> bool:
        """Configure HCI interface to support Simple Pairing mode (or not)"""
        response = self._write_command(HCI_Cmd_Write_Simple_Pairing_Mode(enable=enable))
        return response is not None and response.status == 0x00

    def write_connect_accept_timeout(self, timeout: int = 32000) -> bool:
        """Configure the HCI interface connection timeout for LE and BR/EDR controller"""
        response = self._write_command(HCI_Cmd_Write_Connect_Accept_Timeout(timeout=timeout))
        return response is not None and response.status == 0x00

    def write_default_link_policy_settings(self, policy: int = 0x0f) -> bool:
        """Configure the HCI interface default link policy settings for LE and BR/EDR controller"""
        response = self._write_command(HCI_Cmd_Write_Default_Link_Policy_Settings(policy=policy))
        return response is not None and response.status == 0x00


    def _initialize(self):
        """
        Initialize HCI Device and returns boolean indicating if it can be used by WHAD.
        """
        logger.debug("[%s] Starting initialization process ...", self.interface)
        success = (
                self._reset() and
                self.read_local_supported_commands() and 
                self.read_local_le_supported_features() and 
                self.write_simple_pairing_mode() and
                self.write_connect_accept_timeout() and
                self._set_event_mask(b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d") and
                self.write_default_link_policy_settings() and
                self._le_set_event_mask(mask=b'\xff\xff\xff\xff\x03') and
                self._le_read_buffer_size() and
                self.read_local_le_supported_features() and 
                self._read_bd_address() and 
                self.indicates_le_support() and
                self.__read_filter_accept_list_size() and
                self.clear_filter_list() and
                self._set_bd_address()
        )
        try:
            success = success and self.configure_data_length()
        except HCIUnsupportedCommand as cmderr:
            logger.debug("[%s] Configuring data length cannot be done, command %s is not supported.",
                         self.interface, cmderr.command)
        logger.debug("[%s] Initialization process result: %s", self.interface,
                     "Success" if success else "Failed")
        return success

    @req_cmd("le_clear_filter_accept_list")
    def clear_filter_list(self):
        """Clear LE filter list.
        """
        logger.debug("[%s] Clearing LE filter accept list ...", self.interface)
        response = self._write_command(HCI_Cmd_LE_Clear_Filter_Accept_List())
        return response is not None and response.status == 0x00

    @req_cmd("le_read_filter_accept_list_size")
    def __read_filter_accept_list_size(self) -> bool:
        """Retrieve LE Filter accept list size from local adapter.
        """
        logger.debug("[%s] Reading LE filter accept list size ...", self.interface)
        response = self._write_command(HCI_Cmd_LE_Read_Filter_Accept_List_Size())
        if response is not None and response.status == 0x00:
            r = response[HCI_Cmd_LE_Complete_Read_Filter_Accept_List_Size]
            self.__fa_size = r.list_size
            logger.debug("[%s] LE filter accept list size: %d slots", self.interface,
                         self.__fa_size)
            return True
        return False
    
    def get_whitelist_size(self) -> int:
        """Retrieve the LE Device Whitelist size for the current HCI
        interface.

        :return: Number of slots in current LE Whitelist (Filter Accept List)
        :rtype: int
        """
        # Read Filter Accept List size
        self.__read_filter_accept_list_size()
        return self.__fa_size

    @req_cmd("read_bd_addr")
    def _read_bd_address(self):
        """
        Read BD Address used by the HCI device.
        """
        logger.debug("[%s] Reading HCI interface BD address ...", self.interface)
        response = self._write_command(HCI_Cmd_Read_BD_Addr())
        if response.status == 0x00 and HCI_Cmd_Complete_Read_BD_Addr in response:
            self._bd_address = BDAddress(response.addr, random=False)
            logger.debug("[%s] BD address: %s", self.interface, self._bd_address)
            return True

        # Cannot read BD address, device is non-responsive.
        # logger.error("[%s] cannot read BD address", self.interface)
        logger.debug("cannot read BD address of interface %s", self.interface)
        logger.debug("raising WhadDeviceNotReady exception")
        raise WhadDeviceNotReady(f"cannot read BD address of interface {self.interface}")

    @req_cmd("read_local_name")
    def _read_local_name(self):
        """
        Read local name used by the HCI device.
        """
        logger.debug("[%s] Reading local name ...", self.interface)
        response = self._write_command(HCI_Cmd_Read_Local_Name())
        if response.status == 0x00 and HCI_Cmd_Complete_Read_Local_Name in response:
            self._local_name = response.local_name
            return True
        
        # Cannot read local name.
        logger.debug("[%s] Failed reading local name !", self.interface)
        logger.debug("[%s] Device not supported.")
        raise WhadDeviceNotReady()

    @req_cmd("read_local_version_information")
    def _read_local_version_information(self):
        """
        Read local version information used by the HCI device.
        """
        logger.debug("[%s] Reading local version info ...", self.interface)
        response = self._write_command(HCI_Cmd_Read_Local_Version_Information())
        if response.status == 0x00 and HCI_Cmd_Complete_Read_Local_Version_Information in response:
            version = [int(v) for v in HCI_VERSIONS[response.hci_version].split(".")]
            version += [response.hci_subversion]
            try:
                manufacturer = BT_MANUFACTURERS[response.company_identifier].encode("utf-8")
            except IndexError:
                logger.debug("[%s] Unsupported manufacturer ID 0x%04x", self.interface,
                             response.company_identifier)
                manufacturer = f"unknown<0x{response.company_identifier:04x}>".encode("utf-8")
            logger.debug("[%s] Version: %s", self.interface, version)
            logger.debug("[%s] Manufacturer: %s", self.interface, manufacturer)
            return version, manufacturer
        
        # Cannot read local version information.
        logger.debug("[%s] Failed reading local version info !", self.interface)
        logger.debug("[%s] Unsupported HCI interface.")
        raise WhadDeviceNotReady()

    @req_cmd("le_read_supported_states")
    def _read_le_supported_states(self):
        """
        Returns the list of Bluetooth Low Energy states supported by the HCI device.
        """
        logger.debug("[%s] Reading LE supported states ...", self.interface)
        response = self._write_command(HCI_Cmd_LE_Read_Supported_States())
        if response.status == 0x00 and HCI_Cmd_Complete_LE_Read_Supported_States in response:
            states = []
            for bit_position, state in LE_STATES.items():
                if response.supported_states & (1 << bit_position) != 0:
                    states.append(state)
            return states

        # Cannot read supported LE states.
        logger.debug("[%s] Failed reading LE supported states !", self.interface)
        logger.debug("[%s] Unsupported HCI interface.")
        raise WhadDeviceNotReady()

    @req_cmd("le_set_random_address")
    def _set_bd_address(self, bd_address: bytes = b"\x00\x11\x22\x33\x44\x55",
                        bd_address_type: int = AddressType.RANDOM) -> bool:
        """
        Modify the BD address (if supported by the HCI device).
        """
        logger.debug("[%s] Setting HCI adapter random address to %s ...", self.interface, 
                     BDAddress(bd_address))
        
        # Disabled for now
        if False and bd_address_type == AddressType.PUBLIC:
            _, self._manufacturer = self._read_local_version_information()
            if self._manufacturer in ADDRESS_MODIFICATION_VENDORS:
                logger.info("[i] Address modification supported !")
                if self._manufacturer == b'Qualcomm Technologies International, Ltd. (QTIL)':
                    # Keep in cache existing devices
                    existing_devices = devices = HCIConfig.list()

                    # Write BD address and reset with vendor specific commands
                    self._write_command(HCI_Cmd_CSR_Write_BD_Address(addr=bd_address),
                                        wait_response=False)
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
                    # For the other manufacturers, we only need to pick the
                    # right command and perform a reset
                    bd_address_mod_map = {
                        b'Texas Instruments Inc.' : HCI_Cmd_TI_Write_BD_Address,
                        b'Broadcom Corporation' : HCI_Cmd_BCM_Write_BD_Address,
                        b'Zeevo, Inc.' : HCI_Cmd_Zeevo_Write_BD_Address,
                        b'Ericsson Technology Licensing' : HCI_Cmd_Ericsson_Write_BD_Address,
                        b'Integrated System Solution Corp.' : HCI_Cmd_Ericsson_Write_BD_Address,
                        b'ST Microelectronics' : HCI_Cmd_ST_Write_BD_Address
                    }
                    command = bd_address_mod_map[self._manufacturer](addr=bd_address)
                    self._write_command(command, wait_response=False)
                    self._reset()

                # Check the modification success and re-generate device ID
                self._bd_address = self._read_bd_address()
                self._dev_id = self._generate_dev_id()
                self._bd_address_type = AddressType.PUBLIC
                return self._bd_address == bd_address

            # Not supported !
            logger.debug("Address modification not supported.")

            # But at least we keep our address type
            self._bd_address_type = bd_address_type
            return False

        response = self._write_command(HCI_Cmd_LE_Set_Random_Address(address=bd_address))
        if response is not None and response.status == 0x00:
            logger.debug("[%s] Random address successfully set to %s", self.interface, 
                     BDAddress(bd_address))
            # Read BD address
            self._read_bd_address()
            self._bd_address_type = AddressType.RANDOM
        else:
            logger.debug("[%s] Failed setting random address, continue anyway", self.interface)
        
        # Success
        return True

    @req_cmd("le_set_scan_parameters")
    def _set_scan_parameters(self, active=True):
        """
        Configure Scan parameters for HCI device.
        """
        logger.debug("[%s] Setting LE Scan Parameters (active:%s) ...", self.interface, 
                     active)
        response = self._write_command(HCI_Cmd_LE_Set_Scan_Parameters(type=int(active)))
        return response is not None and response.status == 0x00

    @req_cmd("le_set_scan_enable")
    def _set_scan_mode(self, enable=True):
        """
        Enable or disable scan mode for HCI device.
        """
        logger.debug("[%s] Enabling LE Scan Mode (enable:%s, no duplicates) ...",
                     self.interface, enable)
        response = self._write_command(HCI_Cmd_LE_Set_Scan_Enable(
            enable=int(enable),filter_dups=False
        ))
        return response is not None and response.status == 0x00

    @req_cmd("le_set_host_channel_classification", "le_create_connection")
    def _connect(self, bd_address, bd_address_type=AddressType.PUBLIC, hop_interval=96,
                 channel_map=None):
        """
        Establish a connection using HCI device.
        """
        logger.debug("bd_address: %s (%d)", bd_address, bd_address_type)
        logger.debug("[hci] _connect() called")
        patype = 0 if bd_address_type == AddressType.PUBLIC else 1
        if channel_map is not None:
            formatted_channel_map = unpack("<Q",channel_map+ b"\x00\x00\x00")[0]
            logger.debug("[%s] Setting Channel Map to  0x%x...",
                self.interface, formatted_channel_map)
            response = self._write_command(HCI_Cmd_LE_Set_Host_Channel_Classification(
                chM=formatted_channel_map
            ))
            if response.status != 0x00:
                logger.debug("[%s] Failed setting Channel Map !", self.interface)
                logger.debug("[%s] Connection aborted.", self.interface)
                return False

        # Connect
        logger.debug("[%s] Creating LE connection to %s ...", self.interface,
                     BDAddress(bd_address, random=bd_address_type==BDAddress.RANDOM))
        response = self._write_command(
            HCI_Cmd_LE_Create_Connection(
                paddr=bd_address,
                patype=patype,
                min_interval=hop_interval,
                max_interval=hop_interval
            )
        )
        if response.status != 0x00:
            logger.debug("[%s] HCI_LE_Create_Connection command failed with response %d", self.interface,
                         response.status)
        return response is not None and response.status == 0x00

    @req_cmd("disconnect")
    def _disconnect(self, handle):
        """
        Establish a disconnection using HCI device.
        """
        logger.debug("[%s] sending HCI disconnect command ...")
        response = self._write_command(HCI_Cmd_Disconnect(handle=handle))
        return response is not None and response.status == 0x00

    @req_cmd("le_set_advertising_data")
    def _set_advertising_data(self, data, wait_response: bool = True) -> bool:
        """
        Configure advertising data to use by HCI device.
        """
        # pad data if less than 31 bytes
        #if len(data) < 31:
        #    data += b'\x00'*(31 - len(data))

        # Send command and wait for response if required.
        result = True
        if wait_response:
            # Wait for response.
            logger.debug("[%s] Setting HCI LE advertising data ...", self.interface)
            response = self._write_command(HCI_Cmd_LE_Set_Advertising_Data(data=EIR_Hdr(data)))

            # Check response and update result.
            result = response is not None and response.status == 0x0
        else:
            # Otherwise send command without waiting a response.
            logger.debug("[%s] Setting HCI LE advertising data (non-blocking) ...", self.interface)
            self._write_command(HCI_Cmd_LE_Set_Advertising_Data(data=EIR_Hdr(data)), wait_response=False)

        # Return result
        return result
    
    @req_cmd("le_read_advertising_physical_channel_tx_power")
    def _read_advertising_physical_channel_tx_power(self) -> bool:
        """Read Advertising Physical Channel Tx Power level
        """
        logger.debug("Read Advertising Physical Channel Tx Power ...")
        response = self._write_command(HCI_Cmd_LE_Read_Advertising_Physical_Channel_Tx_Power())
        response.show()
        if response is not None and response.status == 0x00:
            power_level = response[HCI_Cmd_Complete_LE_Advertising_Tx_Power_Level].tx_power_level
            logger.debug("[%s] Advertising Tx Power level: %d", self.interface, power_level)
            return True
        return False

    @req_cmd("le_set_scan_response_data")
    def _set_scan_response_data(self, data, wait_response=True) -> bool:
        """
        Configure scan response data to use by HCI device.
        """
        result = True
        if wait_response:
            # Wait response and update result accordingly.
            logger.debug("[%s] Setting HCI LE Scan Response Data to %s ...", self.interface,
                         data.hex())
            response = self._write_command(HCI_Cmd_LE_Set_Scan_Response_Data(
                    data=data + (31 - len(data)) * b"\x00", len=len(data)
                )
            )
            result = response is not None and response.status == 0x0
        else:
            # Don't wait for a response.
            logger.debug("[%s] Setting HCI LE Scan Response Data to %s (non-blocking) ...", self.interface,
                         data.hex())
            self._write_command(HCI_Cmd_LE_Set_Scan_Response_Data(
                    data=data + (31 - len(data)) * b"\x00", len=len(data)
                ),
                wait_response=False
            )

        # Return result
        return result

    @req_cmd("le_set_advertising_parameters")
    def set_advertising_parameters(self, interval_min: int = 0x0020, interval_max: int = 0x0020,
                                   adv_type="ADV_IND", oatype: int = 0, datype: int = 0,
                                   daddr:str = "00:00:00:00:00:00", channel_map: int = 0x7,
                                   filter_policy: str = "all:all", wait_response: bool = True) -> bool:
        """Configure the HCI LE advertising parameters.
        """
        # Wait for a response and update result accordingly.
        logger.debug("[%s] Setting HCI LE Advertising Parameters (blocking:%s) ...",
                    self.interface, wait_response)
        response = self._write_command(HCI_Cmd_LE_Set_Advertising_Parameters(
            interval_min = 0x0020,
            interval_max = 0x0020,
            adv_type="ADV_IND",
            oatype=0 if self._bd_address_type == AddressType.PUBLIC else 1,
            datype=0,
            daddr="00:00:00:00:00:00",
            channel_map=0x7,
            filter_policy="all:all"
        ), wait_response=wait_response)

        # Process response if required
        if wait_response:
            return response.status == 0x00
        return True

    @req_cmd("le_set_advertising_enable")
    def _set_advertising_mode(self, enable=True, wait_response=True):
        """
        Enable or disable advertising mode for HCI device.
        """
        # Already enable, nothing to do
        if self._advertising and enable:
            logger.debug("[%s] Advertising is already enabled, nothing to do ...",
                    self.interface)
            return True

        # Not advertising and enabling, we need to configure our advertising
        # parameters.
        if not self._advertising and enable:
            result = self.set_advertising_parameters(
                    interval_min = 0x0020,
                    interval_max = 0x0020,
                    adv_type="ADV_IND",
                    oatype=0 if self._bd_address_type == AddressType.PUBLIC else 1,
                    datype=0,
                    daddr="00:00:00:00:00:00",
                    channel_map=0x7,
                    filter_policy="all:all",
                    wait_response=wait_response
                )

            if result:
                logger.debug("[%s] Sending HCI LE Set Advertise Enable (enable:%s, blocking:%s)",
                             self.interface, enable, wait_response)
                if wait_response:
                    # Wait for a response and update result accordingly.
                    response = self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(enable=int(enable)))
                    result = response.status == 0x00
                else:
                    # Don't wait, simply send command and consider it OK.
                    self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(
                        enable=int(enable)
                    ), wait_response=False)
                    result = True

            # On success, advertising has been enabled.
            self._advertising = result
        else:
            logger.debug("[%s] Sending HCI LE Set Advertise Enable (enable:0, blocking:%s)",
                            self.interface, wait_response)
            # Disabling advertising
            if wait_response:
                response = self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(enable=0))
                result = response.status == 0x00
                if result:
                    self._advertising = False
            else:
                response = self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(enable=0),
                                               wait_response=False)
                self._advertising = False
                result = True

        # Return result
        return result

    @req_cmd("le_long_term_key_request_reply", "le_enable_encryption")
    def _enable_encryption(self, enable=True, handle=None,  key=None, rand=None, ediv=None):
        if self.__converter.pending_key_request:
            logger.debug("[%s] Sending HCI LE Long Term Key request", self.interface)
            response = self._write_command(
                HCI_Cmd_LE_Long_Term_Key_Request_Reply(
                    handle=handle,
                    ltk=key[::-1]
                )
            )
            self.__converter.pending_key_request = False
        else:
            logger.debug("[%s] Sending HCI LE Enable Encryption", self.interface)
            response = self._write_command(
                HCI_Cmd_LE_Enable_Encryption(
                    handle=handle,
                    ltk=key[::-1],
                    rand=rand,
                    ediv=unpack("<H", ediv)[0]
                )
            )
        return response.status == 0x00

    def _update_max_acl_len(self, length: int):
        """Update device HCI MTU
        """
        self.__conn_max_tx_octets = length

    def get_max_acl_len(self) -> int:
        """Retrieve maximum ACL length

        :return: Current HCI maximum TX size
        :rtype: int
        """
        return self.__conn_max_tx_octets


    def _1le_encryption(self, message):
        success = self._enable_encryption(
            message.enabled,
            message.conn_handle,
            message.key,
            message.rand,
            message.ediv
        )
        if success:
            self._send_whad_command_result(CommandResult.SUCCESS)
            return
        self._send_whad_command_result(CommandResult.ERROR)


    def _on_whad_ble_periph_mode(self, message):
        logger.debug("whad ble periph mode message")
        if Commands.PeripheralMode in self._dev_capabilities[Domain.BtLE][1]:
            success = self._read_advertising_physical_channel_tx_power()
            if len(message.scan_data) > 0:
                success = success and self._set_advertising_data(message.scan_data)
                self._cached_scan_data = message.scan_data
            if len(message.scanrsp_data) > 0:
                success = success and self._set_scan_response_data(message.scanrsp_data)
                self._cached_scan_response_data = message.scanrsp_data
            success = success and self._set_advertising_mode(True)
            if success:
                self.__internal_state = HCIInternalState.PERIPHERAL
                self._send_whad_command_result(CommandResult.SUCCESS)
                return
        else:
            logger.debug("[%s] HCI interface does not allow peripheral mode.")
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_disconnect(self, message):
        success = self._disconnect(message.conn_handle)
        if success:
            self._send_whad_command_result(CommandResult.SUCCESS)
            return
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_connect(self, message):
        logger.debug("[hci] received WHAD connect message")
        if Commands.ConnectTo in self._dev_capabilities[Domain.BtLE][1]:
            bd_address = message.bd_address
            bd_address_type = message.addr_type
            channel_map = message.channel_map if message.channel_map is not None else None
            hop_interval = message.hop_interval if message.hop_interval is not None else 96
            if self._connect(bd_address, bd_address_type, hop_interval=hop_interval,
                             channel_map=channel_map):
                self._send_whad_command_result(CommandResult.SUCCESS)
                return
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_central_mode(self, message):
        if Commands.CentralMode in self._dev_capabilities[Domain.BtLE][1]:
            self.__internal_state = HCIInternalState.CENTRAL
            self._send_whad_command_result(CommandResult.SUCCESS)
            return
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_scan_mode(self, message):
        if Commands.ScanMode in self._dev_capabilities[Domain.BtLE][1]:
            active_scan = message.active
            if self._set_scan_parameters(active_scan):
                self.__internal_state = HCIInternalState.SCANNING
                self._send_whad_command_result(CommandResult.SUCCESS)
                return
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_start(self, message):
        logger.info("whad internal state: %d", self.__internal_state)
        if self.__internal_state == HCIInternalState.SCANNING:
            self._set_scan_mode(True)
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif self.__internal_state == HCIInternalState.PERIPHERAL:
            if not self._advertising:
                if self._set_advertising_mode(True):
                    self._advertising = True
                    self._send_whad_command_result(CommandResult.SUCCESS)
                else:
                    self._send_whad_command_result(CommandResult.ERROR)
            else:
                self._send_whad_command_result(CommandResult.SUCCESS)

        elif self.__internal_state == HCIInternalState.CENTRAL:
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_stop(self, message):
        if self.__internal_state == HCIInternalState.SCANNING:
            self._set_scan_mode(False)
            self.__internal_state = HCIInternalState.NONE
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif self.__internal_state == HCIInternalState.CENTRAL:
            self.__internal_state = HCIInternalState.NONE
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif self.__internal_state == HCIInternalState.PERIPHERAL:
            # We are not advertising anymore
            self._set_advertising_mode(False)
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_send_pdu(self, message):
        logger.debug("[%s] Received WHAD BLE send_pdu message", self.interface)
        if ((self.__internal_state == HCIInternalState.CENTRAL and message.direction == BleDirection.MASTER_TO_SLAVE) or
           (self.__internal_state == HCIInternalState.PERIPHERAL and message.direction == BleDirection.SLAVE_TO_MASTER)):
            try:
                hci_packets = self.__converter.process_message(message)

                if hci_packets is not None:
                    logger.debug("[%s] sending HCI packets ...", self.interface)

                    self.__converter.lock()
                    success = True
                    for hci_packet in hci_packets:
                        success = success and self._write_packet(hci_packet)
                    self.__converter.unlock()
                    logger.debug("[%s] HCI packet sending result: %s", self.interface, success)
                    if success:
                        logger.debug("[%s] send_pdu command succeeded.", self.interface)
                        self._send_whad_command_result(CommandResult.SUCCESS)
                    else:
                        logger.debug("[%s] send_pdu command failed.", self.interface)
                        self._send_whad_command_result(CommandResult.ERROR)

                pending_messages = self.__converter.get_pending_messages()
                for pending_message in pending_messages:
                    self._send_whad_message(pending_message)

            except WhadDeviceUnsupportedOperation:
                logger.debug("Parameter error")
                self._send_whad_command_result(CommandResult.PARAMETER_ERROR)
        else:
            # Wrong state, cannot send PDU
            logger.debug("wrong state or packet direction.")
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_set_bd_addr(self, message):
        logger.debug("Received WHAD BLE set_bd_addr message")
        if self._set_bd_address(message.bd_address, message.addr_type):
            logger.debug("HCI adapter BD address set to %s", str(message.bd_address))
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            logger.debug("HCI adapter does not support BD address spoofing")
            self._send_whad_command_result(CommandResult.ERROR)
