"""
Host/controller interface adaptation layer.
"""
import logging
from time import sleep
from queue import Queue, Empty
from struct import unpack
from threading import Lock, Event
from typing import Optional

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
    EIR_Hdr, HCI_Cmd_LE_Create_Connection_Cancel, HCI_Event_Hdr, HCI_Event_Command_Complete

from whad.scapy.layers.bluetooth import HCI_Cmd_LE_Complete_Read_Buffer_Size, \
    HCI_Cmd_Read_Buffer_Size, HCI_Cmd_Complete_Read_Buffer_Size, HCI_Cmd_LE_Set_Event_Mask, \
    HCI_Cmd_Read_Local_Supported_Commands, HCI_Cmd_Complete_Supported_Commands, \
    HCI_Cmd_Read_Local_Supported_Features, HCI_Cmd_Complete_Supported_Features, \
    HCI_Cmd_LE_Complete_Read_Filter_Accept_List_Size, HCI_Cmd_LE_Complete_Supported_Features, \
    HCI_Cmd_LE_Write_Suggested_Default_Data_Length, HCI_Cmd_LE_Read_Suggested_Default_Data_Length, \
    HCI_Cmd_LE_Complete_Suggested_Default_Data_Length, HCI_Cmd_Write_Simple_Pairing_Mode, \
    HCI_Cmd_Write_Default_Link_Policy_Settings, HCI_Cmd_LE_Read_Advertising_Physical_Channel_Tx_Power, \
    HCI_Cmd_Complete_LE_Advertising_Tx_Power_Level, HCI_Cmd_Write_Class_Of_Device

# Whad custom layers
from whad.scapy.layers.hci import HCI_VERSIONS, BT_MANUFACTURERS, \
    HCI_Cmd_LE_Read_Supported_States, \
    HCI_Cmd_Complete_LE_Read_Supported_States, HCI_Cmd_CSR_Write_BD_Address, HCI_Cmd_CSR_Reset, \
    HCI_Cmd_TI_Write_BD_Address, HCI_Cmd_BCM_Write_BD_Address, HCI_Cmd_Zeevo_Write_BD_Address, \
    HCI_Cmd_Ericsson_Write_BD_Address, HCI_Cmd_ST_Write_BD_Address, \
    HCI_Cmd_LE_Set_Host_Channel_Classification

# Whad
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied, \
    WhadDeviceUnsupportedOperation, WhadDeviceError

# Whad hub
from whad.hub.discovery import Domain
from whad.hub.generic.cmdresult import CommandResult
from whad.hub.discovery import Capability
from whad.hub.ble import Direction as BleDirection, Commands, AddressType, BDAddress

from ..device import VirtualDevice
from .converter import HCIConverter
from .hciconfig import HCIConfig
from .constants import LE_STATES, ADDRESS_MODIFICATION_VENDORS, HCIInternalState, \
    HCIConnectionState

logger = logging.getLogger(__name__)

def get_hci(index):
    '''
    Returns an HCI socket based on adapter index.
    '''
    # Make sure Python installation is built with Bluetooth support
    try:
        from socket import AF_BLUETOOTH #pyright: ignore #pylint: disable=W0611
    except ImportError:
        logger.error("Python interpreter is built without Bluetooth support, cannot use HCI devices")
        return None

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
    HciIface, and blocks its execution if at least one of them is not provided
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
        return super()(_wrap)

class Hci(VirtualDevice):
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
            available_devices[device_id] = Hci(index=device_id)

        return available_devices

    def __init__(self, index: int):
        """
        Initialization of an HCI virtual device wrapping a system HCI
        adapter with Scapy's BluetoothUserSocket.

        The virtual HCI device is identified by the same interface index
        than the one used on the host OS to avoid confusion.
        """
        super().__init__(index=index)

        # Create our message converter instance.
        self.__converter = HCIConverter(self)

        # Default timeout for HCI communications
        self.__timeout = 1.0

        ###
        ### WHAD device properties
        ###

        # Device index )same as host)
        self.__index = index

        # Device capabilities
        self._dev_capabilities = None

        # Firmware version (emulated)
        self._fw_version = None

        # Firmware URL
        self._fw_url = None

        # Firmware Authro
        self._fw_author = None

        # Device unique ID
        self._dev_id = None

        ###
        ### Virtual device state management
        ###

        # Internal state stores the current state for the device
        # Set to HCIInternalState.UNINITIALIZED by default, will be updated
        # once the device will be opened/accessed.
        self.__internal_state = HCIInternalState.UNINITIALIZED
        self.__started = False

        # Connection state when in Peripheral or Central modes.
        self.__conn_state: HCIConnectionState = HCIConnectionState.DISCONNECTED
        self._connected: bool = False

        # Specific states for Peripheral mode
        self.__advertising: bool = False
        self._cached_scan_data = None
        self._cached_scan_response_data = None

        # Specific states for Observer mode
        self.__scanning: bool = False
        self.__active_mode: bool = False

        # Flag used to avoid recursion when closing.
        self.__closing: bool = False

        # Active handles, used in Peripheral and Central modes
        self._active_handles: list[int] = []

        ###
        ### Scapy's BluetoothUserSocket related properties
        ###

        # We use a lock to avoid concurrency issues when accessing
        # the underlying HCI socket.
        self.__lock = Lock()
        self.__socket: Optional[BluetoothUserSocket]= None
        self.__opened = False

        # Disconnection event
        #
        # This event is used by the Read thread to notify the
        # main thread that a disconnection has completed.
        self.__disconnected = Event()

        # Queue used for passing responses from the IO read thread to
        # the main application thread.
        self.__hci_responses = Queue()

        ###
        ### HCI device properties (cache)
        ###

        # Adapter's local name
        self._local_name = None

        # Adapter's BD address
        self._bd_address = None

        # Adapter's BD address type (default: public)
        self._bd_address_type = AddressType.PUBLIC

        # Adapter's supported commands (local)
        self.__local_supp_cmd: Optional[HCI_Cmd_Complete_Supported_Commands] = None

        # Adapter's manufacturer name
        self._manufacturer = None

        # Data PDU Length management
        self.__datarate = Hci.PHY_1M
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

        # Classic Features
        self.__features: Optional[HCI_Cmd_Complete_Supported_Features] = None

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


    def open(self) -> bool:
        """
        Open device. If already open, issue a warning (debug-only).

        :raises WhadDeviceNotReady: An error occurred when trying to open the HCI device.
        """
        if not self.__opened:
            # Open a Bluetooth user socket
            self.__socket = get_hci(self.__index)
            if self.__socket is None:
                # An error occured, raise WhadDeviceNotReady
                logger.error("Whad device is not ready.")
                raise WhadDeviceNotReady()

            # Flush HCI interface
            logger.debug("[%s] Flushing HCI interface ...", self.interface)
            self.__socket.flush()

            # Mark as opened
            self.__opened = True

            # Ask parent class to run background I/O threads
            super().open()

            # Initialize this HCI interface
            #if not self._initialize():
            #    # If something went wrong, raise a WhadDeviceNotReady excption.
            #    raise WhadDeviceNotReady()
        else:
            # Device is already open, log this.
            logger.debug("[%s] Device is already open, ignoring call to open().", self.interface)

        # Device is now open and idling
        self.__internal_state = HCIInternalState.IDLE

        # Success
        return True

    def close(self):
        """
        Close current device.
        """
        # Avoid recursion that may occur due to super().close()
        if self.__closing:
            return

        # Marking device as in closing process
        self.__closing = True

        # Terminate all active connections.
        if self.__conn_state == HCIConnectionState.ESTABLISHED:
            # Disconnect if necessary
            for handle in self._active_handles:
                self._disconnect(handle)
            # Delete all active handles
            self._active_handles = []
        elif self.__conn_state == HCIConnectionState.INITIATING:
            # Cancel current connection if still trying to connect
            self.cancel_connection()

        # Stop advertising if still enabled.
        if self.__advertising:
            self._set_advertising_mode(False)

        # If device is still set in scanning mode, then stop scanning
        # as well.
        if self.__scanning:
            self._set_scan_mode(False)

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


    def write(self, payload):
        """
        Writes data to the device. It relies on select() in order to make sure
        we are allowed to write to the device and wait without eating too much CPU
        if the device is not ready to be written to.

        :param bytes data: Data to write
        :return: number of bytes written to the device
        :raises WhadDeviceNotReady: Virtual device cannot be accessed.
        """
        # If device is not open or socket could not be created, raise
        # a WhadDeviceNotReady exception.
        if not self.__opened or self.__socket is None:
            raise WhadDeviceNotReady()
        self.__socket.send(payload)

    def read(self):
        """
        Fetches data from the device, if there is any data to read. We call select()
        to make sure data is waiting to be read before reading it.

        :raises WhadDeviceNotReady: HCI device is unresponsive or has been disconnected.
        """
        if not self.__opened:
            raise WhadDeviceNotReady()
        try:
            # We assume here that we can determine if there is something to read
            # by calling readable without locking our socket
            if self.__socket is not None and self.__socket.readable(0.1):
                # Lock our socket to catch the awaiting event
                self.__lock.acquire()
                event = self.__socket.recv()
                self.__lock.release()
                if event.type == 0x4 and event.code in (0xe, 0xf, 0x13):
                    self.__hci_responses.put(event)
                else:
                    messages = self.__converter.process_event(event)
                    if messages is not None:
                        for message in messages:
                            self._send_whad_message(message)

        except (BrokenPipeError, OSError) as err:
            print(err)
            logger.error("Error, waiting...")
            sleep(1)

    def _wait_response(self, timeout: Optional[float] = None) -> Optional[HCI_Event_Hdr]:
        response = None
        try:
            response = self.__hci_responses.get(block=True, timeout=timeout)
        except Empty:
            logger.debug("[hci] device did not respond")
        return response

    def _write_packet(self, packet) -> bool:
        """
        Writes an HCI packet to the underlying HCI socket.
        """
        logger.debug("[hci] sending packet ...")

        # We claim access to our socket by acquiring its lock
        with self.__lock:
            if self.__socket is not None:
                # And we send our HCI ACL packet
                self.__socket.send(packet)
            else:
                logger.error("[%s] Cannot send HCI packet: missing socket.", self.interface)
                return False

        # Wait for a response
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

    def _write_command(self, command, from_queue=True):
        """
        Writes an HCI command and returns the response.
        """
        # Prepare HCI command
        hci_command = HCI_Hdr()/HCI_Command_Hdr()/command

        # Acquire lock on our socket
        self.__lock.acquire()

        # Send prepared HCI command
        logger.debug("[%s][write_command] Sending HCI command to user socket ...", self.interface)
        self.__socket.send(hci_command)
        logger.debug("[%s][write_command] Command sent.", self.interface)

        # If we are expecting to receive events from our reception queue, we
        # need to release the socket lock and wait for our read() method to
        # catch an answer. This is usually done when an HCI command is initiated
        # by the user application or the protocol stack in use.
        if from_queue:
            # We release our socket lock
            self.__lock.release()

            # And we wait for a response to be sent to our reception queue
            logger.debug("[%s][write_command] Waiting for response ...", self.interface)
            response = self._wait_response(timeout=.5)

            # Timeout reached ?
            if response is None:
                counter = 1
                while counter <= 3:
                    # Issue a warning that will be visible to the user
                    logger.warning("[%s] HCI interface seems stalled, retrying (%d/3) ...", self.interface, counter)

                    # Try sending a NOOP HCI Command packet
                    self.__socket.send(HCI_Hdr()/HCI_Command_Hdr(ogf=0, ocf=0, len=0))

                    # Wait for an answer
                    response = self._wait_response(timeout=.5)
                    if response is not None and HCI_Event_Command_Complete in response:
                        # If this response is sent for the last NOOP we sent, previous
                        # command has been discarded and needs to be sent again and
                        # things should be back in order.
                        if response[HCI_Event_Command_Complete].opcode == 0:
                            logger.debug("[%s] HCI interface answered NOOP, trying again with HCI command ...",
                                         self.interface)
                            self.__socket.send(hci_command)
                            counter += 1
                            response = self._wait_response(timeout=0.5)
                        elif response[HCI_Event_Command_Complete].opcode == hci_command[HCI_Command_Hdr].opcode:
                            # Brace yourselves, we received the answer we were waiting for,
                            # exiting loop
                            logger.debug("[%s] HCI interface answered the previous command, continuing",
                                         self.interface)
                            break
                    else:
                        # No answer, trying again
                        logger.debug("[%s] HCI interface not answering our NOOP, trying again ...",
                                     self.interface)
                        counter += 1

                # At this point, if response is None it simply means the HCI device is stuck.
                # We raise a WhadDeviceNotReady exception to notify others that this device
                # is not responding anymore.
                if response is None:
                    raise WhadDeviceNotReady()

            # We obviously received an answer, process it.
            while response.opcode != hci_command[HCI_Command_Hdr].opcode:
                logger.debug("[%s][write_command] Received response with opcode %d", self.interface, response.opcode)
                response = self._wait_response()
            logger.debug("[%s][write_command] Response received.", self.interface)

            if response is not None:
                logger.debug("[%s] HCI write command returned status %d",
                            self.interface, response.status)
        else:
            # In the other case, _write_command() is directly called from the
            # read() method and therefore we need to keep our socket locked
            # in order to read from it. Any event received that is not an
            # expected HCI_Command_Complete message is sent to the HCI RX
            # queue.

            event = self.__socket.recv()
            while not (event.type == 0x4 and event.code == 0xe):
                if event.type == 0x4 and event.code in (0xf, 0x13):
                    self.__hci_responses.put(event)
                event = self.__socket.recv()

            # We got our response: we release our socket lock and set the
            # captured event as the reponse to return to caller.
            self.__lock.release()
            response = event

        # Return the returned response.
        return response

    def reset(self):
        """
        self._bd_address = self._read_bd_address()
        self._local_name = self._read_local_name()
        """
        # Reset and initialize the underlying HCI adapter
        if not self._initialize():
            raise WhadDeviceNotReady()

        # Build device information based on information
        # retrieved from the HCI adapter
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

    def is_valid_cmd(self, command: int) -> bool:
        """Check if a specific WHAD message is supported by the virtual device."""
        if self._dev_capabilities is None:
            return False
        if Domain.BtLE not in self._dev_capabilities:
            return False
        return command in self._dev_capabilities[Domain.BtLE][1]


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
        if self.__local_supp_cmds is not None:
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
        if self.__features is not None:
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
        if self.__le_features is not None:
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

    def write_default_link_policy_settings(self, policy: int = 0x07) -> bool:
        """Configure the HCI interface default link policy settings for LE and BR/EDR controller"""
        response = self._write_command(HCI_Cmd_Write_Default_Link_Policy_Settings(policy=policy))
        return response is not None and response.status == 0x00

    def write_device_class(self, major_service_class: int = 0x360, major_device_class: int = 0x00,
                           minor_device_class: int = 0x00) -> bool:
        """Configure a default class of device"""
        response = self._write_command(HCI_Cmd_Write_Class_Of_Device(
            major_service_classes=major_service_class,
            major_device_class=major_device_class,
            minor_device_class=minor_device_class
        ))
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
                # self.write_simple_pairing_mode() and  # It looks like it causes issues with HCI :/
                self.write_connect_accept_timeout() and
                self.write_device_class() and
                self._set_event_mask(b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d") and
                self._le_set_event_mask(mask=b'\xff\xff\xff\xff\x03') and
                self._le_read_buffer_size() and
                self._read_bd_address() and
                self.indicates_le_support() and
                self.__read_filter_accept_list_size() and
                self.clear_filter_list()
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
    def _set_bd_address(self, bd_address: bytes = b"\x55\x44\x33\x22\x11\x00",
                        bd_address_type: int = AddressType.RANDOM) -> bool:
        """
        Modify the BD address (if supported by the HCI device).
        """
        logger.debug("[%s] Setting HCI adapter random address to %s ...", self.interface,
                     BDAddress(bd_address))

        # Disabled for now
        if bd_address_type == AddressType.PUBLIC:
            _, self._manufacturer = self._read_local_version_information()
            if self._manufacturer in ADDRESS_MODIFICATION_VENDORS:
                logger.info("[i] Address modification supported !")
                if self._manufacturer == b'Qualcomm Technologies International, Ltd. (QTIL)':
                    # Keep in cache existing devices
                    existing_devices = devices = HCIConfig.list()

                    # Write BD address and reset with vendor specific commands
                    self._write_command(HCI_Cmd_CSR_Write_BD_Address(addr=bd_address),
                                        from_queue=False)
                    self._write_command(HCI_Cmd_CSR_Reset(), from_queue=False)

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
                    self._write_command(command, from_queue=False)
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

        if bd_address_type == BDAddress.RANDOM:
            response = self._write_command(HCI_Cmd_LE_Set_Random_Address(address=bd_address))
            if response is not None and response.status == 0x00:
                logger.debug("[%s] Random address successfully set to %s", self.interface, 
                        BDAddress(bd_address))
                # Read BD address
                self._read_bd_address()
                logger.debug("[%s] BD address set to %s (random)", self.interface,
                             BDAddress(bd_address))
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
        # Cancel connection if we were trying to connect to a remote peripheral
        if self.__conn_state in (HCIConnectionState.INITIATING, HCIConnectionState.ESTABLISHED):
            self.terminate_connection()

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

            # Error ?
            if response is None:
                return False

            # Status different than expected ?
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
            # Not connected
            self.__conn_state = HCIConnectionState.DISCONNECTED
            logger.debug("[%s] HCI_LE_Create_Connection command failed with response %d", self.interface,
                         response.status)
        else:
            # Connection is initiating
            self.__conn_state = HCIConnectionState.INITIATING
        return response is not None and response.status == 0x00

    @req_cmd("le_create_connection_cancel")
    def cancel_connection(self) -> bool:
        """When iniating mode, cancel connection creationg
        """
        logger.debug("[%s] sending HCI cancel connection command ...")
        response = self._write_command(HCI_Cmd_LE_Create_Connection_Cancel())
        if response is not None and response.status == 0x00:
            self.__conn_state = HCIConnectionState.DISCONNECTED
            self._connected = False
            return True
        return False

    @req_cmd("disconnect")
    def _disconnect(self, handle):
        """
        Establish a disconnection using HCI device.
        """
        # Clear the disconnection event
        self.__disconnected.clear()

        # Send a Disconnect command
        logger.debug("[%s] sending HCI disconnect command ...")
        response = self._write_command(HCI_Cmd_Disconnect(handle=handle))
        if response is not None and response.status == 0x00:
            # If we got a valid response, then wait for the read thread to
            # receive a disconnection event
            self.__disconnected.wait()
            self.__conn_state = HCIConnectionState.DISCONNECTED
            self._connected = False
            return True
        return False

    def terminate_connection(self, handle: int):
        """Terminate an active connection or connection attempt.
        """
        if self.__conn_state == HCIConnectionState.INITIATING:
            logger.debug("[%s] HCI interface in connection initiation mode, canceling ...",
                         self.interface)
            if self.cancel_connection():
                logger.debug("[%s] connection initiation successfully canceled.", self.interface)
            else:
                logger.warning("[%s] Cannot cancel pending connection !", self.interface)
        elif self.__conn_state == HCIConnectionState.ESTABLISHED:
            logger.debug("[%s] HCI interface is connected, disconnecting ...")
            if self._disconnect(handle):
                logger.debug("[%s] Successfully disconnected.")
            else:
                logger.warning("[%s] Error while disconnecting !")

            # No more connection established
            self.__conn_state = HCIConnectionState.DISCONNECTED

    @req_cmd("le_set_advertising_data")
    def _set_advertising_data(self, data, from_queue: bool = True) -> bool:
        """
        Configure advertising data to use by HCI device.
        """
        # pad data if less than 31 bytes
        #if len(data) < 31:
        #    data += b'\x00'*(31 - len(data))

        # Send command and wait for response if required.
        result = True
        if from_queue:
            # Wait for response.
            logger.debug("[%s] Setting HCI LE advertising data ...", self.interface)
            response = self._write_command(HCI_Cmd_LE_Set_Advertising_Data(data=EIR_Hdr(data)))

            # Check response and update result.
            result = response is not None and response.status == 0x0
        else:
            # Otherwise send command without waiting a response.
            logger.debug("[%s] Setting HCI LE advertising data (non-blocking) ...", self.interface)
            self._write_command(HCI_Cmd_LE_Set_Advertising_Data(data=EIR_Hdr(data)), from_queue=False)

        # Return result
        return result

    @req_cmd("le_read_advertising_physical_channel_tx_power")
    def _read_advertising_physical_channel_tx_power(self, from_queue: bool = True) -> bool:
        """Read Advertising Physical Channel Tx Power level
        """
        logger.debug("Read Advertising Physical Channel Tx Power ...")
        response = self._write_command(HCI_Cmd_LE_Read_Advertising_Physical_Channel_Tx_Power(),
                                       from_queue=from_queue)

        if response is not None and response.status == 0x00:
            power_level = response[HCI_Cmd_Complete_LE_Advertising_Tx_Power_Level].tx_power_level
            logger.debug("[%s] Advertising Tx Power level: %d", self.interface, power_level)
            return True
        return False

    @req_cmd("le_set_scan_response_data")
    def _set_scan_response_data(self, data, from_queue=True) -> bool:
        """
        Configure scan response data to use by HCI device.
        """
        result = True
        if from_queue:
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
            logger.debug("[%s] Setting HCI LE Scan Response Data to %s (non-blocking) ...",
                         self.interface, data.hex())
            self._write_command(HCI_Cmd_LE_Set_Scan_Response_Data(
                    data=data + (31 - len(data)) * b"\x00", len=len(data)
                ),
                from_queue=False
            )

        # Return result
        return result

    @req_cmd("le_set_advertising_parameters")
    def set_advertising_parameters(self, interval_min: int = 0x0020, interval_max: int = 0x0020,
                                   adv_type="ADV_IND", oatype: int = 0, datype: int = 0,
                                   daddr:str = "00:00:00:00:00:00", channel_map: int = 0x7,
                                   filter_policy: str = "all:all", from_queue: bool = True) -> bool:
        """Configure the HCI LE advertising parameters.
        """
        # Wait for a response and update result accordingly.
        logger.debug("[%s] Setting HCI LE Advertising Parameters (blocking:%s) ...",
                    self.interface, from_queue)
        response = self._write_command(HCI_Cmd_LE_Set_Advertising_Parameters(
            interval_min = interval_min,
            interval_max = interval_max,
            adv_type=adv_type,
            oatype=0 if self._bd_address_type == AddressType.PUBLIC else 1,
            datype=0,
            daddr="00:00:00:00:00:00",
            channel_map=channel_map,
            filter_policy=filter_policy
        ), from_queue=from_queue)

        # Error ?
        if response is None:
            return False

        # Process response if required
        if from_queue:
            return response.status == 0x00

        # Success
        return True

    @req_cmd("le_set_advertising_enable")
    def _set_advertising_mode(self, enable=True, from_queue=True) -> bool:
        """
        Enable or disable advertising mode for HCI device.
        """
        # Already enable, nothing to do
        if self.__advertising and enable:
            logger.debug("[%s] Advertising is already enabled, nothing to do ...",
                    self.interface)
            return True

        # Not advertising and enabling, we need to configure our advertising
        # parameters.
        if not self.__advertising and enable:
            result = self.set_advertising_parameters(
                    interval_min = 0x0020,
                    interval_max = 0x0020,
                    adv_type="ADV_IND",
                    oatype=0 if self._bd_address_type == AddressType.PUBLIC else 1,
                    datype=0,
                    daddr="00:00:00:00:00:00",
                    channel_map=0x7,
                    filter_policy="all:all",
                    from_queue=from_queue
                )

            if result:
                logger.debug("[%s] Sending HCI LE Set Advertise Enable (enable:%s, blocking:%s)",
                             self.interface, enable, from_queue)
                if from_queue:
                    # Wait for a response and update result accordingly.
                    response = self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(enable=int(enable)))
                    if response is None:
                        result = False
                    else:
                        result = response.status == 0x00
                else:
                    # Don't wait, simply send command and consider it OK.
                    self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(
                        enable=int(enable)
                    ), from_queue=False)
                    result = True

            # On success, advertising has been enabled.
            self.__advertising = result
        else:
            logger.debug("[%s] Sending HCI LE Set Advertise Enable (enable:0, blocking:%s)",
                            self.interface, from_queue)
            # Disabling advertising
            if from_queue:
                response = self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(enable=0))
                if response is None:
                    result = False
                else:
                    result = response.status == 0x00
                    self.__advertising = False
            else:
                response = self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(enable=0),
                                               from_queue=False)
                self.__advertising = False
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

    def on_connection_created(self, handle: int = 0):
        """Callback method to handle a new connection
        """
        # Central mode ?
        if self.__internal_state == HCIInternalState.CENTRAL:
            # HCI interface now connected
            if self.__conn_state == HCIConnectionState.INITIATING:
                # Connection is now established
                self.__conn_state = HCIConnectionState.ESTABLISHED
                self._connected = True
                if handle not in self._active_handles:
                    self._active_handles.append(handle)
                else:
                    logger.warning("[%s] Connection event received with existing handle %d",
                                self.interface, handle)
            else:
                logger.debug("[%s] Unexpected connection event (handle:%d, current state:%d)",
                            self.interface, handle, self.__conn_state)
                logger.warning("[%s] Received an unexpected connection event", self.interface)
        elif self.__internal_state == HCIInternalState.PERIPHERAL:
            # HCI interface now connected and no more advertising
            self.__conn_state = HCIConnectionState.ESTABLISHED
            self._connected = True
            self.__advertising = False
            if handle not in self._active_handles:
                self._active_handles.append(handle)
            else:
                logger.warning("[%s] Connection event received with existing handle %d",
                            self.interface, handle)

    def on_connection_terminated(self, handle: int = 0):
        """Callback method to handle connection termination

        :param handle: Connection handle
        :type handle: int
        """
        if self.__conn_state == HCIConnectionState.ESTABLISHED:
            # Connection is now terminated
            self.__conn_state = HCIConnectionState.DISCONNECTED
            self._connected = False
            self.__disconnected.set()

            # Remove handle from active handles
            if handle in self._active_handles:
                self._active_handles.remove(handle)
            else:
                logger.warning("[%s] Disconnect event received for unknown handle %d",
                               self.interface, handle)

            # If we are in peripheral mode and running, re-enable advertising
            if self.__internal_state == HCIInternalState.PERIPHERAL and self.__started:
                logger.debug("[%s] Connection has terminated, restarting advertising ...",
                             self.interface)
                self._set_advertising_mode(True, from_queue=False)

    def _on_whad_ble_periph_mode(self, message):
        """Process WHAD message requesting to switch to Peripheral mode."""

        # Sanity Checks
        if self._dev_capabilities is None:
            raise WhadDeviceNotReady()

        logger.debug("whad ble periph mode message")
        if Commands.PeripheralMode in self._dev_capabilities[Domain.BtLE][1]:
            success = self._read_advertising_physical_channel_tx_power()
            if len(message.scan_data) > 0:
                # Set advertising data if set
                if self._cached_scan_data != message.scan_data:
                    logger.debug("[%s] New scan data received, updating advertising data ...", self.interface)
                    success = success and self._set_advertising_data(message.scan_data)
                    self._cached_scan_data = message.scan_data
            if len(message.scanrsp_data) > 0:
                if self._cached_scan_response_data != message.scanrsp_data:
                    logger.debug("[%s] New scanrsp data received, updating advertising data ...", self.interface)
                    success = success and self._set_scan_response_data(message.scanrsp_data)
                    self._cached_scan_response_data = message.scanrsp_data

            # Set advertising mode if not already advertising.
            if not self.__advertising and (not self._set_advertising_mode(True)):
                logger.debug("[%s] Unable to switch to advertising mode !", self.interface)
                success = False

            # If everything went OK, update state and send Success message
            if success:
                self.__internal_state = HCIInternalState.PERIPHERAL
                self._send_whad_command_result(CommandResult.SUCCESS)
                return
        else:
            logger.debug("[%s] HCI interface does not allow peripheral mode.")
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_disconnect(self, message):
        if self._disconnect(message.conn_handle):

            # Return success
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_connect(self, message):
        """ Handle a WHAD BleConnect message."""
        logger.debug("[%s] Received a WHAD Connect message", self.interface)

        # Are we supposed to process a Connect message ?
        if not self.is_valid_cmd(Commands.ConnectTo):
            logger.debug("[%s] Received an unsupported message (BLE::Connect) !",
                         self.interface)
            self._send_whad_command_result(CommandResult.ERROR)

        # Must be in Central mode or return WrongMode error
        elif self.__internal_state != HCIInternalState.CENTRAL:
            logger.debug("[%s] Received a Connect message while not in Central mode !",
                         self.interface)
            self._send_whad_command_result(CommandResult.WRONG_MODE)

        # All conditions met, process Connect message
        else:
            bd_address = message.bd_address
            bd_address_type = message.addr_type
            channel_map = message.channel_map if message.channel_map is not None else None
            hop_interval = message.hop_interval if message.hop_interval is not None else 96
            if self._connect(bd_address, bd_address_type, hop_interval=hop_interval,
                             channel_map=channel_map):
                self._send_whad_command_result(CommandResult.SUCCESS)
                return

        # Failure
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_central_mode(self, message):
        """Process BLE Central mode message. """
        # Make sure this command is valid
        if not self.is_valid_cmd(Commands.CentralMode):
            logger.debug("[%s] Received an unsupported message (BLE::CentralMode) !",
                         self.interface)
            self._send_whad_command_result(CommandResult.ERROR)

        # If we already are in Central mode, return Success.
        elif self.__internal_state == HCIInternalState.CENTRAL:
            logger.debug("[%s] Device already in central mode, ignoring CentralMode command.",
                         self.interface)
            self._send_whad_command_result(CommandResult.SUCCESS)

        # If current mode is running, cannot switch
        elif self.__started:
            logger.debug("[%s] A different mode is already enabled, cannot swith to Central mode !",
                         self.interface)
            self._send_whad_command_result(CommandResult.WRONG_MODE)
        else:
            # If not running, switch mode
            self.__internal_state = HCIInternalState.CENTRAL
            self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_scan_mode(self, message: ScanMode):
        # Make sure this command is valid
        if not self.is_valid_cmd(Commands.ScanMode):
            logger.debug("[%s] Received an unsupported message (BLE::ScanMode) !",
                         self.interface)
            self._send_whad_command_result(CommandResult.ERROR)

        # If we already are in Observer mode, return Success.
        elif self.__internal_state == HCIInternalState.OBSERVER and message.active == self.__active_mode:
            logger.debug("[%s] Device already in scanner mode, ignoring ScanMode command.",
                         self.interface)
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif self.__started:
            logger.debug("[%s] A different mode is already enabled, cannot swith to Scanner mode !",
                         self.interface)
            self._send_whad_command_result(CommandResult.WRONG_MODE)
        else:
            # Switch to observer (scanner) mode
            self.__active_mode = message.active
            if self._set_scan_parameters(self.__active_mode):
                self.__internal_state = HCIInternalState.OBSERVER
                self._send_whad_command_result(CommandResult.SUCCESS)
            else:
                self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_start(self, _):
        """Enable the current active mode.

        Configure the HCI interface based on selected mode.
        """
        # Make sure this command is valid
        if not self.is_valid_cmd(Commands.Start):
            logger.debug("[%s] Received an unsupported message (BLE::Start) !",
                         self.interface)
            self._send_whad_command_result(CommandResult.ERROR)
        elif self.__started:
            # Return an error
            logger.debug("[%s] Mode is already running !", self.interface)
            self._send_whad_command_result(CommandResult.ERROR)
        else:
            # Handling mode start based on selected mode
            logger.info("whad internal state: %d", self.__internal_state)
            if self.__internal_state == HCIInternalState.OBSERVER:
                # Starting the observer mode by enabling scanning
                self._set_scan_mode(True)
                self.__started = True
                self._send_whad_command_result(CommandResult.SUCCESS)
            elif self.__internal_state == HCIInternalState.PERIPHERAL:
                # Peripheral mode: enable advertising if not already enabled.
                if not self.__advertising:
                    result = self._set_advertising_mode(True)
                    if result:
                        self.__started = True
                        self._send_whad_command_result(CommandResult.SUCCESS)
                    else:
                        self._send_whad_command_result(CommandResult.ERROR)
                else:
                    self.__started = True
                    self._send_whad_command_result(CommandResult.SUCCESS)

            elif self.__internal_state == HCIInternalState.CENTRAL:
                # Central mode does not require anything special
                self.__started = True
                self._send_whad_command_result(CommandResult.SUCCESS)
            else:
                self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_stop(self, message):
        """Process WHAD Stop message."""

        # Stop any connection attempt, terminate established connections
        for handle in self._active_handles:
            self.terminate_connection(handle)

        # Process with requested mode
        if self.__internal_state == HCIInternalState.SCANNING:
            self._set_scan_mode(False)
            self.__internal_state = HCIInternalState.NONE
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif self.__internal_state == HCIInternalState.CENTRAL:
            # Update mode and return success
            self.__internal_state = HCIInternalState.NONE
            self._send_whad_command_result(CommandResult.SUCCESS)
        elif self.__internal_state == HCIInternalState.PERIPHERAL:
            # We are not advertising anymore
            self._set_advertising_mode(False)
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_send_pdu(self, message):
        """Send a given PDU into the active connection
        """
        # Make sure this command is valid
        if not self.is_valid_cmd(Commands.SendPDU):
            logger.debug("[%s] Received an unsupported message (BLE::SendPdu) !",
                         self.interface)
            self._send_whad_command_result(CommandResult.ERROR)

        # Only available in Peripheral and Central modes
        elif not self.__internal_state in (HCIInternalState.CENTRAL, HCIInternalState.PERIPHERAL):
            logger.debug("[%s] Cannot send PDU in current mode (%d) !",
                         self.interface, self.__internal_state)
            self._send_whad_command_result(CommandResult.WRONG_MODE)

        # Make sure current mode is running
        elif not self.__started:
            logger.debug("[%s] Current mode not started, cannot process BLE::SendPdu message !",
                         self.interface)
            self._send_whad_command_result(CommandResult.ERROR)

        # Make sure we have an active connection
        elif self.__conn_state == HCIConnectionState.ESTABLISHED:
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
                    logger.debug("[%s] Cannot send PDU: unsupported operation !", self.interface)
                    self._send_whad_command_result(CommandResult.PARAMETER_ERROR)
            else:
                # Wrong state, cannot send PDU
                logger.debug("[%s] Cannot send PDU: wrong packet direction !", self.interface)
                self._send_whad_command_result(CommandResult.ERROR)
        else:
            # Not connected
            logger.debug("[%s] Cannot send PDU: no active connection with handle %d !", self.interface,
                         message.conn_handle)
            logger.debug("[%s] Cannot send PDU: no connection.", self.interface)
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_set_bd_addr(self, message):
        """Process a WHAD BLE SetBdAddress message."""
        # Make sure this command is valid
        if not self.is_valid_cmd(Commands.SetBdAddress):
            logger.debug("[%s] Received an unsupported message (BLE::SetBdAddress) !",
                         self.interface)
            self._send_whad_command_result(CommandResult.ERROR)
        elif self.__started:
            # Return an error
            logger.debug("[%s] Mode is already running !", self.interface)
            self._send_whad_command_result(CommandResult.ERROR)
        else:
            logger.debug("Received WHAD BLE set_bd_addr message")
            if self._set_bd_address(message.bd_address, message.addr_type):
                logger.debug("[%s] HCI adapter BD address set to %s", self.interface,str(message.bd_address))
                self._send_whad_command_result(CommandResult.SUCCESS)
            else:
                logger.debug("[%s] HCI adapter does not support BD address spoofing", self.interface)
                self._send_whad_command_result(CommandResult.ERROR)
