from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied, \
    WhadDeviceUnsupportedOperation
from whad.device.virtual import VirtualDevice
from whad import WhadDomain

from whad.hub.generic.cmdresult import CommandResult
from whad.hub.discovery import Capability
from whad.hub.ble import Direction as BleDirection, Commands, AddressType

from whad.scapy.layers.bluetooth import BluetoothUserSocketFixed
from scapy.layers.bluetooth import BluetoothSocketError, \
    HCI_Hdr, HCI_Command_Hdr, HCI_Cmd_Reset, HCI_Cmd_Set_Event_Filter, \
    HCI_Cmd_Connect_Accept_Timeout, HCI_Cmd_Set_Event_Mask, HCI_Cmd_LE_Host_Supported, \
    HCI_Cmd_Read_BD_Addr, HCI_Cmd_Complete_Read_BD_Addr, HCI_Cmd_LE_Set_Scan_Enable, \
    HCI_Cmd_LE_Set_Scan_Parameters, HCI_Cmd_LE_Create_Connection, HCI_Cmd_Disconnect, \
    HCI_Cmd_LE_Set_Advertise_Enable, HCI_Cmd_LE_Set_Advertising_Data, HCI_Event_Disconnection_Complete, \
    HCI_Cmd_LE_Set_Scan_Response_Data, HCI_Cmd_LE_Set_Random_Address, HCI_Cmd_LE_Long_Term_Key_Request_Reply,\
    HCI_Cmd_LE_Start_Encryption_Request

from whad.device.virtual.hci.converter import HCIConverter
from whad.device.virtual.hci.hciconfig import HCIConfig
from whad.device.virtual.hci.constants import LE_STATES, ADDRESS_MODIFICATION_VENDORS, HCIInternalState
from whad.scapy.layers.hci import HCI_Cmd_Read_Local_Version_Information, \
    HCI_Cmd_Complete_Read_Local_Version_Information, HCI_VERSIONS, BT_MANUFACTURERS, \
    HCI_Cmd_Read_Local_Name, HCI_Cmd_Complete_Read_Local_Name, HCI_Cmd_LE_Read_Supported_States, \
    HCI_Cmd_Complete_LE_Read_Supported_States, HCI_Cmd_CSR_Write_BD_Address, HCI_Cmd_CSR_Reset, \
    HCI_Cmd_TI_Write_BD_Address, HCI_Cmd_BCM_Write_BD_Address, HCI_Cmd_Zeevo_Write_BD_Address, \
    HCI_Cmd_Ericsson_Write_BD_Address, HCI_Cmd_ST_Write_BD_Address, HCI_Cmd_LE_Set_Host_Channel_Classification
from select import select
from os import read, write
from time import sleep
from queue import Queue, Empty
from struct import unpack

import logging
logger = logging.getLogger(__name__)

def get_hci(index):
    '''
    Returns an HCI socket based on adapter index.
    '''
    try:
        logger.debug('Creating bluetooth socket ...')
        socket = BluetoothUserSocketFixed(index)
        logger.debug('Bluetooth socket successfully created.')
        return socket
    except BluetoothSocketError:
        logger.debug('An error occured while creating bluetooth socket')
        try:
            logger.debug("Shutting down HCI interface #%d", index)
            HCIConfig.down(index)
            logger.debug("HCI interface %d shut down, creating Bluetooth socket ...", index)
            socket = BluetoothUserSocketFixed(index)
            logger.debug("Bluetooth socket successfully created.")
            return socket
        except BluetoothSocketError as err:
            logger.debug(err)
            logger.debug("Cannot create Bluetooth socket !")
            return None
        except PermissionError as perm_err:
            logger.debug("WHAD device hci%d cannot be accessed.", index)
            raise WhadDeviceAccessDenied("hci%d" % index) from perm_err
    except PermissionError:
        logger.debug("WHAD device hci%d cannot be accessed.", index)
        raise WhadDeviceAccessDenied("hci%d" % index)


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
        self.__converter = HCIConverter(self)
        self.__index = index
        self._advertising = False
        self.__socket = None
        self.__internal_state = HCIInternalState.NONE
        self.__opened = False
        self.__hci_responses = Queue()
        self._dev_capabilities = None
        self._bd_address = None
        self._bd_address_type = AddressType.PUBLIC
        self._fw_version = None
        self._fw_url = None
        self._fw_author = None
        self._dev_id = None
        self._manufacturer = None
        self._cached_scan_data = None
        self._cached_scan_response_data = None
        self.__timeout = 1.0
        self._connected = False
        self._active_handles = []
        self._waiting_disconnect = False

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
                logger.error('Whad device is not ready.')
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
        # Disconnect if necessary
        for handle in self._active_handles:
            self._disconnect(handle)
        # Ask parent class to stop I/O thread
        logger.debug('Stopping background IO threads ...')
        super().close()

        # Close underlying device.
        if self.__socket is not None:
            logger.debug('Closing Bluetooth socket ...')
            self.__socket.close()
            del self.__socket
            self.__socket = None
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
            if self.__socket is not None and self.__socket.readable(0.1):
                event = self.__socket.recv()
                if event.type == 0x4 and (event.code == 0xe or event.code == 0xf or event.code == 0x13):
                    self.__hci_responses.put(event)
                else:
                    messages = self.__converter.process_event(event)
                    if messages is not None:
                        for message in messages:
                            self._send_whad_message(message)
                    # If the connection is stopped and peripheral mode is started,
                    # automatically re-enable advertising based on cached data
                    if HCI_Event_Disconnection_Complete in event:
                        self._waiting_disconnect = False
                    if HCI_Event_Disconnection_Complete in event and self.__internal_state == HCIInternalState.PERIPHERAL:
                        # If advertising was not enabled, skip
                        if not self._advertising:
                            return

                        # if data are cached, configure them
                        if self._cached_scan_data is not None:
                            # We can't wait for response because we are in the reception loop context
                            success = self._set_advertising_data(self._cached_scan_data, wait_response=False)

                        if self._cached_scan_response_data is not None:
                            success = self._set_scan_response_data(self._cached_scan_response_data, wait_response=False)

                        # We need to artificially disable advertising indicator to prevent cached operation
                        self._advertising = False
                        self._set_advertising_mode(True, wait_response=False)


        except (BrokenPipeError, OSError) as err:
            print(err)
            logger.error("Error, waiting...")
            sleep(1)

    def _wait_response(self, timeout=None):
        response = None
        try:
            response = self.__hci_responses.get(block=True, timeout=timeout)
        except Empty as err:
            logger.debug('[hci] device did not respond')
        return response

    def _write_packet(self, packet):
        """
        Writes an HCI packet.
        """
        logger.debug('[hci] sending packet ...')
        self.__socket.send(packet)

        # Wait for response
        logger.debug('[hci] waiting for response (timeout: %s)...' % self.__timeout)
        response = self._wait_response(timeout=self.__timeout)
        if response is None:
            return False
        else:
            logger.debug('[hci] response code: 0x%04x' % response.code)
            while response.code != 0x13:
                logger.debug('[hci] waiting for response ...')
                response = self._wait_response(timeout=self.__timeout)
                if response is None:
                    return False
                logger.debug('[hci] response code: 0x%04x' % response.code)
        return response.number == 1

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
        self._bd_address = self._read_BD_address()
        self._local_name = self._read_local_name()
        self._fw_version, self._manufacturer = self._read_local_version_information()
        self._fw_author = self._manufacturer
        self._dev_id = self._generate_dev_id()
        self._fw_url = b"<unknown>"
        self._dev_capabilities = self._get_capabilities()

    def _generate_dev_id(self):
        devid = (bytes.fromhex(self._bd_address.replace(":","")) + self._local_name)[:16]
        if len(devid) < 16:
            devid += b"\x00" * (16 - len(devid))
        return devid

    def _get_capabilities(self):
        supported_states = self._read_LE_supported_states()

        capabilities = 0
        supported_commands = []
        for state in supported_states:
            name, cap, commands = state
            capabilities = capabilities | cap
            supported_commands += commands

        supported_commands += [Commands.SetBdAddress]

        supported_commands = list(set(supported_commands))
        capabilities = {
            WhadDomain.BtLE : (
                                capabilities | Capability.NoRawData,
                                supported_commands
            )
        }
        return capabilities

    def _reset(self):
        """
        Reset HCI device.
        """
        response = self._write_command(HCI_Cmd_Reset())
        return response is not None and response.status == 0x0


    def _set_event_filter(self, type=0):
        """
        Configure HCI device event filter.
        """
        response = self._write_command(HCI_Cmd_Set_Event_Filter(type=type))
        return response is not None and response.status == 0x00

    def _set_event_mask(self, mask=b"\xff\xff\xfb\xff\x07\xf8\xbf\x3d"):
        """
        Configure HCI device event mask.
        """
        response = self._write_command(HCI_Cmd_Set_Event_Mask(mask=mask))
        return response is not None and response.status == 0x00

    def _set_connection_accept_timeout(self, timeout=32000):
        """
        Configure HCI device connection accept timeout.
        """
        response = self._write_command(HCI_Cmd_Connect_Accept_Timeout(timeout=timeout))
        return response is not None and response.status == 0x00

    def _indicates_LE_support(self):
        """
        Indicates to HCI Device that the Host supports Low Energy mode.
        """
        response = self._write_command(HCI_Cmd_LE_Host_Supported())
        return response is not None and response.status == 0x00

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

    def _set_BD_address(self, bd_address="11:22:33:44:55:66", bd_address_type=AddressType.PUBLIC):
        """
        Modify the BD address (if supported by the HCI device).
        """
        if bd_address_type == AddressType.PUBLIC:
            _, self._manufacturer = self._read_local_version_information()
            if self._manufacturer in ADDRESS_MODIFICATION_VENDORS:
                logger.info("[i] Address modification supported !")
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
                self._bd_address = self._read_BD_address()
                self._dev_id = self._generate_dev_id()
                self._bd_address_type = AddressType.PUBLIC
                return self._bd_address == bd_address

            else:
                logger.debug("Address modification not supported.")
                return False
        else:
            self._write_command(HCI_Cmd_LE_Set_Random_Address(address=bd_address))
            self._bd_address = self._read_BD_address()
            self._bd_address_type = AddressType.RANDOM
            return True

    def _set_scan_parameters(self, active=True):
        """
        Configure Scan parameters for HCI device.
        """
        response = self._write_command(HCI_Cmd_LE_Set_Scan_Parameters(type=int(active)))
        return response is not None and response.status == 0x00

    def _set_scan_mode(self, enable=True):
        """
        Enable or disable scan mode for HCI device.
        """
        response = self._write_command(HCI_Cmd_LE_Set_Scan_Enable(enable=int(enable), filter_dups=False))
        return response is not None and response.status == 0x00

    def _connect(self, bd_address, bd_address_type=AddressType.PUBLIC, hop_interval=96, channel_map=None):
        """
        Establish a connection using HCI device.
        """
        patype = 0 if bd_address_type == AddressType.PUBLIC else 1
        if channel_map is not None:
            formatted_channel_map = unpack("<Q",channel_map+ b"\x00\x00\x00")[0]
            response = self._write_command(HCI_Cmd_LE_Set_Host_Channel_Classification(chM=formatted_channel_map))
            if response.status != 0x00:
                return False
        response = self._write_command(
            HCI_Cmd_LE_Create_Connection(
                paddr=bd_address,
                patype=patype,
                min_interval=hop_interval,
                max_interval=hop_interval
            )
        )
        return response is not None and response.status == 0x00

    def _disconnect(self, handle):
        """
        Establish a disconnection using HCI device.
        """
        response = self._write_command(HCI_Cmd_Disconnect(handle=handle))
        self._waiting_disconnect = True
        while self._waiting_disconnect:
            sleep(0.1)
        return response is not None and response.status == 0x00

    def _set_advertising_data(self, data, wait_response=True):
        """
        Configure advertising data to use by HCI device.
        """
        # pad data if less than 31 bytes
        if len(data) < 31:
            data += b'\x00'*(31 - len(data))

        # Send command
        if wait_response:
            response = self._write_command(HCI_Cmd_LE_Set_Advertising_Data(data=data))
            return response is not None and response.status == 0x0
        else:
            self._write_command(HCI_Cmd_LE_Set_Advertising_Data(data=data), wait_response=False)
            return True

    def _set_scan_response_data(self, data, wait_response=True):
        """
        Configure scan response data to use by HCI device.
        """
        if wait_response:
            response = self._write_command(HCI_Cmd_LE_Set_Scan_Response_Data(
                    data=data + (31 - len(data)) * b"\x00", len=len(data)
                )
            )
            return response is not None and response.status == 0x0
        else:
            response = self._write_command(HCI_Cmd_LE_Set_Scan_Response_Data(
                    data=data + (31 - len(data)) * b"\x00", len=len(data)
                ),
                wait_response=False
            )
            return True


    def _set_advertising_mode(self, enable=True, wait_response=True):
        """
        Enable or disable advertising mode for HCI device.
        """
        if self._advertising and enable:
            return True
        else:
            logger.debug('Enable advertising: %s' % enable)
            if wait_response:
                response = self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(enable=int(enable)))
                success = response.status == 0x00
            else:
                self._write_command(HCI_Cmd_LE_Set_Advertise_Enable(enable=int(enable)), wait_response=False)
                success = True
            if success:
                self._advertising = enable
            return success

    def _enable_encryption(self, enable=True, handle=None,  key=None, rand=None, ediv=None):

        if self.__converter.pending_key_request:
            response = self._write_command(
                HCI_Cmd_LE_Long_Term_Key_Request_Reply(
                    handle=handle,
                    ltk=key[::-1]
                )
            )
            self.__converter.pending_key_request = False
        else:
            response = self._write_command(
                HCI_Cmd_LE_Start_Encryption_Request(
                    handle=handle,
                    ltk=key[::-1],
                    rand=rand,
                    ediv=unpack('<H', ediv)[0]
                )
            )
        return response.status == 0x00


    def _on_whad_ble_encryption(self, message):
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
        logger.debug('whad ble periph mode message')
        if Commands.PeripheralMode in self._dev_capabilities[WhadDomain.BtLE][1]:
            success = True
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
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_disconnect(self, message):
        success = self._disconnect(message.conn_handle)
        if success:
            self._send_whad_command_result(CommandResult.SUCCESS)
            return
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_connect(self, message):
        if Commands.ConnectTo in self._dev_capabilities[WhadDomain.BtLE][1]:
            bd_address = message.bd_address
            bd_address_type = message.addr_type
            channel_map = message.channel_map if message.channel_map is not None else None
            hop_interval = message.hop_interval if message.hop_interval is not None else 96
            if self._connect(bd_address, bd_address_type, hop_interval=hop_interval, channel_map=channel_map):
                self._send_whad_command_result(CommandResult.SUCCESS)
                return
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_central_mode(self, message):
        if Commands.CentralMode in self._dev_capabilities[WhadDomain.BtLE][1]:
            self.__internal_state = HCIInternalState.CENTRAL
            self._send_whad_command_result(CommandResult.SUCCESS)
            return
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_scan_mode(self, message):
        if Commands.ScanMode in self._dev_capabilities[WhadDomain.BtLE][1]:
            active_scan = message.active
            if self._set_scan_parameters(active_scan):
                self.__internal_state = HCIInternalState.SCANNING
                self._send_whad_command_result(CommandResult.SUCCESS)
                return
        self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_start(self, message):
        logger.info('whad internal state: %d' % self.__internal_state)
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
            self._advertising = False
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_send_pdu(self, message):
        logger.debug('Received WHAD BLE send_pdu message')
        if ((self.__internal_state == HCIInternalState.CENTRAL and message.direction == BleDirection.MASTER_TO_SLAVE) or
           (self.__internal_state == HCIInternalState.PERIPHERAL and message.direction == BleDirection.SLAVE_TO_MASTER)):
            try:
                hci_packets = self.__converter.process_message(message)

                if hci_packets is not None:
                    logger.debug('sending HCI packets ...')
                    success = True
                    for hci_packet in hci_packets:
                        success = success and self._write_packet(hci_packet)
                    logger.debug('HCI packet sending result: %s' % success)
                    if success:
                        logger.debug('send_pdu command succeeded.')
                        self._send_whad_command_result(CommandResult.SUCCESS)
                    else:
                        logger.debug('send_pdu command failed.')
                        self._send_whad_command_result(CommandResult.ERROR)
                pending_messages = self.__converter.get_pending_messages()
                for pending_message in pending_messages:
                    self._send_whad_message(pending_message)

            except WhadDeviceUnsupportedOperation as err:
                logger.debug('Parameter error')
                self._send_whad_command_result(CommandResult.PARAMETER_ERROR)
        else:
            # Wrong state, cannot send PDU
            logger.debug('wrong state or packet direction.')
            self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_ble_set_bd_addr(self, message):
        logger.debug('Received WHAD BLE set_bd_addr message')
        if self._set_BD_address(message.bd_address, message.addr_type):
            logger.debug('HCI adapter BD address set to %s' % str(message.bd_address))
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            logger.debug('HCI adapter does not support BD address spoofing')
            self._send_whad_command_result(CommandResult.ERROR)
