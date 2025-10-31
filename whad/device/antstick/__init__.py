'''
ANT Stick adaptation layer for WHAD.
'''
import logging
from threading import  Lock
from time import sleep, time
from queue import Queue
from struct import pack

from usb.util import find_descriptor, endpoint_direction, ENDPOINT_IN, ENDPOINT_OUT
from usb.core import find, USBError, USBTimeoutError
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from ..device import VirtualDevice

from whad.hub.ant import Commands
from whad.hub.ant import ChannelType as WhadChannelType
from whad.hub.discovery import Domain, Capability
from whad.hub.generic.cmdresult import CommandResult


from whad.ant.crypto import is_valid_network_key, generate_sync_from_network_key, ANT_PLUS_NETWORK_KEY

from whad.scapy.layers.ant import ANT_Hdr, ANT_Plus_Header_Hdr
from whad.scapy.layers.antstick import ANTStick_Message, ANTStick_Command_Request_Message, \
    ANTStick_Requested_Message_Serial_Number, ANTStick_Requested_Message_ANT_Version, \
    ANTStick_Requested_Message_Advanced_Burst, ANTStick_Requested_Message_Capabilities, \
    ANTStick_Command_Enable_Extended_Messages, ANTStick_Command_Open_RX_Scan_Mode, \
    ANTStick_Command_Set_Channel_ID, ANTStick_Command_Set_Channel_RF_Frequency, \
    ANTStick_Channel_Response_Or_Event, ANTStick_Command_Set_Network_Key, \
    ANTStick_Command_Assign_Channel, ANTStick_Command_Close_Channel, \
    ANTStick_Command_Open_Channel, ANTStick_Extended_Assignment_Extension, \
    ANTStick_Data_Broadcast_Data, ANTSTICK_SYNC, ANTStick_Command_Reset, \
    ANTStick_Command_Unassign_Channel, ANTStick_Command_Set_Channel_Period, \
    ANTStick_Command_Search_Timeout, ANTStick_Command_Low_Priority_Search_Timeout, \
    ANTStick_Data_Acknowledged_Data, ANTStick_Command_Lib_Config, \
    ANTStick_RSSI_Data_Extension, ANTStick_Timestamp_Data_Extension, \
    ANTStick_Data_Burst_Data, ANTStick_Data_Extension, ANTStick_Advanced_Data_Burst_Data

from .constants import AntStickIds, AntMessageCode, AntMessageIds
from .channel import ChannelStatus, ChannelType, Channel
from .network import Network

logger = logging.getLogger(__name__)

def get_antstick(index=0, bus=None, address=None):
    '''
    Returns an ANTStick USB object based on index or bus & address.
    '''
    # We have two generations of ANTStick dongle, match them all
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



class ANTStick(VirtualDevice):
    '''ANTStick virtual device implementation.
    '''

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
                available_devices.append(ANTStick(bus=antstick.bus, address=antstick.address))
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
        '''
        Create device connection
        '''
        device = get_antstick(index,bus=bus,address=address)
        # Check the presence of dongle, or raises an WhadDeviceNotFound exception
        if device is None:
            raise WhadDeviceNotFound

        _, self.__antstick = device

        # Dongle related variables
        self.__antstick_capabilities = None
        self.__opened = False
        self.__opened_stream = False
        self.__lock = Lock()
        self.__in_buffer = b""

        # Dongle related event & packets queues
        self.__event_queue = Queue()
        self.__pdu_queue = Queue()
        self.__response_queue = Queue()
        self.__ack_queue = Queue()

        # Variables linked to ANT protocol management
        self.__last_timestamp = time() * 1000
        # we need to generate the sync value according to the network key algorithm
        self.__sync = generate_sync_from_network_key(ANT_PLUS_NETWORK_KEY)
        self.__rf_channel = 57
        self.__number_of_channels = 0
        self.__number_of_networks = 0
        self.__channels = {}
        self.__networks = {}
        self.__reload_channel = None
        # Call VirtualDevice init
        super().__init__()

    def reset(self):
        '''Reset the ANTStick dongle.
        '''
        self.__antstick.reset()

    def _configure_endpoints(self):
        '''Configure the available in & out endpoints
        '''
        # Code inspired by openant project: https://github.com/Tigge/openant
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
            # match the first IN endpoint
            custom_match=lambda e: endpoint_direction(e.bEndpointAddress)
            == ENDPOINT_IN,
        )



    def open(self):
        '''Open the ANTStick device.
        '''

        # We need to detach the kernel module linked to dongle before use
        if self.__antstick.is_kernel_driver_active(0):
            self.__antstick.detach_kernel_driver(0)
        try:
            self.__antstick.set_configuration()
        except USBError as err:
            # Check if we are allowed to access the driver by OS
            if err.errno == 13:
                raise WhadDeviceAccessDenied("antstick") from err
            # Otherwise, raises a generic WhadDeviceNotReady exception
            raise WhadDeviceNotReady() from err

        # Reset the dongle, then configure endpoints
        self._configure_endpoints()

        self.__antstick.reset()
            
        # Get all relevant informations about the dongle: serial number, manufacturer, firmware version ...
        logger.debug("Recovering serial number, manufacturer, firmware version...")
        serial_number = self._get_serial_number()

        if serial_number is not None:
            self._dev_id = self._get_ant_version()[:12] + pack("<I", serial_number)
            self._dev_id = b"\x00" * (16 - len(self._dev_id)) + self._dev_id
        
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()

        # Recover capabilities
        logger.debug("Recovering capabilities.")
        self._dev_capabilities = self._get_capabilities()

        self._initialize_channels()
        self._initialize_networks()
        self._configure_extension_mode(enable=True)
        self._configure_lib(rssi=True, channel_id=True, timestamp=True)
        self.pending_burst_packets = []

        # Ask parent class to run a background I/O thread
        self.__opened = True
        super().open()

       

    def close(self):
        '''
        Close current device.
        '''
        # Ask parent class to stop I/O thread
        super().close()

        # Close underlying device.
        self.__opened = False
        
    def _initialize_channels(self):
        '''Initialize the internal structure linked to channels
        '''
        for channel_number in range(self.__number_of_channels):
            self.__channels[channel_number] = Channel(
                status = ChannelStatus.UNASSIGNED, 
                type = None, 
                opened = False, 
                assigned_network = None, 
                period = None, 
                device_number = 0, 
                device_type = 0, 
                transmission_type = 0, 
                rf_channel = 57
            )
        
    def _initialize_networks(self):
        '''Initialize the internal structure linked to networks
        '''
        for network_number in range(self.__number_of_networks):
            self.__networks[network_number] = Network(
                network_key = None
            )


    def _reload_channel(self, channel_number):
        ''' Reload the configuration for a given channel number.

        :param channel_number: integer representing the id of selected channel
        :type channel_number: int
        '''
        logger.debug("Reload the ANT channel...")

        # Mark it as closed
        self.__channels[channel_number].opened = False

        # Configure the channel ID (chan number, dev number, transmission type)
        self._set_channel_id(
            channel_number = channel_number, 
            device_number = self.__channels[channel_number].device_number, 
            device_type = self.__channels[channel_number].device_type, 
            transmission_type = self.__channels[channel_number].transmission_type
        )
        # Configure the RF channel (frequency)
        self._set_channel_rf_channel(
            channel_number = channel_number, 
            rf_channel = self.__channels[channel_number].rf_channel, 
        )

        # Configure the channel period (time between time slots)
        self._set_channel_period(
            channel_number = channel_number, 
            period = self.__channels[channel_number].period, 
        )

        # Open the channel
        self._open_channel(channel_number)

    def write(self, payload):
        print("[i] write")

    def read(self):
        '''Read incoming data. 

        This is the main thread responsible for processing incoming data (D->H).
        '''

        # We check if it is opened
        if not self.__opened:
            raise WhadDeviceNotReady()
        else:
            # Should we reload the channel ? 
            if self.__reload_channel is not None:
                self.__opened = False
                self._reload_channel(self.__reload_channel)
                self.__reload_channel = None
                self.__opened = True

            # Ask to read an incoming ANTStick message
            self._antstick_read_message()

            # If the stream is marked as open
            if self.__opened_stream:

                # Process events
                while not self.__event_queue.empty():
                    event = ANTStick_Message(self.__event_queue.get())
                    logger.debug("Processing event : " + repr(event))

                    if event.message_code in (
                        AntMessageCode.EVENT_RX_FAIL,
                        AntMessageCode.EVENT_TX,
                        AntMessageCode.EVENT_TRANSFER_TX_COMPLETED, 
                        AntMessageCode.EVENT_TRANSFER_TX_FAILED,
                        AntMessageCode.EVENT_TRANSFER_TX_START
                    ):
                        # Filter only channel event 
                        logger.debug("Event filtered as channel event, signaling the event.")
                        self._send_whad_ant_channel_event(event.channel_number, event.message_code)
                    
                    # Regularly, the channel is automatically closed, re-open it as soon as 
                    # possible by reloading the channel.
                    if (
                        event.message_code == AntMessageCode.EVENT_CHANNEL_CLOSED and 
                        self.__channels[event.channel_number].opened
                    ):
                        logger.debug("Event indicating a channel closed is detected, reloading channel...")
                        self.__reload_channel = event.channel_number

                    
                    elif event.message_code in (
                        AntMessageCode.EVENT_TRANSFER_TX_COMPLETED,
                        AntMessageCode.EVENT_TRANSFER_TX_FAILED,
                        AntMessageCode.EVENT_TRANSFER_RX_FAILED,
                        AntMessageCode.EVENT_TRANSFER_TX_START,
                        AntMessageCode.EVENT_TRANSFER_NEXT_DATA_BLOCK
                    ):
                        # Add to the ACK queue any event related to transfer management.
                        logger.debug("Event related to transfer management, adding to ACK queue...")
                        self.__ack_queue.put(bytes(event))

                # Process PDU
                while not self.__pdu_queue.empty():
                    # Recover incoming data PDU
                    data = ANTStick_Message(self.__pdu_queue.get())
                    logger.debug("Processing incoming PDU : " + repr(data))

                    if data is not None:
                        # Recover the channel number from the ANTStick Message PDU
                        channel_number = data.channel_number & 0b11111

                        # Recover the device number from the ANTStick Message PDU
                        device_number = (
                            data.device_number if ANTStick_Data_Extension in data 
                            else self.__channels[channel_number].device_number
                        )
                        
                        # Recover the device type from the ANTStick Message PDU
                        device_type = (
                            data.device_type if ANTStick_Data_Extension in data 
                            else self.__channels[channel_number].device_type
                        )

                        # Recover the transmission type from the ANTStick Message PDU
                        transmission_type = (
                            data.transmission_type if ANTStick_Data_Extension in data 
                            else self.__channels[channel_number].transmission_type
                        )

                        # Recover if the packet is broadcast or ack/burst
                        broadcast = (0 if ANTStick_Data_Broadcast_Data in data else 1)

                        # Convert it to a scapy packet
                        pkt = bytes(
                                ANT_Hdr(
                                    preamble = self.__sync, 
                                    device_number = device_number,  
                                    device_type = device_type,
                                    transmission_type = transmission_type, 
                                    broadcast = broadcast, 
                                    ack = False,
                                    end = False, 
                                    count = 0, 
                                    slot = False, 
                                    unknown = 0
                            ) / data.pdu
                        )
                        pkt = ANT_Hdr(pkt)

                        # Extract RSSI and timestamp if available
                        rssi = None
                        if ANTStick_RSSI_Data_Extension in data:
                            rssi = data.rssi
                        if ANTStick_Timestamp_Data_Extension in data:
                            timestamp = data.timestamp
                        else:
                            # If timestamp is not available, build it according to Host clock
                            now = time() * 1000
                            timestamp = now - self.__last_timestamp

                        # Transmit the PDU as WHAD ANT Message
                        self._send_whad_ant_pdu(
                            pdu=bytes(pkt), 
                            rf_channel=self.__rf_channel, 
                            timestamp=int(timestamp * 1000), 
                            rssi = rssi
                        )
                    else:
                        sleep(0.0001)
                        
            else:
                sleep(0.0001)


    def _send_whad_ant_pdu(self, pdu, channel_number=0, rf_channel=0, timestamp=None, rssi=None):
        '''Send a WHAD ANT PDU message from virtual device to whad-client core

        :param pdu: PDU to transmit
        :type pdu: bytes
        :param channel_number: channel number in use
        :type channel_number: int
        :param rf_channel: RF channel (frequency) in use (offset from 2400MHz)
        :type rf_channel: int 
        :param timestamp: timestamp in use (in us)
        :type timestamp: int
        :param rssi: RSSI in use
        :type rssi: int 
        '''
        # Create the PDUReceived message according to parameters
        msg = self.hub.ant.create_pdu_received(
            pdu=pdu, 
            channel_number=channel_number, 
            rf_channel=rf_channel
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp

        # Set RSSI if provided
        if rssi is not None:
            msg.rssi = rssi

        # Send message
        self._send_whad_message(msg)


    def _get_manufacturer(self):
        '''Returns the manufacturer indicated by the ANT dongle.
        '''
        return self.__antstick.manufacturer.encode('utf-8').replace(b"\x00", b"")

    def _get_firmware_version(self):
        '''Returns the firmware version (fake value since it can't be recovered from the dongle.)
        '''
        return (1, 0, 0)

    def _get_url(self):
        '''Returns the URL of the manufacturer website (thisisant website).
        '''
        return "https://thisisant.com".encode('utf-8')



    def _get_capabilities(self):
        '''Returns the capabilities of the ANTStick dongle.

        This class transmits a Command Request allowing to recover all the features available on 
        the dongle. It then builds the WHAD capabilities associated to the ANT domain dynamically.
        '''

        # Forge and transmit the command request and indicate the expected dissector in the response.
        response = self._antstick_send_command(
            ANTStick_Command_Request_Message(message_id_req=0x54), 
            rsp_filter = lambda response: ANTStick_Requested_Message_Capabilities in response
        )

        # Extract ANTStick capabilities
        if ANTStick_Requested_Message_Capabilities in response:
            self.__antstick_capabilities = response
            self.__number_of_channels = response.max_channels
            self.__number_of_networks = response.max_networks
            
            # We do not support Raw PDU here since ANTStick only provide a limited control over packets.
            capabilities = Capability.NoRawData
            commands = [
                Commands.ListChannels, 
                Commands.ListNetworks,
            ]

            # Infer the available capabilities and the related commands.
            if (
                self.__antstick_capabilities.cap_no_receive_messages == 0 and 
                self.__antstick_capabilities.cap_no_receive_channels == 0 
            ): 
                capabilities |= Capability.Sniff
                commands += [
                        Commands.Sniff, 
                        Commands.SetDeviceNumber, 
                        Commands.SetDeviceType, 
                        Commands.SetTransmissionType, 
                        Commands.SetRFChannel, 
                        Commands.Start, 
                        Commands.Stop
                    ]
            if (
                self.__antstick_capabilities.cap_no_transmit_messages == 0 and 
                self.__antstick_capabilities.cap_no_transmit_channels == 0 
            ): 
                capabilities |= Capability.Inject
                commands += [
                    Commands.Send, 
                    Commands.SetRFChannel, 
                    Commands.Start, 
                    Commands.Stop
                ]
            if (
                self.__antstick_capabilities.cap_no_ackd_messages == 0 and
                self.__antstick_capabilities.cap_no_burst_messages == 0 and
                self.__antstick_capabilities.cap_no_transmit_channels == 0 
            ):
                capabilities |= Capability.SimulateRole
                commands += [
                    Commands.SlaveMode,
                    Commands.SetDeviceNumber, 
                    Commands.SetDeviceType, 
                    Commands.SetTransmissionType,
                    Commands.SetChannelPeriod, 
                    Commands.SetNetworkKey,
                    Commands.SetRFChannel, 
                    Commands.AssignChannel, 
                    Commands.UnassignChannel, 
                    Commands.OpenChannel, 
                    Commands.CloseChannel, 
                    Commands.Start, 
                    Commands.Stop
                ]
            if (
                self.__antstick_capabilities.cap_no_receive_channels == 0
            ):
                capabilities |= Capability.SimulateRole
                commands += [
                    Commands.MasterMode,
                    Commands.SetDeviceNumber, 
                    Commands.SetDeviceType, 
                    Commands.SetTransmissionType,
                    Commands.SetChannelPeriod, 
                    Commands.SetNetworkKey,
                    Commands.SetRFChannel, 
                    Commands.AssignChannel, 
                    Commands.UnassignChannel, 
                    Commands.OpenChannel, 
                    Commands.CloseChannel, 
                    Commands.Start, 
                    Commands.Stop
                ]

            if (
                self.__antstick_capabilities.cap_scan_mode_enabled == 1
            ):
                capabilities |= Capability.Scan
                commands += [
                    Commands.Sniff, 
                    Commands.SetRFChannel, 
                    Commands.SetDeviceNumber, 
                    Commands.SetDeviceType, 
                    Commands.SetTransmissionType,
                    Commands.SetChannelPeriod, 
                    Commands.SetNetworkKey,
                    Commands.Start, 
                    Commands.Stop
                ]

            # Returns the capabilities
            return {
                Domain.ANT : (
                                capabilities, 
                                list(set(commands))
                )
            }       

        return None

    def _get_serial_number(self):
        '''Transmit a command to get the ANTStick serial number and returns it.
        
        :return: serial number of the ANTStick dongle
        :rtype: int
        '''
        response = self._antstick_send_command(
            ANTStick_Command_Request_Message(message_id_req=0x61), 
            rsp_filter = lambda response: ANTStick_Requested_Message_Serial_Number in response, 
            force_reset = True
        )

        if ANTStick_Requested_Message_Serial_Number in response:
            return response.serial_number
        return None        


    def _get_ant_version(self):
        '''Transmit a command to get the ANTStick supported ANT version and returns it.
        
        :return: supported ANT Version of the ANTStick dongle
        :rtype: bytes
        '''

        response = self._antstick_send_command(
            ANTStick_Command_Request_Message(message_id_req=0x3E),
            rsp_filter= lambda response:ANTStick_Requested_Message_ANT_Version in response
        )
        if ANTStick_Requested_Message_ANT_Version in response:
            return response.version
        return None


    def _set_network_key(self, network_key, network_number=0):
        '''Transmit a command to configure the network key associated with a given network.
        
        This function will also generate the syncword associated with the provided network key. 
        The internal structure of the virtual device will then be updated accordingly.

        :param network_key: network key to use (8-bytes length bytes)
        :type network_key: bytes
        :param network_number: network number of the network to configure
        :type network_number: int
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''
        if not is_valid_network_key(network_key):
            return False

        if network_number not in self.__networks:
            return False

        response = self._antstick_send_command(ANTStick_Command_Set_Network_Key(
            network_number=network_number, 
            network_key=network_key[::-1]
            )
        )

        self.__sync = generate_sync_from_network_key(network_key)
        self.__networks[network_number].key = network_key
        self.__networks[network_number].sync_word = generate_sync_from_network_key(network_key)

        return True

    def _unassign_channel(self, channel_number=0):
        '''Transmit a command to unassign a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to unassign
        :type channel_number: int
        :return: boolean indicating if it has been successfully unassigned.
        :rtype: bool
        '''

        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        response = self._antstick_send_command(ANTStick_Command_Unassign_Channel(
                channel_number=channel_number
            )
        )
        self.__channels[channel_number].status = ChannelStatus.UNASSIGNED
        self.__channels[channel_number].assigned_network = None
        return True


    def _assign_channel(self, channel_number=0, channel_type=0, network_number=0, background_scanning = False):
        '''Transmit a command to assign a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to assign
        :type channel_number: int
        :param channel_type: channel type to use
        :param channel_type: int
        :param network_number: network number of the network to link to the channel
        :param network_number: int
        :param background_scanning: indicate if the background scanning must be enabled or not
        :type background_scanning: bool
        :return: boolean indicating if it has been successfully assigned.
        :rtype: bool
        '''

        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)
        
        # Send ANTStick command to assign ANT channel
        response = self._antstick_send_command(ANTStick_Command_Assign_Channel(
                channel_number=channel_number, 
                network_number=network_number, 
                channel_type=channel_type
            )
             / 
            ANTStick_Extended_Assignment_Extension(
                extended_assignment = 0x20 # | (0x01 if background_scanning else 0x00)
            ) # for some reason transmission doesn't work without async mode so let's hardcode it
        )
        #TODO: check if extended assignement can use background scanning or not
        # Update internal structure
        self.__channels[channel_number].status = ChannelStatus.ASSIGNED
        self.__channels[channel_number].assigned_network = network_number 
        self.__channels[channel_number].type = ChannelType(channel_type)
        return True

    def _set_channel_id(self, channel_number=0, device_number=None, device_type=None, transmission_type=None):
        '''Transmit a command to set the channel ID for a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to configure
        :type channel_number: int
        :param device_number: device number to use
        :param device_number: int
        :param device_type: device type to use
        :param device_type: int
        :param transmission_type: transmission type to use
        :param transmission_type: int
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''

        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)


        if device_number is None:
            device_number = self.__channels[channel_number].device_number
        if device_type is None:
            device_type = self.__channels[channel_number].device_type
        if transmission_type is None:
            transmission_type = self.__channels[channel_number].transmission_type

        # Send ANTStick command to configure ANT Channel ID 
        response = self._antstick_send_command(ANTStick_Command_Set_Channel_ID(
                channel_number=channel_number, 
                device_number=device_number, 
                device_type=device_type, 
                transmission_type=transmission_type
            )
        )
        # Update internal structure
        self.__channels[channel_number].device_number = device_number
        self.__channels[channel_number].device_type = device_type
        self.__channels[channel_number].transmission_type = transmission_type

        return True


    def _set_channel_rf_channel(self, channel_number=0, rf_channel=57):
        '''Transmit a command to set the RF channel (frequency) for a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to configure
        :type channel_number: int
        :param rf_channel: rf channel to use (frequency = 2400 + rf_channel MHz)
        :param rf_channel: int
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''

        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        # Send ANTStick command to configure RF channel
        response = self._antstick_send_command(ANTStick_Command_Set_Channel_RF_Frequency(
                channel_number=channel_number, 
                channel_rf_frequency=rf_channel
            )
        )

        # Update internal structure
        self.__rf_channel = rf_channel
        self.__channels[channel_number].rf_channel = rf_channel

        return True



    def _set_channel_period(self, channel_number=0, period = 0):
        '''Transmit a command to set the channel period for a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to configure
        :type channel_number: int
        :param period: period to use
        :param period: int
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''
        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        # Send ANTStick command to configure RF channel
        response = self._antstick_send_command(ANTStick_Command_Set_Channel_Period(
                channel_number=channel_number, 
                period=period
            )
        )
        # Update internal structure
        self.__channels[channel_number].period = period

        return True

    def _open_rx_scan_mode(self, sync_channel_packets_only=False):
        '''Open RX Scan mode (uses ANT channel 0).
        
        This function will also update the channel internal structure of the virtual device.

        :param sync_channel_packets_only: boolean indicating if the synchronization must be done on channel packets only
        :type sync_channel_packets_only: bool
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''
        if 0 not in self.__channels:
            return False

        if self.__channels[0].opened:
            self._close_channel(0)

        # Send an ANTStick command to configure Open RX Scan mode
        response = self._antstick_send_command(ANTStick_Command_Open_RX_Scan_Mode(
                sync_channel_packets_only=(1 if sync_channel_packets_only else 0)
            )
        )
        # Update the channel 0 as opened in internal structure
        self.__channels[0].opened = True
        return True


    def _configure_lib(self, rssi=False, channel_id=False, timestamp=False):
        '''Configure the supported features in the receiving library (this virtual device).

        :param rssi: boolean indicating if virtual device supports RSSI. 
        :type rssi: bool
        :param channel_id: boolean indicating if virtual device supports channel ID. 
        :type channel_id: bool
        :param timestamp: boolean indicating if virtual device supports RX timestamps. 
        :type timestamp: bool
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''
        # Send ANTStick command to indicate what features are supported on Host side
        response = self._antstick_send_command(ANTStick_Command_Lib_Config(
                channel_id_output_enabled=(1 if channel_id else 0), 
                rssi_output_enabled=(1 if rssi else 0), 
                rx_timestamp_enabled=(1 if timestamp else 0)
            )
        )
        return True


    def _configure_extension_mode(self, enable=True):
        '''Enable or disable the extension mode in dongle.

        :param enable: boolean indicating if extended messages are supported.
        :type enable: bool
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''

        response = self._antstick_send_command(ANTStick_Command_Enable_Extended_Messages(
                enable=(1 if enable else 0)
            )
        )
        return True

    def _open_channel(self, channel_number=0):
        '''Transmit a command to open a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to open
        :type channel_number: int
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''
        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            return True

            # Configure an infinite search timeout, because who wants a 
            # channel to be arbitrarily closed after a few seconds ? WTF Garmin !
            self._configure_search_timeout(channel_number, 0xFF)
            self._configure_low_priority_search_timeout(channel_number, 0)

        # Send the ANTStick command required to open the channel
        response = self._antstick_send_command(ANTStick_Command_Open_Channel(
                channel_number=channel_number
            )
        )
        self.__channels[channel_number].opened = True
        return True


    def _configure_search_timeout(self, channel_number=0, timeout=0):
        '''Transmit a command to configure the search timeout for a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to configure
        :type channel_number: int
        :param timeout: search timeout value to use
        :type timeout: int
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''
        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        response = self._antstick_send_command(ANTStick_Command_Search_Timeout(
                channel_number=channel_number, 
                timeout=timeout
            )
        )
        return True

    def _configure_low_priority_search_timeout(self, channel_number=0, timeout=0):
        '''Transmit a command to configure the low priority search timeout for a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to configure
        :type channel_number: int
        :param timeout: search timeout value to use
        :type timeout: int
        :return: boolean indicating if it has been successfully configured.
        :rtype: bool
        '''
        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        # Send ANTStick command to configure the low priority search timeout
        response = self._antstick_send_command(ANTStick_Command_Low_Priority_Search_Timeout(
                channel_number=channel_number, 
                timeout=timeout
            )
        )
        return True

    def _close_channel(self, channel_number=0):
        '''Transmit a command to close a given channel.
        
        This function will also update the channel internal structure of the virtual device.

        :param channel_number: channel number of the channel to close
        :type channel_number: int
        :return: boolean indicating if it has been successfully closed.
        :rtype: bool
        '''
        if channel_number not in self.__channels:
            return False

        if not self.__channels[channel_number].opened:
            return True

        # Send the ANTStick command to close the channel
        response = self._antstick_send_command(ANTStick_Command_Close_Channel(
                channel_number=channel_number
            )
        )
        # Update the internal structure to mark the channel as closed
        self.__channels[channel_number].opened = False
        return True

    def _antstick_reset(self):
        '''Transmit a command to force a full reset of the dongle.

        This command will behave differently depending on the dongle version in use, 
        expect a short slot of time where the dongle will not respond because of the reset process.
        '''
        self._antstick_send_command(ANTStick_Command_Reset(), force_reset=True)
        

    def _antstick_send_command(
            self,
            command,
            rsp_filter=lambda p:True,
            force_reset=False,
            timeout=200,
            no_response=False
    ):
        '''
        Send an ANTStick command to the dongle.

        Depending on the configured mode, it is possible to :
            - ignore the response (if `no_response` is set to True)
            - accept any response (if `no_response` is set to False)
            - accept a specific kind of response (if `no_response` is set 
            to False and `rsp_filter` has been configured to match a given 
            type of response).

        :param command: ANTStick command to transmit to the dongle
        :type command: bytes
        :param rsp_filter: Filter to apply to filter out a specific response type
        :type rsp_filter: function
        :param force_reset: boolean indicating if a reset must be applied after
        :type force_reset: bool
        :param timeout: maximal timeout value (in ms) before terminating 
        :type timeout: int
        :param no_response: boolean indicating if the response must be ignored or not
        :type no_response: bool
        :return: None if no response received before the timeout, received response otherwise
        :rtype: ANTStick_Message
        '''
        data = bytes(ANTStick_Message() / command)
        logger.debug("Transmitting ANTStick command: " +  repr(ANTStick_Message(data)))
        

        while True:
            try:
                    #self.__lock.acquire()
                    self.__antstick.write(self.__out_endpoint,
                                        data, timeout=timeout)
                    #self.__lock.release()

                    break
            except (USBTimeoutError, USBError):
                #self.__lock.release()

                pass
        if no_response:
            return None

        response = None
        while response is None:
            if not self.__opened:
                self._antstick_read_message()

            response = self._antstick_read_response(rsp_filter=rsp_filter)
            
            if response is None and force_reset:
                self.__antstick.reset()
                self.__antstick.write(self.__out_endpoint, data, timeout=timeout)
                self._antstick_read_message()

        if ANTStick_Channel_Response_Or_Event in response and response.message_code == 40: # invalid message 
            return None

        return response

    def _antstick_read_response(self, rsp_filter=lambda p : True, timeout=200):
        '''
        Read an ANTStick response from the dongle.

        It can filter out specific response type according to the rsp_filter function. 

        :param rsp_filter: Filter to apply to filter out a specific response type
        :type rsp_filter: function
        :param timeout: maximal timeout value (in ms) before terminating 
        :type timeout: int
        :return: None if no response received before the timeout, received response otherwise
        :rtype: ANTStick_Message
        '''
        if not self.opened:
            self._antstick_read_message()
        if self.__response_queue.empty():
            return None
        else:
            msg = self.__response_queue.get()
            while not rsp_filter(ANTStick_Message(msg)):
                self.__response_queue.put(msg)
                msg = self.__response_queue.get()

            logger.debug("Receiving ANTStick response: " +  repr(ANTStick_Message(msg)))
            return ANTStick_Message(msg)

    def _antstick_read_message(self, timeout=200):
        '''
        Read a chunk of data from the IN endpoint of the dongle, and populate three queues 
        depending on the type of received messages:
        - PDU Queue
        - Event Queue
        - Response Queue

        :param timeout: maximal timeout value (in ms) before terminating 
        :type timeout: int
        '''
        # Read a chunk of data from the IN endpoint
        try:
                #self.__lock.acquire()
                msg = bytes(
                    self.__antstick.read(
                        self.__in_endpoint,
                        64, timeout=timeout
                    )
                )
                #self.__lock.release()
                # Append it to the in buffer          
                self.__in_buffer += msg

        except (USBTimeoutError, USBError) as e:
            pass#self.__lock.release()

        while True:
            while len(self.__in_buffer) > 0 and self.__in_buffer[0] != ANTSTICK_SYNC:
                self.__in_buffer = self.__in_buffer[1:]
                
            if len(self.__in_buffer) <= 4:
                break

            if len(self.__in_buffer) < 2 + self.__in_buffer[1]:
                break

            msg = self.__in_buffer[:len(self.__in_buffer) + 3]
            
            self.__in_buffer = self.__in_buffer[len(msg):]

            message_id = msg[2]
            if message_id in (
                AntMessageIds.BROADCAST_DATA,
                AntMessageIds.ACKNOWLEDGED_DATA,
                AntMessageIds.BURST_TRANSFER_DATA,
                AntMessageIds.ADVANCED_BURST_TRANSFER_DATA
            ):
                self.__pdu_queue.put(msg)
            elif (
                message_id == AntMessageIds.RESPONSE_CHANNEL and
                ANTStick_Message(msg).message_code >= 1 and ANTStick_Message(msg).message_code <= 17 # event range
            ):
                self.__event_queue.put(msg)
            else:
                self.__response_queue.put(msg)
    


    # WHAD command handlers

    def _on_whad_ant_sniff(self, message):
        """Callback called when an ANT Sniff message is received.

        Configure the ANTStick dongle according to the configuration provided in the message.
        In sniffing mode, only channel #0 and network #0 will be used and configured. The behaviour 
        of a sniffer will be emulated with ANTStick dongle by disabling all filters and using the 
        Open Rx Scan Mode, allowing to trigger a continuous reception without any sleep between reception slots.

        A Generic WHAD message CommandResult will be transmitted to Host to indicate a successful operation.

        :param message: WHAD ANT-domain SniffMode message
        :type message: SniffMode
        """
        self._set_network_key(network_number = 0, network_key = message.network_key)
        self._assign_channel(
            channel_number = 0, 
            network_number = 0, 
            channel_type = 0x40, 
            background_scanning = True
        )
        self._set_channel_id(
            channel_number = 0,
            device_number = message.device_number, 
            device_type = message.device_type, 
            transmission_type = message.transmission_type
        )
        self._set_channel_rf_channel(
            channel_number = 0, 
            rf_channel = message.rf_channel
        )
        self._open_rx_scan_mode()
        # self._open_channel(channel_number=0)
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_start(self, message):
        """Callback called when an ANT Start message is received.

        Open the stream of reception according to the currently configured mode.

        A Generic WHAD message CommandResult will be transmitted to Host to indicate a successful operation.
        
        :param message: WHAD ANT-domain Start message
        :type message: Start
        """

        self.__opened_stream = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_stop(self, message):
        """Callback called when an ANT Stop message is received.

        Close the stream of reception on the ANTStick dongle.

        A Generic WHAD message CommandResult will be transmitted to Host to indicate a successful operation.
        
        :param message: WHAD ANT-domain Stop message
        :type message: Stop
        """
        self.__opened_stream = False
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_list_networks(self, message):
        """Callback called when an ANT ListNetworks message is received.

        Will trigger the transmission of a WHAD notification AvailableNetworks,
        indicating the number of networks supported by the ANTStick dongle.

        :param message: WHAD ANT-domain ListNetworks message
        :type message: ListNetworks
        """
        self._send_whad_ant_available_networks(self.__number_of_networks)
        
    def _send_whad_ant_available_networks(self, number_of_networks):
        """Transmit a WHAD notification AvailableNetworks, 
        indicating the number of networks supported by the ANTStick dongle.

        :param number_of_networks: Number of networks supported by the ANTStick dongle
        :type number_of_networks: int
        """

        # create available networks notification
        msg = self.hub.ant.create_available_networks(
            number_of_networks=number_of_networks
        )
        # Send message
        self._send_whad_message(msg)


    def _on_whad_ant_list_channels(self, message):
        """Callback called when an ANT ListChannels message is received.

        Will trigger the transmission of a WHAD notification AvailableChannels,
        indicating the number of channels supported by the ANTStick dongle.

        :param message: WHAD ANT-domain ListChannels message
        :type message: ListChannels
        """
        self._send_whad_ant_available_channels(self.__number_of_channels)

    def _send_whad_ant_available_channels(self, number_of_channels):
        """Transmit a WHAD notification AvailableChannels, 
        indicating the number of channels supported by the ANTStick dongle.

        :param number_of_channels: Number of channels supported by the ANTStick dongle
        :type number_of_channels: int
        """

        # create available channels notification
        msg = self.hub.ant.create_available_channels(
            number_of_channels=number_of_channels
        )
        # Send message
        self._send_whad_message(msg)


    def _send_whad_ant_channel_event(self, channel_number, event):
        """Transmit a WHAD notification ChannelEvent, indicating a specific channel
         event for a given channel signaled by the ANTStick dongle.

        :param channel_number: Channel number of the concerned channel
        :type channel_number: int
        :param event: channel event code of the signaled event
        :type event: int 
        """
        # create channel event notification
        msg = self.hub.ant.create_channel_event(
            channel_number, 
            event
        )
        # Send message
        self._send_whad_message(msg)


    def _on_whad_ant_open_channel(self, message):
        """Callback called when an ANT OpenChannel message is received.

        If the channel is configured and available, open the provided channel.

        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain OpenChannel message
        :type message: OpenChannel
        """
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)
        
        if not self._open_channel(message.channel_number):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_close_channel(self, message):
        """Callback called when an ANT CloseChannel message is received.

        If the channel is opened, close the provided channel.

        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain CloseChannel message
        :type message: CloseChannel
        """
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)
        
        if not self._close_channel(message.channel_number):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)
        

    def _on_whad_ant_assign_channel(self, message):
        """Callback called when an ANT AssignChannel message is received.

        If the channel and networks are available, assign the provided channel to the
        provided network and configure the channel type and background scanning mode.

        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain AssignChannel message
        :type message: AssignChannel
        """
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)
        
        if message.network_number not in self.__networks:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        # Frequency agility, fast channel initiation & async transmission ignored for now
        if not self._assign_channel(
            channel_number = message.channel_number, 
            network_number = message.network_number, 
            channel_type = ChannelType.convert_from_whad_channel_type(message.channel_type), 
            background_scanning = message.background_scanning
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_unassign_channel(self, message):
        """Callback called when an ANT UnassignChannel message is received.

        If the channel and networks are assigned, unassign the provided channel and the
        provided network.

        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain AssignChannel message
        :type message: AssignChannel
        """
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if not self._unassign_channel(
            channel_number = message.channel_number
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_set_network_key(self, message):
        """Callback called when an ANT SetNetworkKey message is received.

        For the provided network (if available), configure the network key if the provided key 
        is valid according to ANT check algorithm. 

        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain SetNetworkKey message
        :type message: SetNetworkKey
        """

        if message.network_number not in self.__networks:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if len(message.network_key) != 8 and not is_valid_network_key(message.network_key):
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if not self._set_network_key(
            network_number = message.network_number, 
            network_key = message.network_key
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_set_rf_channel(self, message):
        """Callback called when an ANT RFChannel message is received.

        If the provided channel is available, configure the RF frequency to use 
        to the one provided in the message. RF Channels frequency is computed according to:

            rf_channel_frequency = 2400 MHz  + rf_channel

        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain SetRFChannel message
        :type message: SetRFChannel
        """
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.rf_channel < 0 or message.rf_channel > 125:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if not self._set_channel_rf_channel(
            channel_number = message.channel_number, 
            rf_channel = message.rf_channel
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_set_device_number(self, message):
        """Callback called when an ANT SetDeviceNumber message is received.

        If the provided channel is available, configure the device number to use 
        to the one provided in the message. 

        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain SetDeviceNumber message
        :type message: SetDeviceNumber
        """        
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.device_number < 0 or message.device_number > 0xFFFF:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if not self._set_channel_id(
            channel_number = message.channel_number, 
            device_number = message.device_number
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_set_device_type(self, message):
        """Callback called when an ANT SetDeviceType message is received.

        If the provided channel is available, configure the device type to use 
        to the one provided in the message. 
        
        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain SetDeviceType message
        :type message: SetDeviceType
        """        
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.device_type < 0 or message.device_type > 0xFF:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if not self._set_channel_id(
            channel_number = message.channel_number, 
            device_type = message.device_type
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_set_transmission_type(self, message):
        """Callback called when an ANT SetTransmissionType message is received.

        If the provided channel is available, configure the transmission type to use 
        to the one provided in the message. 
        
        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain SetTransmissionType message
        :type message: SetTransmissionType
        """        
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.transmission_type < 0 or message.transmission_type > 0xFF:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if not self._set_channel_id(
            channel_number = message.channel_number, 
            transmission_type = message.transmission_type
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)



    def _on_whad_ant_set_channel_period(self, message):
        """Callback called when an ANT SetChannelPeriod message is received.

        If the provided channel is available, configure the channel period to use 
        to the one provided in the message. 
        
        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain SetChannelPeriod message
        :type message: SetChannelPeriod
        """        
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.channel_period < 0 or message.channel_period > 0xFFFF:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if not self._set_channel_period(
            channel_number = message.channel_number, 
            period = message.channel_period
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_send(self, message):
        """Callback called when an ANT SendPdu message is received.

        If the provided channel is available, send a PDU according to the 
        configuration indicated in its header.
        
        Will trigger the transmission of a WHAD Generic CommandResult message,
        indicating the success of the operation.

        :param message: WHAD ANT-domain SendPdu message
        :type message: SendPdu
        """       
        packet = ANT_Hdr(message.pdu)

        if packet.broadcast == 1:
            logger.debug('Transmitting ANT Ack/Burst PDU: ' + repr(packet))
            # We have to transmit an ACK/Burst packet
            if packet.end == 0:
                # If packet is marked as not final (end field = 0), add it to pending PDU queue
                self.pending_burst_packets.append(message)
                self._send_whad_command_result(CommandResult.SUCCESS)

            else:
                # If packet is marked as final, it's either an ack or a burst

                if len(self.pending_burst_packets) > 0:
                    # If we have pending PDU in the queue, build the final Burst command
                    # We follow the Burst sequencing algorithm according to ANT Specification 
                    data = b""
                    self.pending_burst_packets.append(message)

                    for burst in self.pending_burst_packets:
                        data += bytes(burst.pdu)[7:]
                    packets = len(data) // 8
                    if len(data) / 8 > packets:
                        packets = packets + 1
                        while (len(data) // 8) != packets:
                            data = data + b"\x00" 
                    for i in range(packets):
                        sequence = ((i - 1) % 3) + 1
                        if i == 0:
                            sequence = 0
                        elif i == packets - 1:
                            sequence = sequence | 0b100

                        channel_seq = burst.channel_number | sequence << 5
                        packet_data = data[i * 8 : i * 8 + 8]
                        
                        # Send a command for each 8-byte length burst
                        self._antstick_send_command(
                            ANTStick_Data_Burst_Data(
                                channel_number = channel_seq, 
                                pdu = packet_data
                            ), no_response = True
                        )
                    # Clean up the pending PDU queue
                    self.pending_burst_packets = []            
            
                    # Wait actively for an ack and return the CommandResult                    
                    while self.__ack_queue.empty():
                        sleep(0.001)

                    ack_event = ANTStick_Message(self.__ack_queue.get())

                    logger.debug('Receiving an ANT Ack event.')
                    
                    if ack_event.message_code == AntMessageCode.EVENT_TRANSFER_TX_FAILED:
                        self._send_whad_command_result(CommandResult.ERROR)
                        return
                    else:
                        self._send_whad_command_result(CommandResult.SUCCESS)
                        return
                else:
                    # We are transmitting an acknowledged PDU, send the corresponding ANTStick command 
                    self._antstick_send_command(
                        ANTStick_Data_Acknowledged_Data(
                            channel_number = message.channel_number, 
                            pdu = bytes(message.pdu[-8:]) # crop the message to 8 bytes
                        ), no_response = True
                    )
                    
                    # Actively expect an ack
                    while self.__ack_queue.empty():
                        sleep(0.001)

                    ack_event = ANTStick_Message(self.__ack_queue.get())
                    
                    if ack_event.message_code == 6:
                        self._send_whad_command_result(CommandResult.ERROR)
                        return
                    else:
                        self._send_whad_command_result(CommandResult.SUCCESS)
                        return
        else:
            # We have to transmit a Broadcast packet
            # Note: it will be repeated every slot OTA until next transmission
            logger.debug('Transmitting ANT Broadcast PDU: ' + repr(packet))
            self._antstick_send_command(
                ANTStick_Data_Broadcast_Data(
                    channel_number = message.channel_number, 
                    pdu = bytes(message.pdu[-8:])
                ), no_response = True
            )
            self._send_whad_command_result(CommandResult.SUCCESS)