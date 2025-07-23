"""
ANT Stick adaptation layer for WHAD.
"""
import logging
from threading import  Lock
from time import sleep, time
from queue import Queue
from struct import pack

from usb.util import find_descriptor, endpoint_direction, ENDPOINT_IN, ENDPOINT_OUT
from usb.core import find, USBError, USBTimeoutError
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device import VirtualDevice

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

from whad.device.virtual.antstick.constants import AntStickIds
from whad.device.virtual.antstick.channel import ChannelStatus, ChannelType, Channel
from whad.device.virtual.antstick.network import Network

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
        self.__antstick_capabilities = None
        self.__opened = False
        self.__opened_stream = False
        self.__lock = Lock()

        self.__in_buffer = b""
        self.__event_queue = Queue()
        self.__pdu_queue = Queue()
        self.__response_queue = Queue()
        self.__ack_queue = Queue()

        self.__last_timestamp = time() * 1000
        self.__sync = generate_sync_from_network_key(ANT_PLUS_NETWORK_KEY)
        self.__rf_channel = 57
        self.__number_of_channels = 0
        self.__number_of_networks = 0
        self.__channels = {}
        self.__networks = {}
        self.__reload_channel = None
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
        self._antstick_reset()


        # Ask parent class to run a background I/O thread
        serial_number = self._get_serial_number()
        if serial_number is not None:
            self._dev_id = self._get_ant_version()[:12] + pack("<I", serial_number)
            self._dev_id = b"\x00" * (16 - len(self._dev_id)) + self._dev_id
        
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self._initialize_channels()
        self._initialize_networks()
        self._configure_extension_mode(enable=True)
        self._configure_lib(rssi=True, channel_id=True, timestamp=True)
        self.pending_burst_packets = []
        self.__opened = True
        super().open()

       

    def close(self):
        """
        Close current device.
        """
        # Ask parent class to stop I/O thread
        super().close()

        # Close underlying device.
        self.__opened = False
        
    def _initialize_channels(self):
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
        for network_number in range(self.__number_of_networks):
            self.__networks[network_number] = Network(
                network_key = None
            )


    def _reload_channel(self, channel_number):
        self.__channels[channel_number].opened = False
        self._set_channel_id(
            channel_number = channel_number, 
            device_number = self.__channels[channel_number].device_number, 
            device_type = self.__channels[channel_number].device_type, 
            transmission_type = self.__channels[channel_number].transmission_type
        )
        self._set_channel_rf_channel(
            channel_number = channel_number, 
            rf_channel = self.__channels[channel_number].rf_channel, 
        )

        self._set_channel_period(
            channel_number = channel_number, 
            period = self.__channels[channel_number].period, 
        )
        self._open_channel(channel_number)


    def read(self):
        """Read incoming data
        """

        if not self.__opened:
            raise WhadDeviceNotReady()
        else:
            if self.__reload_channel is not None:
                self.__opened = False
                self._reload_channel(self.__reload_channel)
                self.__reload_channel = None
                self.__opened = True
            self._antstick_read_message()

            if self.__opened_stream:
                while not self.__event_queue.empty():
                    event = ANTStick_Message(self.__event_queue.get())
                    if event.message_code in (3, 5,6,10):
                        self._send_whad_ant_channel_event(event.channel_number, event.message_code)
                    #print("Event:", repr(event))
                    if event.message_code == 7 and self.__channels[event.channel_number].opened: # event_channel_closed
                        self.__reload_channel = event.channel_number
                    elif event.message_code in (5,6) + (4,10,17):
                        self.__ack_queue.put(bytes(event))
                    # acked: event_transfer_tx_completed or event_transfer_tx_failed  
                while not self.__pdu_queue.empty():
                    data = ANTStick_Message(self.__pdu_queue.get())
                    #print(repr(data))
                    if data is not None:# and ANTStick_Data_Broadcast_Data in data:
                        cn = data.channel_number & 0b11111
                        pkt = bytes(
                                ANT_Hdr(
                                    preamble = self.__sync, 
                                    device_number = data.device_number if ANTStick_Data_Extension in data else self.__channels[cn].device_number, 
                                    device_type = data.device_type if ANTStick_Data_Extension in data else self.__channels[cn].device_type,
                                    transmission_type=data.transmission_type if ANTStick_Data_Extension in data else self.__channels[cn].transmission_type, 
                                    broadcast = (0 if ANTStick_Data_Broadcast_Data in data else 1), 
                                    ack = False, 
                                    end = False, 
                                    count = 0, 
                                    slot = False, 
                                    unknown = 0
                            ) / data.pdu
                        )
                        pkt = ANT_Hdr(pkt)
                        rssi = None
                        if ANTStick_RSSI_Data_Extension in data:
                            rssi = data.rssi
                        if ANTStick_Timestamp_Data_Extension in data:
                            timestamp = data.timestamp
                        else:
                            now = time() * 1000
                            timestamp = now - self.__last_timestamp
                            
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
        msg = self.hub.ant.create_pdu_received(
            pdu=pdu, 
            channel_number=channel_number, 
            rf_channel=rf_channel
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp

        if rssi is not None:
            msg.rssi = rssi
        # Send message
        self._send_whad_message(msg)


    def _get_manufacturer(self):
        return self.__antstick.manufacturer.encode('utf-8').replace(b"\x00", b"")

    def _get_firmware_version(self):
        return (1, 0, 0)

    def _get_url(self):
        return "https://thisisant.com".encode('utf-8')



    def _get_capabilities(self):
        response = self._antstick_send_command(
            ANTStick_Command_Request_Message(message_id_req=0x54), 
            rsp_filter = lambda response: ANTStick_Requested_Message_Capabilities in response
        )
        # Provide ant stick capabilities
        if ANTStick_Requested_Message_Capabilities in response:
            self.__antstick_capabilities = response
            self.__number_of_channels = response.max_channels
            self.__number_of_networks = response.max_networks
            
            capabilities = Capability.NoRawData # no support of raw PDU here
            commands = [
                Commands.ListChannels, 
                Commands.ListNetworks,
            ]

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

            return {
                Domain.ANT : (
                                capabilities, 
                                list(set(commands))
                )
            }       

        return None        

    def _get_serial_number(self):
        response = self._antstick_send_command(
            ANTStick_Command_Request_Message(message_id_req=0x61), 
            rsp_filter = lambda response: ANTStick_Requested_Message_Serial_Number in response
        )

        if ANTStick_Requested_Message_Serial_Number in response:
            return response.serial_number
        return None        


    def _get_ant_version(self):
        response = self._antstick_send_command(
            ANTStick_Command_Request_Message(message_id_req=0x3E),
            rsp_filter= lambda response:ANTStick_Requested_Message_ANT_Version in response
        )
        if ANTStick_Requested_Message_ANT_Version in response:
            return response.version
        return None


    def _set_network_key(self, network_key, network_number=0):
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


        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        response = self._antstick_send_command(ANTStick_Command_Assign_Channel(
                channel_number=channel_number, 
                network_number=network_number, 
                channel_type=channel_type
            ) / 
            ANTStick_Extended_Assignment_Extension(
                extended_assignment = 0x20 # | (0x01 if background_scanning else 0x00)
            ) # for some reason transmission doesn't work without async mode so let's hardcode it
        )
        self.__channels[channel_number].status = ChannelStatus.ASSIGNED
        self.__channels[channel_number].assigned_network = network_number 
        self.__channels[channel_number].type = ChannelType(channel_type)
        return True

    def _set_channel_id(self, channel_number=0, device_number=None, device_type=None, transmission_type=None, force=False):

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

            
        response = self._antstick_send_command(ANTStick_Command_Set_Channel_ID(
                channel_number=channel_number, 
                device_number=device_number, 
                device_type=device_type, 
                transmission_type=transmission_type
            )
        )
        self.__channels[channel_number].device_number = device_number
        self.__channels[channel_number].device_type = device_type
        self.__channels[channel_number].transmission_type = transmission_type

        return True


    def _set_channel_rf_channel(self, channel_number=0, rf_channel=57):

        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        response = self._antstick_send_command(ANTStick_Command_Set_Channel_RF_Frequency(
                channel_number=channel_number, 
                channel_rf_frequency=rf_channel
            )
        )
        self.__rf_channel = rf_channel
        self.__channels[channel_number].rf_channel = rf_channel

        return True



    def _set_channel_period(self, channel_number=0, period = 0):

        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        response = self._antstick_send_command(ANTStick_Command_Set_Channel_Period(
                channel_number=channel_number, 
                period=period
            )
        )
        self.__channels[channel_number].period = period

        return True

    def _open_rx_scan_mode(self, sync_channel_packets_only=False):
        if 0 not in self.__channels:
            return False

        if self.__channels[0].opened:
            self._close_channel(0)

        response = self._antstick_send_command(ANTStick_Command_Open_RX_Scan_Mode(
                sync_channel_packets_only=(1 if sync_channel_packets_only else 0)
            )
        )
        self.__channels[0].opened = True
        return True


    def _configure_lib(self, rssi=False, channel_id=False, timestamp=False):
        response = self._antstick_send_command(ANTStick_Command_Lib_Config(
                channel_id_output_enabled=(1 if channel_id else 0), 
                rssi_output_enabled=(1 if rssi else 0), 
                rx_timestamp_enabled=(1 if timestamp else 0)
            )
        )
        return True


    def _configure_extension_mode(self, enable=True):
        response = self._antstick_send_command(ANTStick_Command_Enable_Extended_Messages(
                enable=(1 if enable else 0)
            )
        )
        return True

    def _open_channel(self, channel_number=0):
        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            return True

            # Configure an infinite search timeout, because who wants a 
            # channel to be arbitrarily closed after a few seconds ? WTF Garmin !
            self._configure_search_timeout(channel_number, 0xFF)
            self._configure_low_priority_search_timeout(channel_number, 0)

        response = self._antstick_send_command(ANTStick_Command_Open_Channel(
                channel_number=channel_number
            )
        )
        self.__channels[channel_number].opened = True
        return True

    def _configure_search_timeout(self, channel_number=0, timeout=0):
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
        if channel_number not in self.__channels:
            return False

        if self.__channels[channel_number].opened:
            self._close_channel(channel_number)

        response = self._antstick_send_command(ANTStick_Command_Low_Priority_Search_Timeout(
                channel_number=channel_number, 
                timeout=timeout
            )
        )
        return True
    def _close_channel(self, channel_number=0):
        if channel_number not in self.__channels:
            return False

        if not self.__channels[channel_number].opened:
            return True

        response = self._antstick_send_command(ANTStick_Command_Close_Channel(
                channel_number=channel_number
            )
        )
        self.__channels[channel_number].opened = False
        return True

    def _antstick_reset(self):
        self._antstick_send_command(ANTStick_Command_Reset(), force_reset=True)
        

    def _antstick_send_command(self, command, rsp_filter=lambda p:True, force_reset=False, timeout=200, no_response=False):
        data = bytes(ANTStick_Message() / command)
        #print(">", bytes(data))
        #print(repr(ANTStick_Message(data)))

        while True:
            try:
                    self.__lock.acquire()
                    self.__antstick.write(self.__out_endpoint,
                                        data, timeout=timeout)
                    self.__lock.release()

                    break
            except (USBTimeoutError, USBError):
                self.__lock.release()

                pass
        if no_response:
            return None

        response = None
        while response is None:
            if not self.__opened:
                self._antstick_read_message()
                #print(self.__in_buffer)
            response = self._antstick_read_response(rsp_filter=rsp_filter)
            if response is None and force_reset:
                self.__antstick.reset()
                self.__antstick.write(self.__out_endpoint, data, timeout=timeout)
                self._antstick_read_message()

        if ANTStick_Channel_Response_Or_Event in response and response.message_code == 40: # invalid message 
            return None

        return response

    def _antstick_read_response(self, rsp_filter=lambda p : True, timeout=200):
        if self.__response_queue.empty():
            return None
        else:
            msg = self.__response_queue.get()
            while not rsp_filter(ANTStick_Message(msg)):
                self.__response_queue.put(msg)
                msg = self.__response_queue.get()

            #print("<", msg.hex())
            #print(repr(ANTStick_Message(msg)))
            return ANTStick_Message(msg)

    def _antstick_read_message(self, timeout=200):
        try:
                self.__lock.acquire()
                msg = bytes(self.__antstick.read(self.__in_endpoint,
                                                64, timeout=timeout))
                self.__lock.release()            
                self.__in_buffer += msg

        except (USBTimeoutError, USBError) as e:
            self.__lock.release()

        while True:
            while len(self.__in_buffer) > 0 and self.__in_buffer[0] != ANTSTICK_SYNC:
                self.__in_buffer = self.__in_buffer[1:]
                
            if len(self.__in_buffer) <= 4:
                break

            if len(self.__in_buffer) < 2 + self.__in_buffer[1]:
                break

            msg = self.__in_buffer[:len(self.__in_buffer) + 3]
            self.__in_buffer = self.__in_buffer[len(msg):]

            if msg[2] in (0x4E, 0x4F, 0x50, 0x72):
                self.__pdu_queue.put(msg)
            elif msg[2] == 0x40 and ANTStick_Message(msg).message_code >= 1 and ANTStick_Message(msg).message_code <= 17: # event range
                self.__event_queue.put(msg)
            else:
                #print("Adding response: ", repr(ANTStick_Message(msg))) 
                self.__response_queue.put(msg)
    


    # WHAD command handlers
    def _on_whad_ant_sniff(self, message):
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
            rf_channel = 57
        )
        self._open_rx_scan_mode()
        # self._open_channel(channel_number=0)
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_start(self, message):
        self.__opened_stream = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_stop(self, message):
        self.__opened_stream = False
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_list_networks(self, message):
        self._send_whad_ant_available_networks(self.__number_of_networks)
        
    def _send_whad_ant_available_networks(self, number_of_networks):
        # create available networks notification
        msg = self.hub.ant.create_available_networks(
            number_of_networks=number_of_networks
        )
        # Send message
        self._send_whad_message(msg)


    def _on_whad_ant_list_channels(self, message):
        self._send_whad_ant_available_channels(self.__number_of_channels)

    def _send_whad_ant_available_channels(self, number_of_channels):
        # create available channels notification
        msg = self.hub.ant.create_available_channels(
            number_of_channels=number_of_channels
        )
        # Send message
        self._send_whad_message(msg)


    def _send_whad_ant_channel_event(self, channel_number, event):
        # create available channels notification
        msg = self.hub.ant.create_channel_event(
            channel_number, 
            event
        )
        # Send message
        self._send_whad_message(msg)


    def _on_whad_ant_open_channel(self, message):
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)
        
        if not self._open_channel(message.channel_number):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_close_channel(self, message):
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)
        
        if not self._close_channel(message.channel_number):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)
        

    def _on_whad_ant_assign_channel(self, message):
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
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if not self._unassign_channel(
            channel_number = message.channel_number
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_set_network_key(self, message):
        if message.network_number not in self.__networks:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if len(message.network_key) != 8 and not is_valid_network_key(message.network_key):
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if self._set_network_key(
            network_number = message.network_number, 
            network_key = message.network_key
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_set_rf_channel(self, message):
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.rf_channel < 0 or message.rf_channel > 125:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if self._set_channel_rf_channel(
            channel_number = message.channel_number, 
            rf_channel = message.rf_channel
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_set_device_number(self, message):
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.device_number < 0 or message.device_number > 0xFFFF:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if self._set_channel_id(
            channel_number = message.channel_number, 
            device_number = message.device_number
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_set_device_type(self, message):
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.device_type < 0 or message.device_type > 0xFF:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if self._set_channel_id(
            channel_number = message.channel_number, 
            device_type = message.device_type
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_ant_set_transmission_type(self, message):
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.transmission_type < 0 or message.transmission_type > 0xFF:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if self._set_channel_id(
            channel_number = message.channel_number, 
            transmission_type = message.transmission_type
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)



    def _on_whad_ant_set_channel_period(self, message):
        if message.channel_number not in self.__channels:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if message.channel_period < 0 or message.channel_period > 0xFFFF:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        if self._set_channel_period(
            channel_number = message.channel_number, 
            period = message.channel_period
        ):
            self._send_whad_command_result(CommandResult.ERROR)

        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ant_send(self, message):
        packet = ANT_Hdr(message.pdu)
        #print("transmitting: ", repr(packet))
        if packet.broadcast == 1:
            if packet.end == 0:
                self.pending_burst_packets.append(message)
                self._send_whad_command_result(CommandResult.SUCCESS)

            else:
                if len(self.pending_burst_packets) > 0:
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
                        #print(">>>>", packet_data)
                        self._antstick_send_command(
                            ANTStick_Data_Burst_Data(
                                channel_number = channel_seq, 
                                pdu = packet_data
                            ), no_response = True
                        )
                    self.pending_burst_packets = []            
            
                    
                    while self.__ack_queue.empty():
                        sleep(0.001)
                        ack_event = ANTStick_Message(self.__ack_queue.get())
                        if ack_event.message_code == 6:
                            self._send_whad_command_result(CommandResult.ERROR)
                            return
                        elif ack_event.message_code == 5:
                            self._send_whad_command_result(CommandResult.SUCCESS)
                            return
                        else:
                            pass
                else:        
                    self._antstick_send_command(
                        ANTStick_Data_Acknowledged_Data(
                            channel_number = message.channel_number, 
                            pdu = bytes(message.pdu[-8:])
                        ), no_response = True
                    )
                    
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
            self._antstick_send_command(
                ANTStick_Data_Broadcast_Data(
                    channel_number = message.channel_number, 
                    pdu = bytes(message.pdu[-8:])
                ), no_response = True
            )
            self._send_whad_command_result(CommandResult.SUCCESS)
            


if __name__ == '__main__':
    print(ANTStickDevice.list())