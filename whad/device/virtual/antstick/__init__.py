"""
ANT Stick adaptation layer for WHAD.
"""
import logging
from threading import  Lock
from time import sleep, time
from struct import pack

from usb.util import find_descriptor, endpoint_direction, ENDPOINT_IN, ENDPOINT_OUT
from usb.core import find, USBError, USBTimeoutError
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device import VirtualDevice

from whad.hub.ant import Commands
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
    ANTStick_Data_Broadcast_Data

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
        self.__antstick_capabilities = None
        self.__opened = False
        self.__opened_stream = False
        self.__lock = Lock()

        self.__sync = generate_sync_from_network_key(ANT_PLUS_NETWORK_KEY)
        self.__frequency = 2457
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


        serial_number = self._get_serial_number()
        if serial_number is not None:
            self._dev_id = self._get_ant_version()[:12] + pack("<I", serial_number)
            self._dev_id = b"\x00" * (16 - len(self._dev_id)) + self._dev_id
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self.__opened = True
        # Ask parent class to run a background I/O thread
        super().open()

    def read(self):
        """Read incoming data
        """

        if not self.__opened:
            raise WhadDeviceNotReady()

        if self.__opened_stream:
            try:
                data = self._antstick_read_message()
                if data is not None and ANTStick_Data_Broadcast_Data in data:
                    pkt = bytes(
                            ANT_Hdr(
                                preamble = self.__sync, 
                                device_number = data.device_number, 
                                device_type = data.device_type,
                                transmission_type=data.transmission_type, 
                                broadcast = 0, 
                                ack = False, 
                                end = False, 
                                count = 0, 
                                slot = False, 
                                unknown = 0
                        ) / data.pdu
                    )
                    pkt = ANT_Hdr(pkt)
                    print(repr(pkt))
                    self._send_whad_ant_pdu(
                        pdu=bytes(pkt)
                    )
                else:
                    sleep(0.5)
                    print("waiting...")
            except USBTimeoutError:
                data = b""
                # self._send_whad_pdu(data[5:], data[:5], int(self.__last_packet_timestamp))
        else:
            sleep(0.1)


    def _send_whad_ant_pdu(self, pdu, channel_number=0, timestamp=None):
        msg = self.hub.ant.create_pdu_received(
            pdu=pdu, 
            channel_number=channel_number
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        self._send_whad_message(msg)


    def _get_manufacturer(self):
        return self.__antstick.manufacturer.encode('utf-8').replace(b"\x00", b"")

    def _get_firmware_version(self):
        return (1, 0, 0)

    def _get_url(self):
        return "https://thisisant.com".encode('utf-8')



    def _get_capabilities(self):
        response = self._antstick_send_command(ANTStick_Command_Request_Message(message_id_req=0x54))
        # Provide ant stick capabilities
        if ANTStick_Requested_Message_Capabilities in response:
            self.__antstick_capabilities = response
            
            capabilities = Capability.NoRawData # no support of raw PDU here
            commands = []

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
                        Commands.SetFrequency, 
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
                    Commands.SetFrequency, 
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
                    Commands.SetFrequency, 
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
                    Commands.SetFrequency, 
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
                    Commands.SetFrequency, 
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
        response = self._antstick_send_command(ANTStick_Command_Request_Message(message_id_req=0x61))
        if ANTStick_Requested_Message_Serial_Number in response:
            return response.serial_number
        return None        


    def _get_ant_version(self):
        response = self._antstick_send_command(ANTStick_Command_Request_Message(message_id_req=0x3E))
        if ANTStick_Requested_Message_ANT_Version in response:
            return response.version
        return None


    def _set_network_key(self, network_key, network_number=0):
        if not is_valid_network_key(network_key):
            return False

        response = self._antstick_send_command(ANTStick_Command_Set_Network_Key(
            network_number=network_number, 
            network_key=network_key[::-1]
            )
        )

        self.__sync = generate_sync_from_network_key(network_key)
        return True


    def _assign_channel(self, channel_number=0, channel_type=0, network_number=0, background_scanning = False):
        response = self._antstick_send_command(ANTStick_Command_Assign_Channel(
                channel_number=channel_number, 
                network_number=network_number, 
                channel_type=channel_type
            ) / 
            ANTStick_Extended_Assignment_Extension(
                extended_assignment = (0x01 if background_scanning else 0x00)
            )
        )
        return True

    def _set_channel_id(self, channel_number=0, device_number=0, device_type=0, transmission_type=0):
        response = self._antstick_send_command(ANTStick_Command_Set_Channel_ID(
                channel_number=channel_number, 
                device_number=device_number, 
                device_type=device_type, 
                transmission_type=transmission_type
            )
        )
        return True


    def _set_channel_rf_frequency(self, channel_number=0, frequency=2457):
        self.__frequency = frequency
        response = self._antstick_send_command(ANTStick_Command_Set_Channel_RF_Frequency(
                channel_number=channel_number, 
                channel_rf_frequency=frequency - 2400
            )
        )
        return True

    def _open_rx_scan_mode(self, sync_channel_packets_only=False):
        response = self._antstick_send_command(ANTStick_Command_Open_RX_Scan_Mode(
                sync_channel_packets_only=(1 if sync_channel_packets_only else 0)
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
        response = self._antstick_send_command(ANTStick_Command_Open_Channel(
                channel_number=channel_number
            )
        )
        return True


    def _close_channel(self, channel_number=0):
        response = self._antstick_send_command(ANTStick_Command_Close_Channel(
                channel_number=channel_number
            )
        )
        return True

    def _antstick_send_command(self, command, timeout=200, no_response=False):
        data = bytes(ANTStick_Message() / command)
        print(">", bytes(data))
        ANTStick_Message(data).show()
            
        with self.__lock:
            try:
                self.__antstick.write(self.__out_endpoint,
                                     data, timeout=timeout)
            except USBTimeoutError:
                return None

            response = self._antstick_read_message()
            if ANTStick_Channel_Response_Or_Event in response and response.message_code == 40: # invalid message 
                return None

            return response

    def _antstick_read_message(self, timeout=200):
        try:
            msg = bytes(self.__antstick.read(self.__in_endpoint,
                                             64, timeout=timeout))
            print("<", bytes(msg), bytes(msg).hex())
            #ANTStick_Message(msg).show()

            return ANTStick_Message(msg)
        except USBTimeoutError:
            return None


    # WHAD command handlers
    def _on_whad_ant_sniff(self, message):
        print("ANT sniff cmd", message)
        self._close_channel(channel_number=0)
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
        self._set_channel_rf_frequency(
            channel_number = 0, 
            frequency = 2457
        )
        self._configure_extension_mode(enable=True)
        self._open_rx_scan_mode()
        # self._open_channel(channel_number=0)
        self.__opened_stream = True
        self._send_whad_command_result(CommandResult.SUCCESS)

if __name__ == '__main__':
    print(ANTStickDevice.list())