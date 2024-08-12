from usb.core import find, USBError, USBTimeoutError
from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.device.virtual import VirtualDevice
from whad.device.virtual.rfstorm.constants import RFStormId, RFStormCommands, \
    RFStormDataRate, RFStormEndPoints, RFStormInternalStates, RFStormDomains
from whad.hub.generic.cmdresult import CommandResult
from whad.hub.esb import Commands as EsbCommands
from whad.hub.phy import Commands as PhyCommands
from whad.esb.esbaddr import ESBAddress
from whad.hub.unifying import Commands as UniCommands
from whad import WhadCapability, WhadDomain
from whad.phy import Endianness
from threading import Thread, Lock
from time import sleep, time
from whad.helpers import swap_bits

# Helpers functions
def get_rfstorm(id=0,bus=None, address=None):
    '''
    Returns a RFStorm USB object based on index or bus and address.
    '''
    devices = list(find(idVendor=RFStormId.RFSTORM_ID_VENDOR, idProduct=RFStormId.RFSTORM_ID_PRODUCT,find_all=True))
    if bus is not None and address is not None:
        for device in devices:
            if device.bus == bus and device.address == address:
                return (devices.index(device), device)
        # No device found with the corresponding bus/address, return None
        return None
    else:
        try:
            return (id, devices[id])
        except IndexError:
            return None


class RFStormDevice(VirtualDevice):

    INTERFACE_NAME = "rfstorm"

    @classmethod
    def list(cls):
        '''
        Returns a list of available RFStorm devices.
        '''
        available_devices = []
        for rfstorm in find(idVendor=RFStormId.RFSTORM_ID_VENDOR, idProduct=RFStormId.RFSTORM_ID_PRODUCT,find_all=True):
            available_devices.append(RFStormDevice(bus=rfstorm.bus, address=rfstorm.address))
        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in format "<bus>-<address>").
        '''
        return str(self.__rfstorm.bus)+"-"+str(self.__rfstorm.address)


    def __init__(self, index=0, bus=None, address=None):
        """
        Create device connection
        """
        device = get_rfstorm(index,bus=bus,address=address)
        if device is None:
            raise WhadDeviceNotFound

        self.__opened = False
        self.__channel = 0
        self.__address = b"\xFF\xFF\xFF\xFF\xFF"
        self.__ptx = False
        self.__scanning = False
        self.__acking = False
        self.__ack_payload = None
        self.__check_ack = False

        self.__phy_sync = None
        self.__phy_rate = RFStormDataRate.RF_2MBPS
        self.__phy_size = 32
        self.__phy_endianness = Endianness.BIG

        self.__internal_state = RFStormInternalStates.NONE
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        self.__index, self.__rfstorm = device
        self.__last_packet_timestamp = 0

        self.__supported_frequency_range = (2400000000, 2500000000)
        self.__lock = Lock()
        super().__init__()

    def reset(self):
        self.__rfstorm.reset()

    def open(self):
        try:
            self.__rfstorm.set_configuration()
        except USBError as err:
            if err.errno == 13:
                raise WhadDeviceAccessDenied("rfstorm")
            else:
                raise WhadDeviceNotReady()

        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()

        self.__opened_stream = False
        self.__opened = True

        # Ask parent class to run a background I/O thread
        super().open()


    def _get_serial_number(self):
        return bytes.fromhex(
                                "{:02x}".format(self.__rfstorm.bus)*8 +
                                "{:02x}".format(self.__rfstorm.address)*8
        )

    def _get_manufacturer(self):
        return "Marc Newlin (BastilleResearch)".encode('utf-8')


    # Discovery related functions
    def _get_capabilities(self):
        capabilities = {
            WhadDomain.Esb : (
                                (WhadCapability.Sniff | WhadCapability.Inject | WhadCapability.SimulateRole | WhadCapability.NoRawData),
                                [
                                    EsbCommands.Sniff,
                                    EsbCommands.Send,
                                    EsbCommands.Start,
                                    EsbCommands.Stop,
                                    EsbCommands.SetNodeAddress,
                                    EsbCommands.PrimaryReceiverMode,
                                    EsbCommands.PrimaryTransmitterMode
                                ]
            ),
            WhadDomain.LogitechUnifying : (
                                (WhadCapability.Sniff | WhadCapability.Inject | WhadCapability.SimulateRole | WhadCapability.NoRawData),
                                [
                                    UniCommands.Sniff,
                                    UniCommands.Send,
                                    UniCommands.Start,
                                    UniCommands.Stop,
                                    UniCommands.SetNodeAddress,
                                    UniCommands.LogitechMouseMode,
                                    UniCommands.LogitechKeyboardMode,
                                    UniCommands.LogitechDongleMode
                                ]
            ),
            WhadDomain.Phy: (
                                (WhadCapability.Sniff | WhadCapability.Inject | WhadCapability.NoRawData),
                                [
                                    PhyCommands.SetGFSKModulation,
                                    PhyCommands.GetSupportedFrequencies,
                                    PhyCommands.SetFrequency,
                                    PhyCommands.SetDataRate,
                                    PhyCommands.SetEndianness,
                                    PhyCommands.SetPacketSize,
                                    PhyCommands.SetSyncWord,
                                    PhyCommands.Sniff,
                                    PhyCommands.Send,
                                    PhyCommands.Start,
                                    PhyCommands.Stop
                                ]
            ),

        }
        return capabilities

    def _get_firmware_version(self):
        return (1, 0, 0)

    def _get_url(self):
        return "https://github.com/BastilleResearch/nrf-research-firmware".encode('utf-8')


    def close(self):
        """
        Close current device.
        """
        # Ask parent class to stop I/O thread
        super().close()

        # Close underlying device.
        self.__opened = False

    def _rfstorm_send_command(self, command, data=b"", timeout=200, no_response=False):
        data = [command] + list(data)
        try:
            self.__lock.acquire()
            self.__rfstorm.write(RFStormEndPoints.RFSTORM_COMMAND_ENDPOINT, data, timeout=timeout)
        except USBTimeoutError:
            self.__lock.release()
            return False
        response = self._rfstorm_read_response()
        self.__lock.release()
        if not no_response:
            return response
        else:
            return True

    def _rfstorm_read_response(self, timeout=200):
        try:
            return bytes(self.__rfstorm.read(RFStormEndPoints.RFSTORM_RESPONSE_ENDPOINT, 64, timeout=timeout))
        except USBTimeoutError:
            return None

    def _rfstorm_check_success(self, data):
        return data is not None and len(data) > 0 and data[0] > 0

    def _rfstorm_read_packet(self):
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_RECV)

    def _rfstorm_promiscuous_mode(self, prefix=b""):
        data = bytes([len(prefix)]) + prefix
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_PROMISCUOUS, data, no_response=True)

    def _rfstorm_generic_promiscuous_mode(self, prefix=b"", rate=RFStormDataRate.RF_2MBPS, payload_length=32):
        data = bytes([len(prefix), rate, payload_length]) + prefix
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_PROMISCUOUS_GENERIC, data, no_response=True)

    def _rfstorm_sniffer_mode(self, address=b""):
        data = bytes([len(address)]) + address
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_SNIFF, data, no_response=True)

    def _rfstorm_tone_mode(self):
            return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TONE)

    def _rfstorm_transmit_payload(self, payload, timeout=4, retransmits=1):
        data = bytes([len(payload), timeout, retransmits]) + payload
        return self._rfstorm_check_success(
            self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TRANSMIT, data)
        )
    def _rfstorm_transmit_payload_generic(self, payload, address=b"\x33\x33\x33\x33\x33"):
        data = bytes([len(payload), len(address)]) + payload + address
        return self._rfstorm_check_success(
            self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TRANSMIT_GENERIC, data)
        )

    def _rfstorm_transmit_ack_payload(self, payload):
        data = bytes([len(payload)]) + payload
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TRANSMIT_ACK, data, no_response=True)

    def _rfstorm_set_channel(self, channel):
        if channel < 0 or channel > 125:
            return False

        data = bytes([channel])
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_SET_CHANNEL, data)

    def _rfstorm_get_channel(self, channel):
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_GET_CHANNEL)[0]

    def _rfstorm_enable_lna(self):
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_ENABLE_LNA)

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        if not self.__opened:
            raise WhadDeviceNotReady()
        if self.__opened_stream:
            if self.__domain == RFStormDomains.RFSTORM_PHY:
                try:
                    data = self._rfstorm_read_packet()
                except USBTimeoutError:
                    data = b""
                if data is not None and isinstance(data, bytes) and len(data) >= 1 and data != b"\xFF":
                    self.__last_packet_timestamp = time()
                    if len(data[:5]) >= 3:
                        if self.__phy_endianness == Endianness.LITTLE:
                            data = bytes([swap_bits(i) for i in data])
                        self._send_whad_pdu(data[5:], data[:5], int(self.__last_packet_timestamp))

            else:
                if self.__scanning:
                    if time() - self.__last_packet_timestamp > 1:
                        if self.__internal_state == RFStormInternalStates.PROMISCUOUS_SNIFFING:
                            self.__channel = (self.__channel + 1) % 100
                            self._rfstorm_set_channel(self.__channel)
                            sleep(0.05)
                        elif self.__internal_state == RFStormInternalStates.SNIFFING:
                            for i in range(0,100):
                                self._rfstorm_set_channel(i)
                                if self._rfstorm_transmit_payload(b"\x0f\x0f\x0f\x0f",1,1):
                                    self.__last_packet_timestamp = time()
                                    self.__channel = i
                                    self._send_whad_pdu(b"", address=self.__address)
                                    break

                if not self.__ptx:
                    try:
                        data = self._rfstorm_read_packet()
                    except USBTimeoutError:
                        data = b""

                    if data is not None and isinstance(data, bytes) and len(data) >= 1 and data != b"\xFF":
                        if self.__acking:
                            if self.__ack_payload is not None:
                                self._rfstorm_transmit_ack_payload(self.__ack_payload)
                                self.__ack_payload = None
                            else:
                                self._rfstorm_transmit_ack_payload(b"")
                        self.__last_packet_timestamp = time()
                        if self.__internal_state == RFStormInternalStates.PROMISCUOUS_SNIFFING:
                            if len(data[:5]) >= 3:
                                self._send_whad_pdu(data[5:], data[:5])
                        elif self.__internal_state == RFStormInternalStates.SNIFFING:
                            self._send_whad_pdu(data[1:], self.__address)
                else:
                    sleep(0.1)


    # Virtual device whad message builder
    def _send_whad_pdu(self, pdu, address, timestamp=None):

        if self.__domain == RFStormDomains.RFSTORM_RAW_ESB:
            self._send_whad_esb_pdu(pdu, address, timestamp)
        elif self.__domain == RFStormDomains.RFSTORM_UNIFYING:
            self._send_whad_unifying_pdu(pdu, address, timestamp)
        elif self.__domain == RFStormDomains.RFSTORM_PHY:
            self._send_whad_phy_pdu(address + pdu, timestamp)

    def _send_whad_esb_pdu(self, pdu, address, timestamp=None):
        msg = self.hub.esb.create_pdu_received(
            self.__channel,
            pdu,
            address=ESBAddress(address)
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        self._send_whad_message(msg)

    def _send_whad_unifying_pdu(self, pdu, address, timestamp=None):
        msg = self.hub.unifying.create_pdu_received(
            self.__channel,
            pdu,
            address=ESBAddress(address)
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp


        # Send message
        self._send_whad_message(msg)

    def _send_whad_phy_pdu(self, packet, timestamp=None):
        msg = self.hub.phy.create_packet_received(
            (self.__channel + 2400) * 1000000,
            packet
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        self._send_whad_message(msg)

    def _on_whad_phy_sync_word(self, message):
        if len(message.sync_word) > 0 and len(message.sync_word) < 5:
            self.__phy_sync = message.sync_word
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_get_supported_freq(self, message):
        ranges = (self.__supported_frequency_range[0], self.__supported_frequency_range[1])

        # Create a SupportedFreqRanges response message
        msg = self.hub.phy.create_supported_freq_ranges([ranges])

        # Send message
        self._send_whad_message(msg)

    def _on_whad_phy_set_freq(self, message):
        range_start, range_end = self.__supported_frequency_range[0], self.__supported_frequency_range[1]

        if message.frequency >= range_start and message.frequency <= range_end:
            self.__channel = int(message.frequency / 1000000) - 2400
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)


    def _on_whad_phy_datarate(self, message):
        rates = {
            250000 : RFStormDataRate.RF_250KBPS,
            1000000 : RFStormDataRate.RF_1MBPS,
            2000000 : RFStormDataRate.RF_2MBPS,
        }
        if message.rate in list(rates.keys()):
            self.__phy_rate = rates[message.rate]
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)


    def _on_whad_phy_packet_size(self, message):
        if message.packet_size >= 5 and message.packet_size <= 31:
            self.__phy_size = message.packet_size
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_endianness(self, message):
        if message.endianness in (Endianness.BIG, Endianness.LITTLE):
            self.__phy_endianness = message.endianness
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_mod_gfsk(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_phy_send(self, message):
        self._on_whad_send(message)

    def _on_whad_send(self, message):
        if self.__domain == RFStormDomains.RFSTORM_PHY:
            if self.__phy_endianness == Endianness.LITTLE:
                sync = bytes([swap_bits(i) for i in self.__phy_sync])[::-1]
                data =  bytes([swap_bits(i) for i in message.packet])
            else:
                sync = self.__phy_sync
                data = message.packet
            success = self._rfstorm_transmit_payload_generic(sync + data, address=b"")
            if success:
                self._send_whad_command_result(CommandResult.SUCCESS)
            else:
                self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

        else:
            channel = message.channel if message.channel != 0xFF else self.__channel
            pdu = message.pdu
            retransmission_count = message.retr_count
            if self.__acking:
                self.__ack_payload = pdu
            else:
                ack = self._rfstorm_transmit_payload(pdu, retransmits=retransmission_count)
                self._send_whad_command_result(CommandResult.SUCCESS)

                if self.__check_ack:
                    if ack:
                        self._send_whad_pdu(b"", address=self.__address)
                        self._send_whad_command_result(CommandResult.SUCCESS)
                    else:
                        self._send_whad_command_result(CommandResult.SUCCESS)

            self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_send(self, message):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        self._on_whad_send(message)

    def _on_whad_unifying_send(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_send(message)

    def _on_whad_set_node_addr(self, message):
        self.__address = message.address
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_set_node_addr(self, message):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        self._on_whad_set_node_addr(message)

    def _on_whad_unifying_set_node_addr(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_set_node_addr(message)

    def _on_whad_ptx(self, message):
        self.__internal_state = RFStormInternalStates.SNIFFING
        self.__acking = False
        self.__check_ack = True
        self.__ptx = True
        self.__channel = message.channel
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_ptx(self, message):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        self._on_whad_ptx(message)

    def _on_whad_unifying_mouse(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_ptx(message)

    def _on_whad_unifying_keyboard(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_ptx(message)

    def _on_whad_prx(self, message):
        self.__internal_state = RFStormInternalStates.SNIFFING
        self.__acking = True
        self.__check_ack = False
        self.__ptx = False
        self.__channel = message.channel
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_prx(self, message):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        self._on_whad_prx(message)

    def _on_whad_unifying_dongle(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_prx(message)

    def _on_whad_sniff(self, message):
        if self.__domain == RFStormDomains.RFSTORM_PHY:
            self.__internal_state = RFStormInternalStates.SNIFFING

            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            channel = message.channel
            show_acknowledgements = message.show_acks
            address = message.address
            self.__ptx = False
            self.__channel = channel

            self.__acking = False
            if address == b"\xFF\xFF\xFF\xFF\xFF":
                self.__internal_state = RFStormInternalStates.PROMISCUOUS_SNIFFING
            else:
                self.__internal_state = RFStormInternalStates.SNIFFING
                self.__address = address
            self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_sniff(self, message):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        self._on_whad_sniff(message)

    def _on_whad_unifying_sniff(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_sniff(message)

    def _on_whad_phy_sniff(self, message):
        self.__domain = RFStormDomains.RFSTORM_PHY
        self._on_whad_sniff(message)

    def _on_whad_stop(self, message):
        self.__opened_stream = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_stop(self, message):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        self._on_whad_stop(message)

    def _on_whad_unifying_stop(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_stop(message)

    def _on_whad_phy_stop(self, message):
        self.__domain = RFStormDomains.RFSTORM_PHY
        self._on_whad_stop(message)

    def _on_whad_start(self, message):
        self._rfstorm_enable_lna()
        if self.__domain == RFStormDomains.RFSTORM_PHY:
            if self.__phy_endianness == Endianness.LITTLE:
                sync = bytes([swap_bits(i) for i in self.__phy_sync])[::-1]
            else:
                sync = self.__phy_sync
            success = self._rfstorm_generic_promiscuous_mode(prefix=sync, rate=self.__phy_rate, payload_length=self.__phy_size)
            if success:
                self.__opened_stream = True
                self._send_whad_command_result(CommandResult.SUCCESS)
            else:
                self._send_whad_command_result(CommandResult.ERROR)

        else:
            if self.__channel == 0xFF:
                self.__scanning = True
                self.__channel = 0
            else:
                self.__scanning = False
            success = self._rfstorm_set_channel(self.__channel)
            if self.__internal_state == RFStormInternalStates.SNIFFING:
                success = success and self._rfstorm_sniffer_mode(self.__address[::-1])
            elif self.__internal_state == RFStormInternalStates.PROMISCUOUS_SNIFFING:
                success = success and self._rfstorm_promiscuous_mode()

            if success:
                self.__opened_stream = True
                self._send_whad_command_result(CommandResult.SUCCESS)
            else:
                self._send_whad_command_result(CommandResult.ERROR)

    def _on_whad_esb_start(self, message):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        self._on_whad_start(message)

    def _on_whad_unifying_start(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_start(message)

    def _on_whad_phy_start(self, message):
        self.__domain = RFStormDomains.RFSTORM_PHY
        self._on_whad_start(message)
