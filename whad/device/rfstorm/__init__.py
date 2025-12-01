"""
RFStorm adaptation layer for WHAD.
"""
import logging
from re import I
from threading import  Lock
from time import sleep, time
from typing import Type, Optional

from usb.core import find, USBError, USBTimeoutError

from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied
from whad.hub.generic.cmdresult import ParameterError, Success, Error
from whad.hub.message import HubMessage
from whad.hub.esb import (
    Commands as EsbCommands,
    SendPdu as EsbSend, SetNodeAddress as EsbSetNodeAddress,
    EsbStart, EsbStop, SniffMode as EsbSniffMode,
    PtxMode as EsbPtxMode, PrxMode as EsbPrxMode,
    PduReceived as EsbPduReceived,
)
from whad.hub.phy import (
    Commands as PhyCommands,
    Endianness, Start as PhyStart, Stop as PhyStop, SetSyncWord,
    GetSupportedFreqs, SetFreq, SetDatarate, SetSyncWord,
    SetEndianness, SetPacketSize, SetGfskMod,
    SendPacket, SniffMode as PhySniffMode,
    PacketReceived as PhyPacketReceived
)
from whad.esb.esbaddr import ESBAddress
from whad.hub.unifying import(
    Commands as UniCommands,
    SendPdu as UnifyingSend, SetNodeAddress as UnifyingSetNodeAddress,
    UnifyingStart, UnifyingStop, SniffMode as UnifyingSniffMode,
    MouseMode as UnifyingMouse, KeyboardMode as UnifyingKeyboard,
    DongleMode as UnifyingDongle,
    PduReceived as UnifyingPduReceived
)
from whad.hub.discovery import Capability, Domain
from whad.phy import Endianness
from whad.helpers import swap_bits

from ..device import VirtualDevice
from .constants import RFStormId, RFStormCommands, \
    RFStormDataRate, RFStormEndPoints, RFStormInternalStates, RFStormDomains

logger = logging.getLogger(__name__)

# Helpers functions
def get_rfstorm(index=0,bus=None, address=None):
    '''
    Returns a RFStorm USB object based on index or bus and address.
    '''
    devices = list(find(idVendor=RFStormId.RFSTORM_ID_VENDOR,
                        idProduct=RFStormId.RFSTORM_ID_PRODUCT,find_all=True))
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


class RfStorm(VirtualDevice):
    """RFStorm virtual device implementation.
    """

    INTERFACE_NAME = "rfstorm"

    @classmethod
    def list(cls):
        '''
        Returns a list of available RFStorm devices.
        '''
        available_devices = []
        try:
            for rfstorm in find(idVendor=RFStormId.RFSTORM_ID_VENDOR,
                                idProduct=RFStormId.RFSTORM_ID_PRODUCT,find_all=True):
                available_devices.append(RfStorm(bus=rfstorm.bus, address=rfstorm.address))
        except ValueError:
            logger.warning("Cannot access RFStorm, root privileges may be required.")

        return available_devices

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in
        format "<bus>-<address>").
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
        self.__opened_stream = False
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
        _, self.__rfstorm = device
        self.__last_packet_timestamp = 0

        self.__supported_frequency_range = (2400000000, 2500000000)
        self.__lock = Lock()
        super().__init__()

    def reset(self):
        self.__rfstorm.reset()

    def open(self):
        try:
            logger.debug("[rfstorm] setting up hardware interface ...")
            self.__rfstorm.set_configuration()
        except USBError as err:
            if err.errno == 13:
                raise WhadDeviceAccessDenied("rfstorm") from err
            raise WhadDeviceNotReady() from err

        self.dev_id = self.__get_serial_number()
        self.author = self.__get_manufacturer()
        self.url = self.__get_url()
        self.version = self.__get_firmware_version()
        self.capabilities = self.__get_capabilities()

        self.__opened_stream = False
        self.__opened = True

        # Ask parent class to run a background I/O thread
        super().open()


    def __get_serial_number(self):
        return bytes.fromhex(
            f"{self.__rfstorm.bus:02x}"*8 +
            f"{self.__rfstorm.address:02x}"*8
        )

    def __get_manufacturer(self):
        return "Marc Newlin (BastilleResearch)"


    # Discovery related functions
    def __get_capabilities(self):
        capabilities = {
            Domain.Esb : (
                (Capability.Sniff | Capability.Inject | Capability.SimulateRole \
                    | Capability.NoRawData),
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
            Domain.LogitechUnifying : (
                (Capability.Sniff | Capability.Inject | Capability.SimulateRole \
                 | Capability.NoRawData),
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
            Domain.Phy: (
                (Capability.Sniff | Capability.Inject | Capability.NoRawData),
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

    def __get_firmware_version(self):
        return (1, 0, 0)

    def __get_url(self):
        return "https://github.com/BastilleResearch/nrf-research-firmware"


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
        with self.__lock:
            try:
                self.__rfstorm.write(RFStormEndPoints.RFSTORM_COMMAND_ENDPOINT,
                                     data, timeout=timeout)
            except USBTimeoutError:
                return False
            response = self._rfstorm_read_response()

        # If we have a response, return it
        if not no_response:
            return response

        # Success
        return True

    def _rfstorm_read_response(self, timeout=200):
        try:
            return bytes(self.__rfstorm.read(RFStormEndPoints.RFSTORM_RESPONSE_ENDPOINT,
                                             64, timeout=timeout))
        except USBTimeoutError:
            return None

    def _rfstorm_check_success(self, data):
        return data is not None and len(data) > 0 and data[0] > 0

    def _rfstorm_read_packet(self):
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_RECV)

    def _rfstorm_promiscuous_mode(self, prefix=b""):
        data = bytes([len(prefix)]) + prefix
        logger.debug("[rfstorm] enabling generic promisucuous mode")
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_PROMISCUOUS,
                                          data, no_response=True)

    def _rfstorm_generic_promiscuous_mode(self, prefix=b"", rate=RFStormDataRate.RF_2MBPS,
                                          payload_length=32):
        logger.debug("[rfstorm] enabling generic promisucuous mode")
        data = bytes([len(prefix), rate, payload_length]) + prefix
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_PROMISCUOUS_GENERIC,
                                          data, no_response=True)

    def _rfstorm_sniffer_mode(self, address=b""):
        data = bytes([len(address)]) + address
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_SNIFF, data,
                                          no_response=True)

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
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_TRANSMIT_ACK,
                                          data, no_response=True)

    def _rfstorm_set_channel(self, channel: int):
        if channel < 0 or channel > 125:
            logging.debug("[rfstorm] Cannot configure channel, invalid value (%d)", channel)
            return False

        logger.debug("[rfstorm] Configuring channel (%d)", channel)
        data = bytes([channel])
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_SET_CHANNEL, data)

    def _rfstorm_get_channel(self, channel):
        """Query hardware and retrieve configured channel."""
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_GET_CHANNEL)[0]

    def _rfstorm_enable_lna(self):
        """Enable hardware low-noise amplifier, if available."""
        return self._rfstorm_send_command(RFStormCommands.RFSTORM_CMD_ENABLE_LNA)

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        """Read incoming data
        """
        if not self.__opened:
            raise WhadDeviceNotReady()
        if self.__opened_stream:
            if self.__domain == RFStormDomains.RFSTORM_PHY:
                try:
                    data = self._rfstorm_read_packet()
                    logger.debug("[rfstorm:phy] Received packet: %s", data.hex())
                except USBTimeoutError:
                    data = b""
                if data is not None and isinstance(data, bytes) and \
                        len(data) >= 1 and data != b"\xFF":
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
                            logger.debug("[rfstorm:esb|uni] hopping on channel %d", self.__channel)
                            self._rfstorm_set_channel(self.__channel)
                            sleep(0.05)
                        elif self.__internal_state == RFStormInternalStates.SNIFFING:
                            for i in range(0,100):
                                logger.debug("[rfstorm] hopping on channel %d", self.__channel)
                                self._rfstorm_set_channel(i)
                                if self._rfstorm_transmit_payload(b"\x0f\x0f\x0f\x0f",1,1):
                                    logger.debug("[rfstorm] got a ping response")
                                    self.__last_packet_timestamp = time()
                                    self.__channel = i
                                    self._send_whad_pdu(b"", address=self.__address)
                                    break

                if not self.__ptx:
                    try:
                        data = self._rfstorm_read_packet()
                        logger.debug("[rfstorm|rx] Received packet: %s", data.hex())
                    except USBTimeoutError:
                        data = b""

                    if data is not None and isinstance(data, bytes) and \
                            len(data) >= 1 and data != b"\xFF":
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
    def __build_whad_pdu(self, pdu: bytes, address: bytes, timestamp: Optional[int] = None) -> Type[HubMessage]:
        """Build a PDU message for the selected domain.

        :param pdu: PDU data
        :type  pdu: bytes
        :param address: Destination address
        :type  address: bytes
        :param timestamp: Timestamp
        :type  timestamp: int
        """
        if self.__domain == RFStormDomains.RFSTORM_RAW_ESB:
            message = self.__build_whad_esb_pdu(pdu, address, timestamp)
        elif self.__domain == RFStormDomains.RFSTORM_UNIFYING:
            message = self.__build_whad_unifying_pdu(pdu, address, timestamp)
        elif self.__domain == RFStormDomains.RFSTORM_PHY:
            message = self.__build_whad_phy_pdu(address + pdu, timestamp)
        else:
            message = None
        return message

    def __build_whad_esb_pdu(self, pdu, address, timestamp=None) -> EsbPduReceived:
        msg = self.hub.esb.create_pdu_received(
            self.__channel,
            pdu,
            address=ESBAddress(address)
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        return msg

    def __build_whad_unifying_pdu(self, pdu, address, timestamp=None) -> UnifyingPduReceived:
        msg = self.hub.unifying.create_pdu_received(
            self.__channel,
            pdu,
            address=ESBAddress(address)
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        return msg

    def __build_whad_phy_pdu(self, packet, timestamp=None) -> PhyPacketReceived:
        msg = self.hub.phy.create_packet_received(
            (self.__channel + 2400) * 1000000,
            packet
        )

        # Set timestamp if provided
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        return msg

    ##
    # WHAD message handlers (from connector)
    ##

    # PHY Domain

    @VirtualDevice.route(SetSyncWord)
    def on_phy_sync_word(self, message: SetSyncWord):
        if len(message.sync_word) > 0 and len(message.sync_word) < 5:
            self.__phy_sync = message.sync_word
            return Success()
        return ParameterError()

    @VirtualDevice.route(GetSupportedFreqs)
    def on_phy_get_supported_freq(self, message):
        ranges = (self.__supported_frequency_range[0], self.__supported_frequency_range[1])

        # Create a SupportedFreqRanges response message
        return self.hub.phy.create_supported_freq_ranges([ranges])

    @VirtualDevice.route(SetFreq)
    def on_phy_set_freq(self, message: SetFreq):
        range_start, range_end = self.__supported_frequency_range[0:2]

        if message.frequency >= range_start and message.frequency <= range_end:
            self.__channel = int(message.frequency / 1000000) - 2400
            return Success()
        return ParameterError()

    @VirtualDevice.route(SetDatarate)
    def on_phy_datarate(self, message: SetDatarate):
        rates = {
            250000 : RFStormDataRate.RF_250KBPS,
            1000000 : RFStormDataRate.RF_1MBPS,
            2000000 : RFStormDataRate.RF_2MBPS,
        }
        if message.rate in rates:
            self.__phy_rate = rates[message.rate]
            return Success()
        return ParameterError()

    @VirtualDevice.route(SetPacketSize)
    def on_phy_packet_size(self, message: SetPacketSize):
        if message.packet_size >= 5 and message.packet_size <= 31:
            self.__phy_size = message.packet_size
            return Success()
        return ParameterError()

    @VirtualDevice.route(SetEndianness)
    def on_phy_endianness(self, message: SetEndianness):
        if message.endianness in (Endianness.BIG, Endianness.LITTLE):
            self.__phy_endianness = message.endianness
            return Success()
        return ParameterError()

    @VirtualDevice.route(SetGfskMod)
    def on_phy_mod_gfsk(self, message: SetGfskMod):
        return Success()

    @VirtualDevice.route(SendPacket)
    def on_phy_send(self, message: SendPacket):
        return self.__on_whad_send(message)

    # Packet send wrapper
    def __on_whad_send(self, message):
        if self.__domain == RFStormDomains.RFSTORM_PHY:
            if self.__phy_endianness == Endianness.LITTLE:
                sync = bytes([swap_bits(i) for i in self.__phy_sync])[::-1]
                data =  bytes([swap_bits(i) for i in message.packet])
            else:
                sync = self.__phy_sync
                data = message.packet
            success = self._rfstorm_transmit_payload_generic(sync + data, address=b"")
            if success:
                return Success()
            return ParameterError()
        else:
            #channel = message.channel if message.channel != 0xFF else self.__channel
            pdu = message.pdu
            retransmission_count = message.retr_count
            if self.__acking:
                self.__ack_payload = pdu
            else:
                ack = self._rfstorm_transmit_payload(pdu, retransmits=retransmission_count)
                if self.__check_ack:
                    # Packet was successfully acked, send success and ack payload
                    # if not, send success without ack packet.
                    if ack:
                        ack_packet = self.__build_whad_pdu(b"", address=self.__address)
                        return [Success(), ack_packet]
                    else:
                        return Success()

            return Success()

    # ESB Domain

    @VirtualDevice.route(EsbSend)
    def on_esb_send(self, message: EsbSend):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        return self.__on_whad_send(message)

    @VirtualDevice.route(UnifyingSend)
    def on_unifying_send(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        return self.__on_whad_send(message)

    def __set_node_addr(self, address: bytes):
        self.__address = address
        return Success()

    @VirtualDevice.route(EsbSetNodeAddress)
    def on_esb_set_node_addr(self, message: EsbSetNodeAddress):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        return self.__set_node_addr(message.address)

    @VirtualDevice.route(UnifyingSetNodeAddress)
    def on_whad_unifying_set_node_addr(self, message: UnifyingSetNodeAddress):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        return self.__set_node_addr(message.address)

    def __enable_ptx(self, channel: int):
        self.__internal_state = RFStormInternalStates.SNIFFING
        self.__acking = False
        self.__check_ack = True
        self.__ptx = True
        self.__channel = channel
        return Success()

    @VirtualDevice.route(EsbPtxMode)
    def on_esb_ptx(self, message: EsbPtxMode):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        return self.__enable_ptx(message.channel)

    @VirtualDevice.route(UnifyingMouse)
    def on_unifying_mouse(self, message: UnifyingMouse):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        return self.__enable_ptx(message.channel)

    @VirtualDevice.route(UnifyingKeyboard)
    def on_unifying_keyboard(self, message: UnifyingKeyboard):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        self._on_whad_ptx(message.channel)

    def __enable_prx(self, channel: int):
        self.__internal_state = RFStormInternalStates.SNIFFING
        self.__acking = True
        self.__check_ack = False
        self.__ptx = False
        self.__channel = channel
        return Success()

    @VirtualDevice.route(EsbPrxMode)
    def on_esb_prx(self, message: EsbPrxMode):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        return self.__enable_prx(message.channel)

    @VirtualDevice.route(UnifyingDongle)
    def _on_whad_unifying_dongle(self, message):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        return self.__enable_prx(message.channel)

    def __enable_sniffing(self, channel: int, address: bytes, show_acks: bool):
        if self.__domain == RFStormDomains.RFSTORM_PHY:
            self.__internal_state = RFStormInternalStates.SNIFFING
            return Success()
        else:
            self.__ptx = False
            self.__channel = channel

            self.__acking = False
            if address == b"\xFF\xFF\xFF\xFF\xFF":
                self.__internal_state = RFStormInternalStates.PROMISCUOUS_SNIFFING
            else:
                self.__internal_state = RFStormInternalStates.SNIFFING
                self.__address = address
            return Success()

    @VirtualDevice.route(EsbSniffMode)
    def on_esb_sniff(self, message: EsbSniffMode):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        return self.__enable_sniffing(message.channel, message.address, message.show_acks)

    @VirtualDevice.route(UnifyingSniffMode)
    def on_unifying_sniff(self, message: UnifyingSniffMode):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        return self.__enable_sniffing(message.channel, message.address, message.show_acks)

    @VirtualDevice.route(PhySniffMode)
    def on_phy_sniff(self, message: PhySniffMode):
        self.__domain = RFStormDomains.RFSTORM_PHY
        return self.__enable_sniffing(message.channel, None, False)

    def __stop(self):
        self.__opened_stream = False
        return Success()

    @VirtualDevice.route(EsbStop)
    def on_esb_stop(self, message: EsbStop):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        return self.__stop()

    @VirtualDevice.route(UnifyingStop)
    def on_unifying_stop(self, message: UnifyingStop):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        return self.__stop()

    @VirtualDevice.route(PhyStop)
    def on_phy_stop(self, message: PhyStop):
        self.__domain = RFStormDomains.RFSTORM_PHY
        return self.__stop()

    def __start(self):
        self._rfstorm_enable_lna()
        if self.__domain == RFStormDomains.RFSTORM_PHY:
            if self.__phy_endianness == Endianness.LITTLE:
                sync = bytes([swap_bits(i) for i in self.__phy_sync])[::-1]
            else:
                sync = self.__phy_sync

            # Set channel
            success_chan = self._rfstorm_set_channel(self.__channel)

            # Enable promiscuous mode
            success = self._rfstorm_generic_promiscuous_mode(prefix=sync, rate=self.__phy_rate,
                                                             payload_length=self.__phy_size)
            if success and success_chan:
                self.__opened_stream = True
                return Success()
            return Error()

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
                return Success()
            return Error()

    @VirtualDevice.route(EsbStart)
    def on_esb_start(self, message: EsbStart):
        self.__domain = RFStormDomains.RFSTORM_RAW_ESB
        return self.__start()

    @VirtualDevice.route(UnifyingStart)
    def on_unifying_start(self, message: UnifyingStart):
        self.__domain = RFStormDomains.RFSTORM_UNIFYING
        return self.__start()

    @VirtualDevice.route(PhyStart)
    def _on_whad_phy_start(self, message: PhyStart):
        self.__domain = RFStormDomains.RFSTORM_PHY
        return self.__start()

