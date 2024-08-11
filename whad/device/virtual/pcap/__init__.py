from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied, \
    WhadDeviceDisconnected
from whad.device.virtual import VirtualDevice
from whad.helpers import message_filter,is_message_type,bd_addr_to_bytes
from whad.device.virtual.pcap.capabilities import CAPABILITIES
from whad.hub.generic.cmdresult import CommandResult
from whad.hub.dot15d4 import Commands
from scapy.layers.dot15d4 import Dot15d4#, Dot15d4FCS
from whad.ble.utils.phy import channel_to_frequency, frequency_to_channel, crc, FieldsSize, is_access_address_valid
from scapy.utils import PcapReader, PcapWriter
from struct import unpack, pack
from scapy.layers.bluetooth4LE import BTLE
from whad.scapy.layers.phy import Phy_Packet
from whad.hub.dot15d4 import Dot15d4Metadata
from whad.hub.ble import BLEMetadata
from whad.hub.esb import ESBMetadata
from whad.hub.phy import PhyMetadata, Modulation, Endianness
from whad.hub.unifying import UnifyingMetadata
from time import sleep
from whad import WhadDomain
from os.path import exists
import logging
import sys

logger = logging.getLogger(__name__)

class PCAPDevice(VirtualDevice):

    INTERFACE_NAME = "pcap"

    @classmethod
    def list(cls):
        '''
        Returns a list of available PCAP devices.
        '''
        return None

    @classmethod
    def check_interface(cls, interface):
        '''
        This method checks dynamically if the provided interface can be instantiated.
        '''
        logger.info("Checking interface: %s" % str(interface))
        if interface.endswith(".pcap") or interface.endswith(".pcapng"):
            return True
        else:
            return False

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in format "<bus>-<address>").
        '''
        return "pcap:" + str(self.__filename)


    def __init__(self, filename):
        """
        Create device connection
        """
        self.__opened = False
        self.__started = False
        self.__flush = "flush:" in filename
        self.__filename = filename.replace("flush:", "")
        self.__pcap_reader = None
        self.__pcap_writer = None
        self.__dlt = None
        self.__domain = None
        self.__start_timestamp, self.__last_timestamp = None, None


        self.__supported_frequency_range = [
            (281000000, 361000000),
            (378000000, 481000000),
            (749000000, 962000000),
            (2400000000, 2500000000)
        ]
        super().__init__()

    def _is_reader(self):
        """
        Returns True if the PCAP is in reading mode.
        """
        return self.__pcap_reader is not None

    def _get_dlt(self):
        if self._is_reader():
            if hasattr(self.__pcap_reader, "linktype"):
                dlt = self.__pcap_reader.linktype
            else:
                # PCAP-ng
                _ = self.__pcap_reader.read_packet()
                dlt = self.__pcap_reader.interfaces[0][0]
                self.__pcap_reader = PcapReader(self.__filename)
            return dlt

    def _get_domain(self):
        return list(CAPABILITIES[self.__dlt][0].keys())[0]

    def open(self):
        try:
            #print("Opening:", self.__filename)
            if exists(self.__filename):
                logger.info("Existing PCAP file")
                self.__pcap_reader = PcapReader(self.__filename)
                self.__dlt = self._get_dlt()
                self.__domain = self._get_domain()
            else:
                logger.info("No PCAP file")
                raise WhadDeviceNotFound("pcap")

        except:
            raise WhadDeviceAccessDenied("pcap")

        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()
        #self.__flush = False
        self.__opened = True
        # Ask parent class to run a background I/O thread
        super().open()

    def write(self, data):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self):
        if not self.__opened:
            raise WhadDeviceNotReady()
        while self.__started:
            try:
                if self._is_reader():
                    pkt = self.__pcap_reader.read_packet()
                    self._send_packet(pkt)
            except EOFError:
                # TODO: add an event to indicate end of stream ?
                logger.debug('[PCAPDevice] EOF reached')
                raise WhadDeviceDisconnected()

    def reset(self):
        pass

    def _generate_metadata(self, pkt):
        if self.__domain == WhadDomain.Dot15d4:
            metadata = Dot15d4Metadata.convert_from_header(pkt)
        elif self.__domain == WhadDomain.BtLE:
            metadata = BLEMetadata.convert_from_header(pkt)
        elif self.__domain == WhadDomain.Esb:
            metadata = ESBMetadata.convert_from_header(pkt)
        elif self.__domain == WhadDomain.LogitechUnifying:
            metadata = UnifyingMetadata.convert_from_header(pkt)
        elif self.__domain == WhadDomain.Phy:
            metadata = PhyMetadata.convert_from_header(pkt)

        else:
            return None
        if self.__start_timestamp is None:
            self.__start_timestamp = metadata.timestamp
        metadata.timestamp = metadata.timestamp - self.__start_timestamp
        return metadata

    def _interframe_delay(self, timestamp):
        if not self.__flush:
            if self.__last_timestamp is None:
                self.__last_timestamp = 0
            sleep((timestamp - self.__last_timestamp)/100000)

    def _send_packet(self, pkt):
        if self.__domain == WhadDomain.Dot15d4:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            self._send_whad_zigbee_raw_pdu(bytes(pkt[Dot15d4]), channel=metadata.channel, lqi=metadata.lqi, rssi=metadata.rssi, timestamp=metadata.timestamp)
        elif self.__domain == WhadDomain.BtLE:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            self._send_whad_ble_raw_pdu(pkt, metadata)
        elif self.__domain == WhadDomain.Esb:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            self._send_whad_esb_raw_pdu(pkt, metadata)
        elif self.__domain == WhadDomain.LogitechUnifying:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            self._send_whad_unifying_raw_pdu(pkt, metadata)
        elif self.__domain == WhadDomain.Phy:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            self._send_whad_phy_pdu(pkt, metadata)


    def _send_whad_phy_pdu(self, packet, metadata):
        #packet.show()
        msg = self.hub.phy.create_packet_received(
            metadata.frequency, # TODO: frequency,
            bytes(packet[Phy_Packet]),
            metadata.rssi, # TODO: rssi
            metadata.timestamp,
            metadata.syncword,
            metadata.datarate,
            metadata.deviation,
            Modulation(metadata.modulation),
            Endianness(metadata.endianness)
        )
        # Send message
        self._send_whad_message(msg)

    def _send_whad_unifying_raw_pdu(self, packet, metadata):
        # Create a RawPduReceived message
        msg = self.hub.unifying.create_raw_pdu_received(
            metadata.channel,
            bytes(packet),
            metadata.rssi,
            metadata.timestamp,
            metadata.is_crc_valid,
            metadata.address
        )

        # Send message
        self._send_whad_message(msg)

    def _send_whad_esb_raw_pdu(self, packet, metadata):

        # Create a RawPduReceived message
        msg = self.hub.esb.create_raw_pdu_received(
            metadata.channel,
            bytes(packet),
            metadata.rssi,
            metadata.timestamp,
            metadata.is_crc_valid,
            metadata.address
        )

        # Send message
        self._send_whad_message(msg)

    def _send_whad_ble_raw_pdu(self, packet, metadata):
        packet = packet[BTLE:]
        access_address = packet.access_addr
        pdu = bytes(packet)[FieldsSize.ACCESS_ADDRESS_SIZE:-FieldsSize.CRC_SIZE]

        # Create a RawPduReceived message
        msg = self.hub.ble.create_raw_pdu_received(
            metadata.direction,
            pdu,
            access_address,
            0,
            crc_validity=metadata.is_crc_valid,
            crc=packet.crc,
            channel=metadata.channel,
            timestamp=metadata.timestamp,
            rssi=metadata.rssi
        )

        # Send message
        self._send_whad_message(msg)



    # Virtual device whad message builder
    def _send_whad_zigbee_raw_pdu(self, packet, channel=None, rssi=None, lqi=None, is_fcs_valid=True, timestamp=None):
        pdu = packet[:-2]
        fcs = unpack("<H",packet[-2:])[0]

        # Create a RawPduReceived message
        msg = self.hub.dot15d4.create_raw_pdu_received(
            channel,
            pdu,
            fcs,
            lqi = lqi,
            fcs_validity=is_fcs_valid
        )

        # Set timestamp and RSSI if provided
        if rssi is not None:
            msg.rssi = rssi
        if timestamp is not None:
            msg.timestamp = timestamp

        # Send message
        self._send_whad_message(msg)


    # Virtual device whad message callbacks
    def _on_whad_ble_stop(self, message):
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_start(self, message):
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_sniff_adv(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_sniff_conn(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_phy_stop(self, message):
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_send_raw(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_sniff(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_start(self, message):
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_phy_get_supported_freq(self, message):
        # Create a SupportedFreqRanges
        msg = self.hub.phy.create_supported_freq_ranges(
            self.__supported_frequency_range
        )

        # Send message
        self._send_whad_message(msg)

    def _on_whad_phy_send(self, message):
        self._send_packet(message.packet)
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_phy_set_freq(self, message):
        found = False
        for supported_range in self.__supported_frequency_range:
            range_start, range_end = supported_range[0], supported_range[1]
            if message.frequency >= range_start and message.frequency <= range_end:
                found = True
                break
        if found:
            self.__frequency = message.frequency
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_datarate(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_packet_size(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_endianness(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_tx_power(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_ask(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_4fsk(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_fsk(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_gfsk(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_sync_word(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_dot15d4_stop(self, message):
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_send_raw(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_sniff(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_start(self, message):
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_stop(self, message):
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_send_raw(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_sniff(self, message):
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_start(self, message):
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_unifying_stop(self, message):
        self.__domain = WhadDomain.LogitechUnifying
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_unifying_send_raw(self, message):
        self.__domain = WhadDomain.LogitechUnifying
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_unifying_sniff(self, message):
        self.__domain = WhadDomain.LogitechUnifying
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_unifying_start(self, message):
        self.__domain = WhadDomain.LogitechUnifying
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    # Discovery related functions
    def _get_capabilities(self):
        index = 0 if self._is_reader() else 1
        capabilities = CAPABILITIES[self.__dlt][index]
        return capabilities

    def _get_manufacturer(self):
        return "whad-team".encode('utf-8')

    def _get_serial_number(self):
        return bytes.fromhex("00" * 16)

    def _get_firmware_version(self):
        return (0, 0, 0)

    def _get_url(self):
        return "https://github.com/whad-team/whad-client".encode('utf-8')
