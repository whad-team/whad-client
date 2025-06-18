"""
PCAP virtual device for WHAD.

This module provides a PCAP reader that behaves like a virtual WHAD device by
replaying packets from a specific PCAP file like they were being received with
some compatible hardware.
"""
import logging

from os.path import exists
from time import sleep
from struct import unpack

from scapy.layers.bluetooth4LE import BTLE
from scapy.layers.dot15d4 import Dot15d4
from scapy.utils import PcapReader

from whad.exceptions import WhadDeviceNotFound, WhadDeviceNotReady, WhadDeviceAccessDenied, \
    WhadDeviceDisconnected, WhadDeviceError

from whad.hub.generic.cmdresult import CommandResult
from whad.scapy.layers.phy import Phy_Packet
from whad.hub.dot15d4 import Dot15d4Metadata
from whad.hub.ble import BLEMetadata
from whad.hub.esb import ESBMetadata
from whad.hub.phy import PhyMetadata, Modulation, Endianness
from whad.hub.unifying import UnifyingMetadata
from whad.hub.discovery import Domain
from whad.ble.utils.phy import FieldsSize

from ..device import VirtualDevice
from .capabilities import CAPABILITIES

logger = logging.getLogger(__name__)

class Pcap(VirtualDevice):
    """PCAP replay virtual device implementation.
    """

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
        logger.info("Checking interface: %s", str(interface))
        return interface.endswith(".pcap") or interface.endswith(".pcapng")

    @property
    def identifier(self):
        '''
        Returns the identifier of the current device (e.g., bus + address in
        format "<bus>-<address>").
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

        # No DLT
        return None

    def _get_domain(self):
        """Retrieve the domain associated with the current link-layer type (DLT).
        """
        if self.__dlt in CAPABILITIES:
            return list(CAPABILITIES[self.__dlt][0].keys())[0]
        else:
            return None

    def open(self):
        try:
            if exists(self.__filename):
                logger.info("Existing PCAP file")
                self.__pcap_reader = PcapReader(self.__filename)
                self.__dlt = self._get_dlt()
                self.__domain = self._get_domain()
                if self.__domain is None:
                    raise WhadDeviceError(f"Unsupported PCAP file (DLT: {self.__dlt})")
            else:
                logger.info("No PCAP file")
                raise WhadDeviceNotFound("pcap")
        except WhadDeviceError as deverr:
            raise deverr
        except Exception as access_error:
            raise WhadDeviceAccessDenied("pcap") from access_error

        self._dev_id = self._get_serial_number()
        self._fw_author = self._get_manufacturer()
        self._fw_url = self._get_url()
        self._fw_version = self._get_firmware_version()
        self._dev_capabilities = self._get_capabilities()
        #self.__flush = False
        self.__opened = True
        # Ask parent class to run a background I/O thread
        super().open()

    def write(self, payload):
        if not self.__opened:
            raise WhadDeviceNotReady()

    def read(self) -> bytes:
        """Read packets from PCAP file and replay them
        """
        if not self.__opened:
            logger.error("Device not ready")
            raise WhadDeviceNotReady()
        while self.__started:
            try:
                if self._is_reader():
                    pkt = self.__pcap_reader.read_packet()
                    return self.__to_raw_message(pkt)
            except EOFError as eof:
                # End of PCAP reached, we are no more open and notify the
                # calling thread that we are now disconnected.
                logger.debug("[PCAPDevice] EOF reached")
                self.__opened = False
                raise WhadDeviceDisconnected() from eof

    @property
    def opened(self) -> bool:
        return self.__opened

    def reset(self):
        pass

    def _generate_metadata(self, pkt):
        if self.__domain == Domain.Dot15d4:
            metadata = Dot15d4Metadata.convert_from_header(pkt)
        elif self.__domain == Domain.BtLE:
            metadata = BLEMetadata.convert_from_header(pkt)
        elif self.__domain == Domain.Esb:
            metadata = ESBMetadata.convert_from_header(pkt)
        elif self.__domain == Domain.LogitechUnifying:
            metadata = UnifyingMetadata.convert_from_header(pkt)
        elif self.__domain == Domain.Phy:
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

    def __to_raw_message(self, pkt) -> bytes:
        msg = None
        if self.__domain == Domain.Dot15d4:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            msg = self.__to_whad_zigbee_raw_pdu(bytes(pkt[Dot15d4]), channel=metadata.channel,
                                           lqi=metadata.lqi, rssi=metadata.rssi,
                                           timestamp=metadata.timestamp)
        elif self.__domain == Domain.BtLE:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            msg = self.__to_whad_ble_raw_pdu(pkt, metadata)

        elif self.__domain == Domain.Esb:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            msg = self.__to_whad_esb_raw_pdu(pkt, metadata)

        elif self.__domain == Domain.LogitechUnifying:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            msg = self.__to_whad_unifying_raw_pdu(pkt, metadata)

        elif self.__domain == Domain.Phy:
            metadata = self._generate_metadata(pkt)
            self._interframe_delay(metadata.timestamp)
            self.__last_timestamp = metadata.timestamp
            msg = self.__to_whad_phy_pdu(pkt, metadata)

        if msg is not None:
            # Serialize protobuf message
            raw_msg = msg.serialize()

            # Define header
            header = [
                0xAC, 0xBE,
                len(raw_msg) & 0xff,
                (len(raw_msg) >> 8) & 0xff
            ]

            # Build the final payload
            return bytes(header) + raw_msg
        else:
            return b""

    def __to_whad_phy_pdu(self, packet, metadata):
        return self.hub.phy.create_packet_received(
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

    def __to_whad_unifying_raw_pdu(self, packet, metadata):
        # Create a RawPduReceived message
        return self.hub.unifying.create_raw_pdu_received(
            metadata.channel,
            bytes(packet),
            metadata.rssi,
            metadata.timestamp,
            metadata.is_crc_valid,
            metadata.address
        )

    def __to_whad_esb_raw_pdu(self, packet, metadata):

        # Create a RawPduReceived message
        return self.hub.esb.create_raw_pdu_received(
            metadata.channel,
            bytes(packet),
            metadata.rssi,
            metadata.timestamp,
            metadata.is_crc_valid,
            metadata.address
        )

    def __to_whad_ble_raw_pdu(self, packet, metadata):
        packet = packet[BTLE:]
        access_address = packet.access_addr
        pdu = bytes(packet)[FieldsSize.ACCESS_ADDRESS_SIZE:-FieldsSize.CRC_SIZE]

        # Create a RawPduReceived message
        return self.hub.ble.create_raw_pdu_received(
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

    # Virtual device whad message builder
    def __to_whad_zigbee_raw_pdu(self, packet, channel=None, rssi=None, lqi=None,
                                  is_fcs_valid=True, timestamp=None):
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

        return msg


    # Virtual device whad message callbacks
    def _on_whad_ble_stop(self, message): # pylint: disable=W0613
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_start(self, message): # pylint: disable=W0613
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_sniff_adv(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_ble_sniff_conn(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_phy_stop(self, message): # pylint: disable=W0613
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_send_raw(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_sniff(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_start(self, message): # pylint: disable=W0613
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_phy_get_supported_freq(self, message): # pylint: disable=W0613
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
            self._send_whad_command_result(CommandResult.SUCCESS)
        else:
            self._send_whad_command_result(CommandResult.PARAMETER_ERROR)

    def _on_whad_phy_datarate(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_packet_size(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_endianness(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_tx_power(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_ask(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_4fsk(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_fsk(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_mod_gfsk(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_phy_sync_word(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)


    def _on_whad_dot15d4_stop(self, message): # pylint: disable=W0613
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_send_raw(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_sniff(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_dot15d4_start(self, message): # pylint: disable=W0613
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_stop(self, message): # pylint: disable=W0613
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_send_raw(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_sniff(self, message): # pylint: disable=W0613
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_esb_start(self, message): # pylint: disable=W0613
        self.__started = True
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_unifying_stop(self, message): # pylint: disable=W0613
        self.__domain = Domain.LogitechUnifying
        self.__started = False
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_unifying_send_raw(self, message): # pylint: disable=W0613
        self.__domain = Domain.LogitechUnifying
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_unifying_sniff(self, message): # pylint: disable=W0613
        self.__domain = Domain.LogitechUnifying
        self._send_whad_command_result(CommandResult.SUCCESS)

    def _on_whad_unifying_start(self, message): # pylint: disable=W0613
        self.__domain = Domain.LogitechUnifying
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
