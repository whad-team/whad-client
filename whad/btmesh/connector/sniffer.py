"""
Bluetooth Mesh Sniffer Connector

Basic Bluetooth Mesh Passive Sniffer
"""

import logging
from typing import Generator
from collections import deque
from time import time

from scapy.packet import Packet, Raw

from scapy.layers.bluetooth4LE import BTLE_ADV, EIR_Hdr
from whad.exceptions import WhadDeviceDisconnected
from whad.helpers import message_filter
from whad.hub.ble.pdu import BleAdvPduReceived, BleRawPduReceived
from whad.scapy.layers.btmesh import (
    BTMesh_Obfuscated_Network_PDU,
    BTMesh_Network_PDU,
    BTMesh_Lower_Transport_Control_Message,
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Upper_Transport_Access_PDU,
    BTMesh_Model_Message,
)
from whad.btmesh.connector import BTMesh
from whad.scapy.layers.btmesh import (
    BTMesh_Obfuscated_Network_PDU,
    BTMesh_Network_Clear_PDU,
)
from whad.common.sniffing import EventsManager
from whad.btmesh.sniffing import SnifferConfiguration
from whad.btmesh.crypto import (
    UpperTransportLayerAppKeyCryptoManager,
    NetworkLayerCryptoManager,
)
from whad.btmesh.stack.utils import (
    MeshMessageContext,
    calculate_seq_auth,
)
from whad.btmesh.stack.constants import OPCODE_TO_PAYLOAD_CLASS_LOWER_TRANSPORT
from whad.hub.message import AbstractPacket

logger = logging.getLogger(__name__)


class Sniffer(BTMesh, EventsManager):
    """
    Connector class for BTMesh sniffing, with decryption if keys given in configuration

    In order to have replay capabilities, or to have a valid PCAP for wireshark, do not decrypt packets (yields Obfuscated Network PDUs, no RPL)
    If decrypt enabled, captures read only in whad (will only log packets successfully deciphered). Does not support decryption of Access message to virtual addresses
    """

    def __init__(
        self,
        device,
        configuration=SnifferConfiguration(),  # net_keys=[bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")]
    ):
        """
        Init the sniffer

        :param device: Whad device handle
        :type device: WhadDeviceConnector
        :param configuration: The SnifferConfiguration object with the appropriate parameters
        :rype configuration: SnifferConfiguration
        """

        BTMesh.__init__(self, device)
        EventsManager.__init__(self)
        self.__configuration = configuration

        # Stores fragments of PDU per src_addr/dst_addr/seq_auth trouple
        # Key is src_addr||dst_addr||seq_auth, item is dict of raw fragments (key is fragment index)
        self.__rx_fragments = {}
        # Mac number of concurrent PDUs in the dict
        self.__maxlen_rx_fragments = 50

        # Keys given in the configuration, to try and decryt packets we receive
        # Not in configuration object not to confuse types...
        self.__net_keys = []
        self.__app_keys = []
        self.__iv_indexes = []

        self.__cache = deque(maxlen=100)

    @property
    def configuration(self):
        """Sniffing configuration"""
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def configure(
        self,
        channel=37,
        net_keys=["f7a2a44f8e8a8029064f173ddc1e2b00"],
        app_keys=["63964771734fbd76e3b40519d1d94a48"],
        iv_indexes=["00000000"],
        decrypt=True,
        whitelist_addresses=[],
    ):
        """Configure sniffer"""
        self.stop()
        self.__configuration.channel = channel
        self.__configuration.net_keys = net_keys
        self.__configuration.app_keys = app_keys
        self.__configuration.iv_indexes = iv_indexes
        self.__configuration.decrypt = decrypt
        self.__configuration.whitelist_addresses = whitelist_addresses
        self._enable_sniffing()

    def add_net_key(self, net_key, iv_index="00000000"):
        """Add known encryption netkey to configured keys"""
        self.stop()
        self.__configuration.net_keys.append(net_key)
        self.__configuration.iv_indexes.append(iv_index)
        self._enable_sniffing()

    def add_app_key(self, app_key):
        """Add known encryption appkey to configured keys"""
        self.stop()
        self.__configuration.net_keys.append(app_key)
        self._enable_sniffing()

    @property
    def channel(self):
        """BLE channel number"""
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=37):
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()

    @property
    def crc_init(self):
        """CRC seed value (might not be needed)"""
        return 0x555555

    def _enable_sniffing(self):
        """Enable sniffing"""
        self.__net_keys = []
        self.__app_keys = []
        self.__iv_indexes = []

        if self.__configuration.decrypt:
            # complete iv_index with 0 values if not enough compared to number of net keys
            for i in range(
                0,
                len(self.__configuration.net_keys)
                - len(self.__configuration.iv_indexes),
            ):
                self.__configuration.__iv_indexes.append("00000000")

            for iv_index in self.__configuration.iv_indexes:
                try:
                    self.__iv_indexes.append(bytes.fromhex(iv_index))
                except ValueError:
                    logger.debug(
                        "Incorrect type for iv_index in configuration : %s" % iv_index
                    )
                    self.__iv_indexes.append(bytes.fromhex("00000000"))

            for key in self.__configuration.net_keys:
                try:
                    net_key = bytes.fromhex(key)
                    self.__net_keys.append(
                        NetworkLayerCryptoManager(key_index=0, net_key=net_key)
                    )
                except ValueError:
                    logger.debug("Inccorrect NetKey in configutation : %s" % key)

            for key in self.__configuration.app_keys:
                try:
                    app_key = bytes.fromhex(key)
                    self.__app_keys.append(
                        UpperTransportLayerAppKeyCryptoManager(
                            key_index=0, app_key=app_key
                        )
                    )
                except ValueError:
                    logger.debug("Inccorrect AppKey in configutation : %s" % key)

        # network cache reset
        self.__cache = deque(maxlen=100)

        self.sniff_advertisements(channel=self.__configuration.channel)

    def __check_nid(
        self, net_pdu
    ) -> tuple[NetworkLayerCryptoManager | None, bytes | None]:
        """
        Checks if any of the network keys has an NID matching with one in the packet
        If yes, returns it

        :param net_pdu: NetPdu received
        :type net_pdu: BTMesh_Obfuscated_Network_PDU
        :returns: The network key of the matching key, None if no match
        :rtype: (NetworkLayerCryptoManager|None, bytes|None)
        """
        for i in range(len(self.__net_keys)):
            key = self.__net_keys[i]
            iv_index = self.__iv_indexes[i]
            if net_pdu.nid == key.nid_mf:
                return key, iv_index
            elif net_pdu.nid == key.nid_df:
                return key, iv_index

        return None, None

    def __check_aid(self, lower_transport_pdu):
        """
        Checks if any of the application keys has an AID matching the one in the packet

        :param lower_transport_pdu: The Lower Transport Access PDU received
        """
        key_flag = lower_transport_pdu.application_key_flag
        aid = lower_transport_pdu.application_key_id

        for i in range(len(self.__app_keys)):
            key = self.__app_keys[i]
            if aid == key.aid:
                return key

        return None

    def __cache_verif(self, deobf_net_pdu):
        """
        Checks if received Net pdu in cache. Adds it if not.

        :param deobf_net_pdu: Received deobfuscated network pdu
        :type deobf_net_pdu: BTMesh_Network_PDU
        :returns: True if message is in cache, False otherwise
        :rtype: boolean
        """
        cache_string = deobf_net_pdu.seq_number.to_bytes(
            3, "big"
        ) + deobf_net_pdu.src_addr.to_bytes(2, "big")
        if cache_string in self.__cache:
            return True

        self.__cache.append(cache_string)
        return False

    def process_packet(self, packet):
        """
        Process a received packet

        :param packet: Packet received
        :type packet: Packet
        """
        if not self.bt_mesh_filter(packet, True):
            return None

        # if the packet is a Network PDU, we process it before sending
        if packet.haslayer(BTMesh_Obfuscated_Network_PDU):
            metadata = packet.metadata
            decrypted_packet = self.process_mesh_pdu(packet)
            if decrypted_packet is not None:
                metadata.decrypted = True
                packet.payload = decrypted_packet.payload
                packet.metadata = metadata

        return packet


    def process_segmented_pdu(self, clear_net_pdu, lower_transport_pdu, iv_index):
        """
        Process a segemented pdu received

        :param clear_net_pdu: The Network Layer PDU information
        :type clear_net_pdu: BTMesh_Network_Clear_PDU
        :param lower_transport_pdu: The lower_transport layer pdu to process with seg field to 1
        :type lower_transport_pdu: BTMesh_Lower_Transport_Control_Message | BTMesh_Lower_Transport_Access_Message
        :param iv_index: The current IV_index of the network we sniff on
        :type iv_index: int
        """
        segment_pdu = lower_transport_pdu.payload_field
        seq_auth = calculate_seq_auth(
            iv_index, clear_net_pdu.seq_number, segment_pdu.seq_zero
        )

        # Check if we already have a fragment list for this PDU
        key = hex(clear_net_pdu.src_addr) + hex(clear_net_pdu.dst_addr) + hex(seq_auth)

        if key not in self.__rx_fragments:
            # check if dict size too large, pop item if necessary (FIFO style)
            if len(self.__rx_fragments) >= self.__maxlen_rx_fragments:
                self.__rx_fragments.pop(next(iter(self.__rx_fragments)))

            self.__rx_fragments[key] = {}

        fragments = self.__rx_fragments[key]

        # Check if we already finished receiving this PDU before ...
        if len(fragments.keys()) >= segment_pdu.last_seg_number + 1:
            return None

        # Put fragment in dict
        fragments[segment_pdu.seg_offset] = segment_pdu.getlayer(Raw).load

        # if all segments received, reassemble and return packet
        if len(fragments.keys()) == segment_pdu.last_seg_number + 1:
            raw_upper_pkt = b""
            for index, fragment in sorted(fragments.items()):
                raw_upper_pkt += fragment

            # Reset fragments (if src resends the same whole packet, to have it again)
            self.__rx_fragments[key] = {}

            if clear_net_pdu.network_ctl:
                pkt = OPCODE_TO_PAYLOAD_CLASS_LOWER_TRANSPORT[
                    lower_transport_pdu.opcode
                ](raw_upper_pkt)
            else:
                pkt = BTMesh_Upper_Transport_Access_PDU(raw_upper_pkt)
            return pkt

        # If not all segments recieved yet, return None
        else:
            return None

    def try_network_message_decrypt(self, net_pdu):
        """
        Tries to Deobfucate and decrypt the received network pdu

        :param net_pdu: [TODO:description]
        :returns: THe plaintext and iv_index of the network the message was sent on
        """
        net_key, iv_index = self.__check_nid(net_pdu)
        if net_key is None:
            logger.debug("No NetKey found to decipher this message.")
            return None, None, None

        # Deobfucate the packet and reconstruct it
        raw_deobf_net_pdu = net_key.deobfuscate_net_pdu(net_pdu, iv_index)

        network_ctl = (raw_deobf_net_pdu[0]) >> 7
        ttl = raw_deobf_net_pdu[0] & 0x7F
        seq_number = int.from_bytes(raw_deobf_net_pdu[1:4], "big")
        src_addr = int.from_bytes(raw_deobf_net_pdu[4:6], "big")

        deobf_net_pdu = BTMesh_Network_PDU(
            ivi=iv_index[0] & 0b01,
            nid=net_pdu.nid,
            network_ctl=network_ctl,
            ttl=ttl,
            seq_number=seq_number,
            src_addr=src_addr,
            enc_dst_enc_transport_pdu_mic=net_pdu.enc_dst_enc_transport_pdu_mic,
        )

        # Check Network Cache list if activated
        if self.__configuration.use_network_cache and not self.__cache_verif(
            deobf_net_pdu
        ):
            logger.debug(
                "Received a cached message from %x (seq num %x)"
                % (src_addr, seq_number)
            )
            return None, None, None

        # decrypt the encrypted Lower Transport PDU
        plaintext, is_auth_valid = net_key.decrypt(deobf_net_pdu, iv_index)
        if not is_auth_valid:
            logger.debug(
                "Received Network PDU with wrong authentication value, dropping"
            )
            return None, None, None

        return deobf_net_pdu, plaintext, iv_index

    def try_access_message_decrypt(
        self, clear_net_pdu, lower_transport_pdu, iv_index, aszmic
    ):
        """
        Try to decrypt an access message with the app keys we have

        :param clear_net_pdu: [TODO:description]
        :param lower_transport_pdu: [TODO:description]
        :param iv_index: [TODO:description]
        :param: aszmic: [TODO:description]
        """
        plaintext = None
        app_key = self.__check_aid(lower_transport_pdu)
        if app_key is None:
            return None

        plaintext, is_auth_valid = app_key.decrypt(
            lower_transport_pdu.getlayer(
                BTMesh_Upper_Transport_Access_PDU
            ).enc_access_message_and_mic,
            aszmic=aszmic,
            seq_number=clear_net_pdu.seq_number,
            src_addr=clear_net_pdu.src_addr,
            dst_addr=clear_net_pdu.dst_addr,
            iv_index=iv_index,
        )

        if plaintext is not None and is_auth_valid:
            return plaintext
        else:
            return None

    def process_mesh_pdu(self, pdu):
        """
        Process a Mesh PDU (not a Beacon or Provisioning packet)
        """
        if not self.__configuration.decrypt:
            return pdu

        net_pdu = pdu.getlayer(BTMesh_Obfuscated_Network_PDU)
        deobf_net_pdu, plaintext, iv_index = self.try_network_message_decrypt(net_pdu)
        if plaintext is None:
            return None

        # Create Control PDU or Model Message depending on type and send it to the layer
        dst_addr = int.from_bytes(plaintext[:2], "big")
        raw_lower_transport = plaintext[2:]

        clear_net_pdu = BTMesh_Network_Clear_PDU(
            ivi=deobf_net_pdu.ivi,
            nid=deobf_net_pdu.nid,
            network_ctl=deobf_net_pdu.network_ctl,
            ttl=deobf_net_pdu.ttl,
            seq_number=deobf_net_pdu.seq_number,
            src_addr=deobf_net_pdu.src_addr,
            dst_addr=dst_addr,
        )

        # Different processing if access or control message
        if clear_net_pdu.network_ctl == 1:
            lower_transport_pdu = BTMesh_Lower_Transport_Control_Message(
                raw_lower_transport
            )
        else:
            lower_transport_pdu = BTMesh_Lower_Transport_Access_Message(
                raw_lower_transport
            )

        aszmic = 0
        if lower_transport_pdu.seg == 1:
            aszmic = lower_transport_pdu.payload_field.aszmic
            assembled_packet = self.process_segmented_pdu(
                clear_net_pdu, lower_transport_pdu, iv_index
            )

            # Not received all segments
            if assembled_packet is None:
                return None

            # Retrieve correct segment number for Upper Transport decrypt
            clear_net_pdu.seq_number = (
                calculate_seq_auth(
                    iv_index,
                    clear_net_pdu.seq_number,
                    lower_transport_pdu.payload_field.seq_zero,
                )
                & 0xFFFFFF
            )

            # Pretend the packet was not segmented, to simplify processing
            lower_transport_pdu.seg = 0
            lower_transport_pdu = lower_transport_pdu / assembled_packet

            # If completed segemented control message, return it
            if clear_net_pdu.network_ctl == 1:
                return clear_net_pdu / lower_transport_pdu

        # If unsegmented control message, return directly
        if clear_net_pdu.network_ctl == 1:
            return clear_net_pdu / lower_transport_pdu

        # If access pdu, try to decipher it
        plaintext = self.try_access_message_decrypt(
            clear_net_pdu, lower_transport_pdu, iv_index, aszmic
        )
        if plaintext is None:
            return None
        else:
            return clear_net_pdu / BTMesh_Model_Message(plaintext)

    def sniff(self, timeout: float | None = None) -> Generator[Packet, None, None]:
        """Main sniffing function

        :param timeout: Number of seconds after which sniffing is stopped.
                        Wait forever if set to `None`.
        :type timeout: float
        """
        start = time()
        try:
            if self.support_raw_pdu():
                message_type = BleRawPduReceived
            else:
                message_type = BleAdvPduReceived


            while True:
                message = self.wait_for_message(filter=message_filter(message_type), timeout=0.1)

                if message is not None:
                    packet = message.to_packet()
                    packet = self.process_packet(packet)
                    self.monitor_packet_rx(packet)
                    yield packet

                # Check if timeout has been reached
                if timeout is not None:
                    if time() - start >= timeout:
                        break

        except WhadDeviceDisconnected:
            return
