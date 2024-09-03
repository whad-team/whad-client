"""
Network Layer

Handles Relay and Proxy features, Cipher/Decipher network level (netkey), caching
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.scapy.layers.bt_mesh import (
    BTMesh_Network_PDU,
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Lower_Transport_Control_Message,
)
from whad.bt_mesh.crypto import NetworkLayerCryptoManager
from whad.bt_mesh.stack.constants import (
    VIRTUAL_ADDR_TYPE,
    UNICAST_ADDR_TYPE,
    UNASSIGNED_ADDR_TYPE,
)
from whad.bt_mesh.stack.utils import get_address_type, MeshMessageContext

logger = logging.getLogger(__name__)


@alias("network")
class NetworkLayer(Layer):
    def __init__(self, connector, options={}):
        """
        NetworkLayer. One for all the networks (does the filtering)

        :param connector: Connector handling the advertising bearer (or GATT later ?)
        :type connector: Connector
        :param options: Options passed to the layer. Need at least a primary net_key (the CryptoManager) defaults to {}
        :type options: [TODO:type], optional
        """
        super().__init__(options=options)

        # save connector (BLE phy stack, advertising Bearer (and GATT I guess ?))
        self.__connector == connector

        # Network Key Crypto managers. one per network. Need at least the one for the primary index (0x0000) in options
        self.state.net_keys = {0x0000: options["primary_net_key"]}

        # Stores concatenation of seq_number and src_addr.
        self.state.cache = []

        # Check if relay feature is enabled on this device (proxy not implemented)
        self.state.is_relay_enabled = False

    def __check_nid(self, net_pdu):
        """
        Checks if any of the network keys has an NID matching with one in the packet

        :param net_pdu: [TODO:description]
        :type net_pdu: [TODO:type]
        :returns: The network key index of the matching key, None if no match
        :rtype: int|None
        """
        for index, key in self.state.net_keys.items():
            if key.nid == net_pdu.nid:
                return index

        return None

    def __check_address_validity(self, src_addr, dst_addr, network_ctl):
        """
        Verifies the src_addr and dst_addr under the critierias defined in
        Mesh Spec Section 3.4.3. Does not check against Access layer key type criterias here.

        :param src_addr: The source address in the network PDU
        :type src_addr: Bytes
        :param dst_addr: The destination address in the network PDU (after decryption)
        :type dst_addr: Bytes
        :param network_ctl: value of the network_ctl flag in the Network PDU
        :type network_ctl: int
        :returns: True if address ok, False otherwise
        :rtype: boolean
        """
        src_type = get_address_type(src_addr)
        if src_type != UNICAST_ADDR_TYPE:
            return False

        dst_type = get_address_type(dst_addr)
        if dst_type == UNASSIGNED_ADDR_TYPE:
            return False
        if network_ctl == 1 and dst_type == VIRTUAL_ADDR_TYPE:
            return False

        return True

    def __cache_verif(self, deobf_net_pdu):
        """
        Checks if received Net pdu in cache. Adds it if not.

        :param deobf_net_pdu: Received deobfuscated network pdu
        :type deobf_net_pdu: BTMesh_Network_PDU
        :returns: True if message is in cache, False otherwise
        :rtype: boolean
        """
        cache_string = (
            deobf_net_pdu.seq_number.to_bytes(3, "big") + deobf_net_pdu.src_addr
        )
        if cache_string in self.state.cache:
            return True

        self.state.cache.append(cache_string)
        return False

    def send_to_lower_transport(self, msg_ctx, lower_transport_pdu):
        """
        Sends the lower_transport_pdu to the Lower Transport Layer for processing

        :param msg_ctx: The context of the message, to share information to all the layers
        :type msg_ctx: MeshMessageContext
        :param lower_transport_pdu: [TODO:description]
        :type lower_transport_pdu: [TODO:type]
        """
        self.send("lower_transport", (msg_ctx, lower_transport_pdu))

    def on_net_pdu_received(self, net_pdu):
        """
        Connector received a network pdu on the bearer

        :param net_pdu: The received network PDU
        :type net_pdu: BTMesh_Obfuscated_Network_PDU
        """
        # check if any network key matches the NID in the packet
        net_key_index = self.__check_nid(net_pdu)
        if net_key_index is None:
            return

        net_key: NetworkLayerCryptoManager = self.state.net_keys[net_key_index]
        # Deobfucate the packet and reconstruct it
        raw_deobf_net_pdu = net_key.deobfuscate_net_pdu(net_pdu)

        network_ctl = (raw_deobf_net_pdu[0]) >> 7
        ttl = raw_deobf_net_pdu[0] & 0x7F
        seq_number = raw_deobf_net_pdu[1:4]
        src_addr = raw_deobf_net_pdu[4:6]

        deobf_net_pdu = BTMesh_Network_PDU(
            ivi=net_key.iv_index[0] & 0b01,
            nid=net_key.nid,
            network_ctl=network_ctl,
            ttl=ttl,
            seq_number=int.from_bytes(seq_number, "big"),
            src_addr=int.from_bytes(src_addr, "big"),
            enc_dst_enc_transport_pdu_mic=net_pdu.enc_dst_enc_transport_pdu_mic,
        )

        # check if message in network cache. Mesh Spec section 3.4.5.6
        is_pdu_in_cache = self.__cache_verif(deobf_net_pdu)
        if is_pdu_in_cache:
            logger.warning("PDU Already received in Network Layer Cache, dropping")
            return

        # decrypt the encrypted Lower Transport PDU
        plaintext, is_auth_valid = net_key.decrypt(deobf_net_pdu)
        if not is_auth_valid:
            logger.warning(
                "Received Network PDU with wrong authentication value, dropping"
            )
            return

        # check address validity. Mesh Spec Section 3.4.3
        dst_addr = plaintext[:2]
        are_addr_valid = self.__check_address_validity(src_addr, dst_addr)
        if not are_addr_valid:
            logger.warning(
                "Received Network PDU with non compliant addr types, dropping"
            )
            return

        # Create Lower Transport PDU and send it to the layer
        raw_lower_transport = plaintext[2:]
        if network_ctl == 1:
            lower_transport_pdu = BTMesh_Lower_Transport_Control_Message(
                raw_lower_transport
            )
        else:
            lower_transport_pdu = BTMesh_Lower_Transport_Access_Message(
                raw_lower_transport
            )

        msg_ctx = MeshMessageContext()
        msg_ctx.src_addr = src_addr
        msg_ctx.dest_addr = dst_addr
        msg_ctx.seq_number = seq_number

        self.send_to_lower_transport(msg_ctx, lower_transport_pdu)

        @source("lower_transport")
        def on_lower_transport_packet(self, lower_transport_pdu):
            """
            Callback for Lower Transport Packet sent by the Lower Transport Layer.

            :param self: [TODO:description]
            :type self: [TODO:type]
            :param lower_transport_pdu: Lower Transport PDU
            :type lower_transport_pdu: BTMesh_Lower_Transport_Access_Message|BTMesh_Lower_Transport_Control_Message
            """
