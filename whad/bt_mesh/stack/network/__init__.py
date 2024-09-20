"""
Network Layer

Handles Relay and Proxy features, Cipher/Decipher network level (netkey), caching
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.scapy.layers.bt_mesh import (
    BTMesh_Network_PDU,
    BTMesh_Obfuscated_Network_PDU,
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Lower_Transport_Control_Message,
    EIR_Hdr,
)
from whad.bt_mesh.crypto import NetworkLayerCryptoManager
from whad.bt_mesh.stack.constants import (
    VIRTUAL_ADDR_TYPE,
    UNICAST_ADDR_TYPE,
    UNASSIGNED_ADDR_TYPE,
)
from whad.bt_mesh.stack.utils import get_address_type, MeshMessageContext
from whad.bt_mesh.stack.lower_transport import LowerTransportLayer
from whad.bt_mesh.models import GlobalStatesManager
from scapy.all import raw

logger = logging.getLogger(__name__)


@alias("network")
class NetworkLayer(Layer):
    def configure(self, connector, options={}):
        """
        NetworkLayer. One for all the networks (does the filtering)

        :param connector: Connector handling the advertising bearer (or GATT later ?)
        :type connector: Connector
        :param options: Options passed to the layer. defaults to {}
        :type options: [TODO:type], optional
        """
        super().configure(options=options)

        # save connector (BLE phy stack, advertising Bearer (and GATT I guess ?))
        self.__connector = connector

        # Network Key Crypto managers. Correspondance between nid and net_key_index
        self.state.nid_to_net_key_id = {}

        self.state.global_states_manager = GlobalStatesManager()
        self.update_net_keys()

        # Stores concatenation of seq_number and src_addr.
        self.state.cache = []

        # Check if relay feature is enabled on this device (proxy not implemented)
        self.state.is_relay_enabled = False

        # Stores the next seq_number PDU we are waiting for to be sent
        self.state.next_seq_to_send = 0

        # Dict of packets to be sent. Key is seq_number
        self.state.send_queue = {}

    def update_net_keys(self):
        """
        Update the nid_to_net_key_id. Called when nid received that doesnt match anything
        """
        for net_key in self.state.global_states_manager.get_state(
            "net_key_list"
        ).get_all_values():
            if net_key is not None:
                self.state.nid_to_net_key_id[net_key.nid] = net_key.key_index

    def __check_nid(self, net_pdu):
        """
        Checks if any of the network keys has an NID matching with one in the packet
        If yes, returns it

        :param net_pdu: [TODO:description]
        :type net_pdu: [TODO:type]
        :returns: The network key of the matching key, None if no match
        :rtype: NetworkLayerCryptoManager|None
        """
        if net_pdu.nid in self.state.nid_to_net_key_id.keys():
            key_id = self.state.nid_to_net_key_id[net_pdu.nid]
            return self.state.global_states_manager.get_state("net_key_list").get_value(
                key_id
            )

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
        cache_string = deobf_net_pdu.seq_number.to_bytes(
            3, "big"
        ) + deobf_net_pdu.src_addr.to_bytes(2, "big")
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
        net_pdu.show()
        net_key = self.__check_nid(net_pdu)
        if net_key is None:
            return

        # Deobfucate the packet and reconstruct it
        raw_deobf_net_pdu = net_key.deobfuscate_net_pdu(
            net_pdu, self.state.global_states_manager.iv_index
        )

        network_ctl = (raw_deobf_net_pdu[0]) >> 7
        ttl = raw_deobf_net_pdu[0] & 0x7F
        seq_number = raw_deobf_net_pdu[1:4]
        src_addr = raw_deobf_net_pdu[4:6]

        deobf_net_pdu = BTMesh_Network_PDU(
            ivi=self.state.global_states_manager.iv_index[0] & 0b01,
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
        net_key: NetworkLayerCryptoManager
        plaintext, is_auth_valid = net_key.decrypt(
            deobf_net_pdu, self.state.global_states_manager.iv_index
        )
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
    def on_lower_transport_packet(self, message):
        """
        Callback for Lower Transport Packet sent by the Lower Transport Layer.

        :param message: Lower Transport PDU and its context
        :type message: (BTMesh_Lower_Transport_Access_Message|BTMesh_Lower_Transport_Control_Message, MeshMessageContext)
        """
        pkt, ctx = message
        pkt.show()
        self.state.send_queue[ctx.seq_number] = message
        self.check_sending_queue()

    def check_sending_queue(self):
        """
        Checks if the next packet that needs to be sent is in the queue
        """
        if self.state.next_seq_to_send in self.state.send_queue:
            pkt, ctx = self.state.send_queue.pop(self.state.next_seq_to_send)
            ctx: MeshMessageContext
            # TODO (encryption and all)
            net_key = self.state.global_states_manager.get_state(
                "net_key_list"
            ).get_value(ctx.net_key_id)

            net_pdu = BTMesh_Network_PDU(
                ivi=self.state.global_states_manager.iv_index & 1,
                nid=net_key.nid,
                network_ctl=int(
                    isinstance(pkt, BTMesh_Lower_Transport_Control_Message)
                ),
                ttl=ctx.ttl,
                seq_number=ctx.seq_number,
                src_addr=ctx.src_addr,
            )

            net_key: NetworkLayerCryptoManager
            # encrypt the message
            enc = net_key.encrypt(
                raw(pkt),
                ctx.dest_addr,
                net_pdu,
                self.state.global_states_manager.iv_index,
            )

            # obfuscate the payload
            obfu_data = net_key.obfuscate_net_pdu(
                net_pdu, self.state.global_states_manager.iv_index
            )

            pkt = BTMesh_Obfuscated_Network_PDU(
                ivi=net_pdu.ivi,
                nid=net_pdu.nid,
                obfuscated_data=obfu_data,
                enc_dst_enc_transport_pdu_mic=enc,
            )
            self.__connector.send_raw(EIR_Hdr(type=0x2A) / pkt)
            self.state.next_seq_to_send += 1


NetworkLayer.add(LowerTransportLayer)
