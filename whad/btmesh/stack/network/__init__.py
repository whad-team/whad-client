"""
Network Layer

Handles Relay and Proxy features, Cipher/Decipher network level (netkey), caching
"""

import logging
from collections import deque
from whad.common.stack import Layer, alias, source
from whad.scapy.layers.btmesh import (
    BTMesh_Network_PDU,
    BTMesh_Obfuscated_Network_PDU,
    BTMesh_Lower_Transport_Access_Message,
    BTMesh_Lower_Transport_Control_Message,
    EIR_Hdr,
    EIR_BTMesh_Beacon,
    BTMesh_Secure_Network_Beacon,
)
from whad.btmesh.stack.constants import (
    VIRTUAL_ADDR_TYPE,
    UNICAST_ADDR_TYPE,
    UNASSIGNED_ADDR_TYPE,
    GROUP_ADDR_TYPE,
    MANAGED_FLOODING_CREDS,
    DIRECTED_FORWARDING_CREDS,
)
from whad.btmesh.stack.utils import (
    get_address_type,
    MeshMessageContext,
)
from whad.btmesh.stack.lower_transport import LowerTransportLayer
from scapy.all import raw
from threading import Thread

logger = logging.getLogger(__name__)


@alias("network")
class NetworkLayer(Layer):
    def __init__(self, connector, parent=None, options={}):
        """
        NetworkLayer. One for all the networks (does the filtering)

        :param connector: Connector handling the advertising bearer (or GATT later ?)
        :type connector: Connector
        :param parent: Parent layer. Used for tests only, defaults to None
        :type parent: Layer
        :param options: Options passed to the layer. defaults to {}. Need to pass the "profile" object
        :type options: [TODO:type], optional
        """
        super().__init__(options=options, parent=parent)

        # Custom handler for packets received from parent layer
        # Should take the message as argument (with context)
        # Returns True if normal processing continues, False to directy return after custom handler
        self._custom_handlers = {}

        # save connector to send packets
        self.__connector = connector

        # Network Key Crypto managers. Correspondance between nid and net_key_index
        # FOR MANAGED FLOODING NIDs
        self.state.mf_nid_to_net_key_id = {}

        # Network Key Crypto managers. Correspondance between nid and net_key_index
        # FOR DIRECTED FORWARDING NIDs
        self.state.df_nid_to_net_key_id = {}

        # Stores concatenation of seq_number and src_addr.
        # Max 100 PDUs stored ... (This cache is only for speed purposes, replay protection on Lower Transport Layer)
        self.state.cache = deque(maxlen=100)

        # profile used that stores elements
        self.state.profile = options["profile"]

        self.update_net_keys()

    def register_custom_handler(self, clazz, handler):
        """
        Sets the handler function of the Message with class (Scapy packet) specified

        :param clazz: The class of the scapy packet we handle
        :param handler: The handler function, taking (Packet | MeshMessageContext) as arguments and returning nothing
        """
        self._custom_handlers[clazz] = handler

    def unregister_custom_hanlder(self, clazz):
        """
        Unregisters a previously registerd custom callback for a message received

        :param clazz: The class of the scapy packet not handled by custom handler anymore
        """
        try:
            self._custom_handlers.pop(clazz)
        except KeyError:
            pass

    def update_net_keys(self):
        """
        Update the nid_to_net_key_id. Called when nid received that doesnt match anything
        """
        self.state.mf_nid_to_net_key_id = {}
        self.state.df_nid_to_net_key_id = {}
        for subnet in self.state.profile.get_all_subnets():
            if subnet is not None:
                net_key = self.state.profile.get_net_key(subnet.net_key_index)
                if net_key is not None:
                    self.state.mf_nid_to_net_key_id[net_key.nid_mf] = (
                        subnet.net_key_index
                    )
                    self.state.df_nid_to_net_key_id[net_key.nid_df] = (
                        subnet.net_key_index
                    )

    def __check_nid(self, net_pdu):
        """
        Checks if any of the network keys has an NID matching with one in the packet
        If yes, returns it

        :param net_pdu: [TODO:description]
        :type net_pdu: [TODO:type]
        :returns: The network key of the matching key, None if no match
        :rtype: NetworkLayerCryptoManager|None, Int
        """
        if net_pdu.nid in self.state.mf_nid_to_net_key_id.keys():
            key_id = self.state.mf_nid_to_net_key_id[net_pdu.nid]
            key = self.state.profile.get_net_key(key_id)

            # Recheck in case key got updated ...
            if key.nid_mf == net_pdu.nid:
                return key

        if net_pdu.nid in self.state.df_nid_to_net_key_id.keys():
            key_id = self.state.df_nid_to_net_key_id[net_pdu.nid]
            key = self.state.profile.get_net_key(key_id)

            # Recheck in case key got updated ...
            if key.nid_df == net_pdu.nid:
                return key

        return None

    def __check_address_validity(self, src_addr, dst_addr, network_ctl):
        """
        Verifies the src_addr and dst_addr under the critierias defined in
        Mesh Spec Section 3.4.3. Does not check against Access layer key type criterias here.
        Returns the type of the Address if compliant, or None if not.

        :param src_addr: The source address in the network PDU
        :type src_addr: int
        :param dst_addr: The destination address in the network PDU (after decryption)
        :type dst_addr: int
        :param network_ctl: value of the network_ctl flag in the Network PDU
        :type network_ctl: int
        :returns: Address type if address ok, None otherwise
        :rtype:  int | None
        """
        src_type = get_address_type(src_addr)
        if src_type != UNICAST_ADDR_TYPE or self.state.profile.is_unicast_addr_ours(
            src_addr
        ):
            return None

        dst_type = get_address_type(dst_addr)
        if dst_type == UNASSIGNED_ADDR_TYPE:
            return None
        # I know dumb condition, but better for clarity, but some weird stuff in specification, keep myself accountable
        if dst_type == VIRTUAL_ADDR_TYPE:
            return VIRTUAL_ADDR_TYPE  # Modified because inconcistency in Specification (Direct Forwarding may need dst_field VIRTUAL in ctl msg, hence dont check network_ctl)
        if dst_type == GROUP_ADDR_TYPE:
            return GROUP_ADDR_TYPE

        # Address is UNICAST_ADDR_TYPE
        return UNICAST_ADDR_TYPE

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
        self.send("lower_transport", (lower_transport_pdu, msg_ctx))

    def relay_packet(self, deobf_net_pdu, dst_addr, net_key):
        """
        Relays a received PDU if relay is enabled

        :param deobf_net_pdu: Deobfucated packet
        :type deobf_net_pdu: BTMesh_Network_PDU
        :param dst_addr: Destination addr of the packet
        :type dst_addr: int
        :param net_key: Network Key used to (de)obfuscate the packet
        :type net_key: NetworkLayerCryptoManager
        """
        # Check if unicast addr is not ours
        if self.state.profile.is_unicast_addr_ours(dst_addr):
            return

        # Check TTL > 1
        if deobf_net_pdu.ttl < 2:
            return

        # Only relay if MF for now
        if deobf_net_pdu.nid != net_key.nid_mf:
            return

        deobf_net_pdu.ttl -= 1

        # obfuscate the payload
        obfu_data = net_key.obfuscate_net_pdu(
            deobf_net_pdu, self.state.profile.iv_index
        )

        pkt = BTMesh_Obfuscated_Network_PDU(
            ivi=deobf_net_pdu.ivi,
            nid=deobf_net_pdu.nid,
            obfuscated_data=obfu_data,
            enc_dst_enc_transport_pdu_mic=deobf_net_pdu.enc_dst_enc_transport_pdu_mic,
        )
        thread = Thread(target=self.sending_thread, args=EIR_Hdr(type=0x2A) / pkt)
        thread.start()

    def on_net_pdu_received(self, net_pdu, rssi):
        """
        Connector received a network pdu on the bearer

        :param net_pdu: The received network PDU
        :type net_pdu: BTMesh_Obfuscated_Network_PDU
        :param rssi:  The received PDU rssi
        :type rssi: int
        """
        # check if any network key matches the NID in the packet
        net_key = self.__check_nid(net_pdu)
        if net_key is None:
            self.update_net_keys()

        net_key = self.__check_nid(net_pdu)
        if net_key is None:
            return

        # Deobfucate the packet and reconstruct it
        raw_deobf_net_pdu = net_key.deobfuscate_net_pdu(
            net_pdu, self.state.profile.iv_index
        )

        network_ctl = (raw_deobf_net_pdu[0]) >> 7
        ttl = raw_deobf_net_pdu[0] & 0x7F
        seq_number = int.from_bytes(raw_deobf_net_pdu[1:4], "big")
        src_addr = int.from_bytes(raw_deobf_net_pdu[4:6], "big")

        deobf_net_pdu = BTMesh_Network_PDU(
            ivi=self.state.profile.iv_index[0] & 0b01,
            nid=net_pdu.nid,
            network_ctl=network_ctl,
            ttl=ttl,
            seq_number=seq_number,
            src_addr=src_addr,
            enc_dst_enc_transport_pdu_mic=net_pdu.enc_dst_enc_transport_pdu_mic,
        )

        # check if message in network cache. Mesh Spec section 3.4.5.6
        is_pdu_in_cache = self.__cache_verif(deobf_net_pdu)
        if is_pdu_in_cache:
            logger.debug("PDU Already received in Network Layer Cache, dropping")
            return

        # decrypt the encrypted Lower Transport PDU
        plaintext, is_auth_valid = net_key.decrypt(
            deobf_net_pdu, self.state.profile.iv_index
        )
        if not is_auth_valid:
            logger.debug(
                "Received Network PDU with wrong authentication value, dropping"
            )
            return

        # check address validity. Mesh Spec Section 3.4.3
        dst_addr = int.from_bytes(plaintext[:2], "big")
        addr_type = self.__check_address_validity(src_addr, dst_addr, network_ctl)
        if addr_type is None:
            logger.debug("Received Network PDU with non compliant addr types, dropping")
            return

        # If relay enabled, try to relay packet (if applicable)
        if self.state.profile.local_node.is_relay:
            self.relay_packet(deobf_net_pdu, dst_addr, addr_type, net_key)

        # Check if addr should be processed by our device
        if not self.state.profile.is_addr_ours(dst_addr, addr_type):
            return False

        # Process the packet if we are a target of the message
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
        msg_ctx.net_key_id = net_key.key_index
        msg_ctx.ttl = ttl
        msg_ctx.is_ctl = network_ctl == 1
        msg_ctx.rssi = rssi

        # based on nid value, get the credentials used
        if deobf_net_pdu.nid == net_key.nid_mf:
            msg_ctx.creds = MANAGED_FLOODING_CREDS
        elif deobf_net_pdu.nid == net_key.nid_df:
            msg_ctx.creds = DIRECTED_FORWARDING_CREDS

        self.send_to_lower_transport(msg_ctx, lower_transport_pdu)

    # WIP
    def send_secure_network_beacon(self, key_refresh, iv_update):
        """
        Sends a secure network beacon to the network with the given arguments

        :param key_refresh: Key refresh flag
        :type key_refresh: int
        :param iv_update: IV update flag
        :type iv_update: int
        """

        net_key = self.state.profile.get_net_key(0)

        message = BTMesh_Secure_Network_Beacon(
            iv_update_flag=iv_update,
            key_refresh_flag=key_refresh,
            nid=net_key.network_id,
            ivi=self.state.profile.iv_index[0] & 0b1,
        )

        message.authentication_value = net_key.compute_secure_beacon_auth_value(message)
        thread = Thread(
            target=self.sending_thread,
            args=EIR_Hdr(type=0x2B)
            / EIR_BTMesh_Beacon(mesh_beacon_type=0x01, secure_beacon_data=message),
        )
        thread.start()

    @source("lower_transport")
    def on_lower_transport_packet(self, message):
        """
        Callback for Lower Transport Packet sent by the Lower Transport Layer.

        :param message: Lower Transport PDU and its context
        :type message: (BTMesh_Lower_Transport_Access_Message|BTMesh_Lower_Transport_Control_Message, MeshMessageContext)
        """
        pkt, ctx = message

        # if custom handler, use and return
        if type(pkt) in self._custom_handlers:
            continue_processing = self._custom_handlers[type(pkt)](message)
            # if custom handler says to return after itself
            if not continue_processing:
                return

        net_key = self.state.profile.get_net_key(ctx.net_key_id)

        # get the correct nid based on credentials used
        if ctx.creds == MANAGED_FLOODING_CREDS:
            nid = net_key.nid_mf
        elif ctx.creds == DIRECTED_FORWARDING_CREDS:
            nid = net_key.nid_df

        net_pdu = BTMesh_Network_PDU(
            ivi=self.state.profile.iv_index[0] & 1,
            nid=nid,
            network_ctl=int(ctx.is_ctl),
            ttl=ctx.ttl,
            seq_number=ctx.seq_number,
            src_addr=ctx.src_addr,
        )

        # encrypt the message
        enc = net_key.encrypt(
            raw(pkt),
            ctx.dest_addr,
            net_pdu,
            self.state.profile.iv_index,
        )

        net_pdu.enc_dst_enc_transport_pdu_mic = enc

        # obfuscate the payload
        obfu_data = net_key.obfuscate_net_pdu(net_pdu, self.state.profile.iv_index)

        pkt = BTMesh_Obfuscated_Network_PDU(
            ivi=net_pdu.ivi,
            nid=net_pdu.nid,
            obfuscated_data=obfu_data,
            enc_dst_enc_transport_pdu_mic=enc,
        )
        thread = Thread(target=self.sending_thread, args=EIR_Hdr(type=0x2A) / pkt)
        thread.start()

        """
        if smallest_seq_num == self.state.next_seq_to_send:
            self.state.next_seq_to_send += 1
        """

    def sending_thread(self, pkt):
        self.__connector.send_raw(pkt)


NetworkLayer.add(LowerTransportLayer)
