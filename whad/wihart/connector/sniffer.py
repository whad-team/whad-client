import logging
from typing import Generator
from time import time

from scapy.packet import Packet
from whad.scapy.layers.wirelesshart import WirelessHart_Network_Security_SubLayer_Hdr, \
    WirelessHart_DataLink_Advertisement, WirelessHart_Transport_Layer_Hdr, \
    WirelessHart_Add_Link_Response, WirelessHart_Add_Link_Request, \
    WirelessHart_DataLink_Acknowledgement, WirelessHart_DataLink_Advertisement, WirelessHart_DataLink_Hdr, WirelessHart_Disconnect_Device_Request, WirelessHart_Network_Hdr, WirelessHart_Network_Security_SubLayer_Hdr, WirelessHart_Suspend_Devices_Request, WirelessHart_Suspend_Devices_Response, WirelessHart_Transport_Layer_Hdr, WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request, WirelessHart_Vendor_Specific_Dust_Networks_Ping_Response,  WirelessHart_Write_Modify_Session_Command_Request, WirelessHart_Command_Request_Hdr
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4FCS
from whad.wihart.connector import WirelessHart
from whad.wihart.sniffing import SnifferConfiguration, TimeSynchronizationEvent, \
    NewLinkEvent, NewSuperframeEvent, NewSessionKeyEvent, NewNetworkKeyEvent

from whad.wihart.crypto import WirelessHartDecryptor, WirelessHartNetworkKeyExtractor,\
    WirelessHartSessionKeyExtractor, \
        compute_dlmic, WirelessHartNetworkLayerCryptoManager
from whad.wihart.exceptions import MissingCryptographicMaterial
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter, is_message_type
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived, RawPduReceivedV3, PduReceivedV3, \
    LinkOptions, LinkType
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected



logger = logging.getLogger(__name__)

class Sniffer(WirelessHart, EventsManager):
    """
    Wireless Hart Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device, configuration=SnifferConfiguration()):
        WirelessHart.__init__(self, device)
        EventsManager.__init__(self)


        self.__configuration = configuration
        self.__decryptor = WirelessHartDecryptor()
        
        self.__network_key_extractor = WirelessHartNetworkKeyExtractor()
        self.__session_key_extractor = WirelessHartSessionKeyExtractor()

        self._synchronized = False

        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _provision_keys_from_configuration(self):
        if self.__configuration.join_key is not None:
            self.__decryptor.set_join_key(self.__configuration.join_key)

        if self.__configuration.network_key is not None:
            self.__decryptor.set_network_key(self.__configuration.network_key)

        for ext_key in self.__configuration.broadcast_session_keys:
            self.__decryptor.add_broadcast_extended_session_key(ext_key)

        for ext_key in self.__configuration.unicast_session_keys:
            self.__decryptor.add_unicast_extended_session_key(ext_key)
        
        
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
        first_route_segment: list = None
    ) -> Packet:

        current_asn = self.network.asn
        
        if force_next_sf:
            asn_to_send = current_asn + asn_offset
        else:
            asn_to_send = current_asn

        if is_broadcast_crypto:
            key = self.__decryptor.get_broadcast_session_key(0xf980, 0xffff)
            peer = self.__decryptor.get_broadcast_peer(0xf980, 0xffff)
            target_nwk_dst = 0xffff
            nonce_counter = (peer.get_nonce_counter() + 1) % 256 if peer else 1
        else:
            target_nwk_dst = nwk_dest_addr if nwk_dest_addr is not None else dst
            key = self.__decryptor.get_unicast_session_key(0xf980, dst)
            peer = self.__decryptor.get_unicast_peer(0xf980, dst)
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
            asn_snippet=(asn_to_send % 0xffff),
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
        dl_mic = compute_dlmic(packet, self.__decryptor.get_network_key(), asn_to_send)
        data_link_layer.mic = int.from_bytes(dl_mic)
        
        final_packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer / enciphered

        self.send_in_slot(final_packet, asn_to_send)
        return final_packet

    def ping_request(self, dst: int, spoofed_src: int = 0x0001, graph: int = 0x0001):
        req = WirelessHart_Command_Request_Hdr(command_number=0xfc04, len=4) / \
              WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request(expanded_device_type=0xe0a2, hops=1)
        return self._send_wihart_frame(
            dst=dst, commands=[req], spoofed_src=spoofed_src, graph=graph,
            link_type=LinkType.BROADCAST, link_options=LinkOptions.RECEIVE, asn_offset=200
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


    def _enable_sniffing(self):
        self._provision_keys_from_configuration()        
        self.enable_tsch()
        self.sniff_wihart(channel=self.__configuration.channel)
        
    
    @property
    def decryptor(self):
        return self.__decryptor

    def add_join_key(self, key):
        self.__configuration.join_key = key
        self._provision_keys_from_configuration()

    def add_network_key(self, key):
        self.trigger_event(
            NewNetworkKeyEvent(key)
        )
        self.__configuration.network_key = key
        self._provision_keys_from_configuration()

    def add_unicast_session_key(self, key, source, destination=0x0001, nonce=1):
        self.trigger_event(
            NewSessionKeyEvent(session_key=key, source=source, destination=destination, nonce=nonce, key_type="unicast")
        )
        
        skey = key 
        if isinstance(key, bytes) and len(key) == 16:
            skey = key.hex()
        
        self.__configuration.unicast_session_keys.append(
            str(source) + "," +
            str(destination) + "," +
            skey + "," +
            str(nonce)   
        )

    def add_broadcast_session_key(self, key, source, destination=0xFFFF, nonce=1):
        self.trigger_event(
            NewSessionKeyEvent(session_key=key, source=source, destination=destination, nonce=nonce, key_type="broadcast")
        )
        skey = key 
        if isinstance(key, bytes) and len(key) == 16:
            skey = key.hex()
        
        self.__configuration.broadcast_session_keys.append(
            str(source) + "," +
            str(destination) + "," +
            skey + "," +
            str(nonce)   
        )

    def clear_session_keys(self):
        self.__configuration.unicast_session_keys = []
        self.__configuration.broadcast_session_keys = []

    @property
    def decrypt(self):
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt):
        self.__configuration.decrypt = decrypt


    @property
    def channel(self):
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel=15):
        #self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    @property
    def configuration(self):
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        #self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()

    def process_commands(self, packet):
        self.__session_key_extractor.process_packet(packet)

        new_key_discovered = False
        while self.__session_key_extractor.completed:
            output = self.__session_key_extractor.output
            if output["type"] == "unicast":
                self.add_unicast_session_key(output["key"], output["source"], output["destination"], output["nonce"])
            elif output["type"] == "broadcast":
                self.add_broadcast_session_key(output["key"], output["source"], output["destination"], output["nonce"])
            
            new_key_discovered = True
            self.__session_key_extractor.reset()
            self.__session_key_extractor.process_packet(packet)
            
        self.__network_key_extractor.process_packet(packet)
        if self.__network_key_extractor.completed:
            output = self.__network_key_extractor.output
            self.add_network_key(output["key"])
            new_key_discovered = True
            self.__network_key_extractor.reset()

        if new_key_discovered:
            self._provision_keys_from_configuration()

        if WirelessHart_Transport_Layer_Hdr not in packet:
            return

        for cmd in packet.getlayer(WirelessHart_Transport_Layer_Hdr).commands:
            if WirelessHart_Add_Link_Response in cmd:
                c = cmd[WirelessHart_Add_Link_Response]
                if c.status == 0:
                    #print(f"add link response src = {packet.src_addr}, neighbor = {c.neighbor_nickname}")
                    self.add_link(
                        superframe_id=c.superframe_id, 
                        source=packet.src_addr,
                        time_slot=c.slot_number,
                        channel_offset=c.channel_offset, 
                        neighbor=c.neighbor_nickname if c.link_type==LinkType.NORMAL else 0xffff,
                        options=LinkOptions.TRANSMIT if c.transmit else LinkOptions.RECEIVE if c.receive else LinkOptions.SHARED, 
                        link_type=c.link_type
                    )

            if WirelessHart_Add_Link_Request in cmd:
                c = cmd[WirelessHart_Add_Link_Request]
                #print(f"add link request src = {packet.nwk_dest_addr}, neighbor = {c.neighbor_nickname}")
                self.add_link(
                    superframe_id=c.superframe_id, 
                    source=packet.nwk_dest_addr,
                    time_slot=c.slot_number,
                    channel_offset=c.channel_offset, 
                    neighbor=c.neighbor_nickname if c.link_type==LinkType.NORMAL else 0xffff, 
                    options=LinkOptions.TRANSMIT if c.transmit else LinkOptions.RECEIVE if c.receive else LinkOptions.SHARED, 
                    link_type=c.link_type
                )

    def update_superframe(self, superframe_id, number_of_slots, flags=0, asn=0):
        self.trigger_event(
            NewSuperframeEvent(
                superframe_id=superframe_id,
                number_of_slots=number_of_slots, 
                flags=flags,
                asn=asn
            )
        )
        return super().update_superframe(superframe_id, number_of_slots, flags, asn)

    def add_link(self, superframe_id, source, time_slot, channel_offset, neighbor, options, link_type):
        self.trigger_event(
            NewLinkEvent(
                    superframe_id,
                    source,
                    time_slot,
                    channel_offset,
                    neighbor,
                    options,
                    link_type
            )
        )
        return super().add_link(superframe_id, source, time_slot, channel_offset, neighbor, options, link_type)

    def process_packet(self, packet: Packet):
        """Process received Wireless Hart packet.

        :param packet: received packet
        :type packet: :class:`scapy.packet.Packet`
        :return: received packet
        :rtype: :class:`scapy.packet.Packet`
        """
        #print("offset:", packet.metadata.timestamp - packet.metadata.start_of_slot_timestamp)
        if hasattr(packet.metadata, "asn") and self.network is not None:
            self.network.asn = packet.metadata.asn
            
        if WirelessHart_Network_Security_SubLayer_Hdr in packet and self.__configuration.decrypt:
            try:
                decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
                if success:
                    packet.metadata.decrypted = True
                    metadata = packet.metadata
                    packet = decrypted
                    packet.metadata = metadata
                    self.process_commands(packet)
                    
                    
            except MissingCryptographicMaterial:
                pass

        elif WirelessHart_DataLink_Advertisement in packet:
            if not self._synchronized:
                adv = packet[WirelessHart_DataLink_Advertisement]
                
                if self.network is not None:
                    self.network.panid = packet.dest_panid

                self.trigger_event(TimeSynchronizationEvent(asn=packet.asn))
                
                try:
                    self.set_channel_map(adv.channel_map)
                    
                    probable_offset = 0
                    smallest_superframe = None

                    for superframe in adv.superframes:

                        if smallest_superframe is None:
                            smallest_superframe = (superframe.superframe_id, superframe.superframe_number_of_slots)
                        elif superframe.superframe_number_of_slots < smallest_superframe[1]:
                            smallest_superframe = (superframe.superframe_id, superframe.superframe_number_of_slots)

                        self.update_superframe(
                            superframe_id=superframe.superframe_id,
                            number_of_slots=superframe.superframe_number_of_slots, 
                            flags=0,
                            asn=0
                        )
                        for link in superframe.superframe_links:
                            if smallest_superframe is not None and smallest_superframe[0] == superframe.superframe_id:
                                probable_offset = link.link_channel_offset

                            self.add_link(
                                superframe_id=superframe.superframe_id, 
                                source=packet.src_addr if hasattr(packet, 'src_addr') else 0x0001,
                                time_slot=link.link_join_slot,
                                channel_offset=link.link_channel_offset,
                                neighbor=0xFFFF,
                                options=LinkOptions.RECEIVE,
                                link_type=LinkType.JOIN
                            )
                    
                    if smallest_superframe is not None:
                        self.add_link(
                            superframe_id=smallest_superframe[0],               
                            source=0x0001,           
                            time_slot=0,                   
                            channel_offset=probable_offset,              
                            neighbor=0xFFFF,               
                            options=LinkOptions.RECEIVE,   
                            link_type=LinkType.DISCOVERY   
                        )
                    
                
                    self._synchronized = True

                except Exception as e:
                    logger.error(f"Error during Wireless Hart network synchronization: {e}")

        if self.__configuration.hide_adv and WirelessHart_DataLink_Advertisement in packet and self._synchronized:
            return None

        return packet
        
    def sniff(self, timeout: float = None) -> Generator[Packet, None, None]:
        """Sniff Wireless Hart packets out of thin air.

        :param timeout: Number of seconds after which sniffing will stop. Wait
                        forever if set to `None`.
        :type timeout: float
        """
        
        if self.support_raw_pdu():
            message_type = (RawPduReceived, RawPduReceivedV3)
        else:
            message_type = (PduReceived, PduReceivedV3)

        try:
            for message in super().capture(messages=(message_type), timeout=timeout):
                if message is not None:
                    packet = message.to_packet()
                    print("Time offset:", packet.metadata.timestamp - packet.metadata.start_of_slot_timestamp)

                    if self.__configuration.hide_adv and WirelessHart_DataLink_Advertisement in packet and self._synchronized:
                        continue

                    if packet is not None:
                            
                        packet = self.process_packet(packet)
                        if packet is not None:
                            self.monitor_packet_rx(packet)
                            yield packet
                        

        except WhadDeviceDisconnected:
            return
