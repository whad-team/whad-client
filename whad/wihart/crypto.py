from scapy.packet import Raw
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Hdr, \
    WirelessHart_Network_Hdr, WirelessHart_Network_Security_SubLayer_Hdr, \
    WirelessHart_Transport_Layer_Hdr, WirelessHart_Write_Device_Nickname_Request, \
    WirelessHart_Write_Network_Key_Request, WirelessHart_Write_Network_Key_Response, \
    WirelessHart_Write_Modify_Session_Command_Response, WirelessHart_Write_Modify_Session_Command_Request
from whad.wihart.exceptions import MissingSecurityHeader, \
    MissingCryptographicMaterial, MissingSecurityFlag
from whad.common.analyzer import TrafficAnalyzer
from Cryptodome.Cipher import AES
from typing import Union, Tuple
from struct import pack
from copy import copy
from scapy.config import conf

conf.dot15d4_protocol = "wihart"



def compute_dlmic(pkt, key, asn):
    data = bytes(pkt)[:-6]
    nonce  = pack('>Q', asn)[-5:] + pack('>Q', pkt.src_addr)

    cipher = AES.new(key, AES.MODE_CCM, nonce=nonce, mac_len=4)
    cipher.update(data) # not encrypted but authenticated : full DLPDU (from 0x41 to the end of payload - just before MIC and empty encryption data)
    X1= cipher.encrypt(b"")
    tag = cipher.digest()
    return tag
    

class WirelessHartNetworkLayerCryptoManager:
    def __init__(self, key):
        self.key = key
        self.nonce = None
        self.auth = None

    def generateNonce(self, pkt):
        if pkt.security_types == 1:
            if pkt.nwk_src_addr == 0xf980:
                addr = pkt.nwk_dest_addr
                start_byte = b"\x01"
            else:
                addr = pkt.nwk_src_addr
                start_byte = b"\x00"
            nonce = start_byte + pack('>I', pkt.counter) + pack('>Q', addr)

        else:
            addr = pkt.nwk_src_addr
            start_byte = b"\x00"
            counter = pkt.counter
            '''
            if pkt.nwk_mic == 0x5e1e025c:
                counter = (((3 + 128 - pkt.counter) & 0xFFFFFF) << 8) | pkt.counter
            '''
            nonce = start_byte + pack('>I', counter) + pack('>Q', addr)

        return nonce
    
    def generateAuth(self, pkt):
        encrypted_pkt = copy(pkt)
        encrypted_pkt.counter = 0
        encrypted_pkt.ttl = 0
        encrypted_pkt.nwk_mic = 0
        
        auth = bytes(encrypted_pkt[WirelessHart_Network_Hdr])
        encrypted_payload = bytes(encrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr][1:])
        auth = auth[:len(auth) - len(encrypted_payload)]

        return auth

    def extractCiphertextPayload(self, pkt):
        mic = pack(">I", pkt.nwk_mic)

        encrypted_pkt = copy(pkt)
        encrypted_pkt.counter = 0
        encrypted_pkt.ttl = 0
        encrypted_pkt.nwk_mic = 0

        encrypted_payload = bytes(encrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr][1:])
        
        return encrypted_payload, mic

    def decrypt(self, packet):
        metadata = packet.metadata
        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4FCS(packet)

        # raise MissingSecurityHeader exception if no security header is found
        if WirelessHart_Network_Security_SubLayer_Hdr not in packet:
            raise MissingSecurityHeader()

        # generate the nonce
        self.nonce = self.generateNonce(packet)

        # generate the AES-CCM parameters
        self.auth = self.generateAuth(packet)
        ciphertext, mic = self.extractCiphertextPayload(packet)

        # Perform the decryption and integrity check
        cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=4)
        cipher.update(self.auth)

        try:
            cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=4)
            cipher.update(self.auth)
            decrypted = cipher.decrypt_and_verify(ciphertext, received_mac_tag=mic)
            #del packet[Raw]
            decrypted_pkt = packet.copy()
            decrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr].security_types = 15            
            decrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr].remove_payload()
            decrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr].add_payload(decrypted)
            #decrypted_pkt.do_build()
            decrypted_pkt.metadata = metadata
            
            decrypted_pkt.metadata.decrypted = True
            return (decrypted_pkt, True)

        except ValueError as e:
            #print("error!", e)
            packet.metadata = metadata
            return (packet, False)
        
    def encrypt(self, plaintext, associated_data=None):
        cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=4)
        if associated_data: 
            cipher.update(associated_data)
        if plaintext=="":
            return "", cipher.digest()
        return cipher.encrypt_and_digest(plaintext)
        
class Peer:
    def __init__(self, id1, id2, nonce_counter = 0x1):
        self._id1 = id1
        self._id2 = id2
        self._nonce = nonce_counter
    
    def __eq__(self, other):
        return ( isinstance(other, Peer)
            and (
                    (
                        self._id1 == other._id1 and self._id2 == other._id2)
                        or (self._id1 == other._id2 and self._id2 == other._id1)
                )
        )

    def __hash__(self):
        return hash(tuple(sorted((self._id1, self._id2))))

    def get_nonce_counter(self):
        return self._nonce
    
    def set_nonce_counter(self, nonce):
        self._nonce = nonce & 0xFFFFFFFF
        
    def set_short_nonce_counter(self, counter):
        self._nonce = (self._nonce & 0xffffff00) | counter
        
    def increment_nonce(self):
        self.set_nonce_counter(self.get_nonce_counter()+1)
    
    def __repr__(self):
        return f"id1={self._id1}, id2={self._id2}, nonce={self._nonce}"

class WirelessHartDecryptor:

    def __init__(self, *keys):
        self.__join_key = bytes.fromhex("7777772e68617274636f6d6d2e6f7267") #known join key : "www.hartcomm.org"
        self.__network_key = None
        self.__unicast_sessions_keys = {}
        self.__broadcast_sessions_keys = {}
        self.__join_sessions_keys = {}

    def __repr__(self):
        repr_str = ["<WirelessHartDecryptor>"]

        repr_str.append(f"  Join Key       : {self.__join_key}")
        repr_str.append(f"  Network Key    : {self.__network_key}")

        repr_str.append("  Unicast Sessions Keys:")
        if self.__unicast_sessions_keys:
            for peer, key in self.__unicast_sessions_keys.items():
                repr_str.append(f"    {peer} -> {key}")
        else:
            repr_str.append("    (empty)")

        repr_str.append("  Broadcast Sessions Keys:")
        if self.__broadcast_sessions_keys:
            for peer, key in self.__broadcast_sessions_keys.items():
                repr_str.append(f"    {peer} -> {key}")
        else:
            repr_str.append("    (empty)")

        repr_str.append("  Join Sessions Keys:")
        if self.__join_sessions_keys:
            for peer, key in self.__join_sessions_keys.items():
                repr_str.append(f"    {peer} -> {key}")
        else:
            repr_str.append("    (empty)")

        return "\n".join(repr_str)

    def set_join_key(self, key):
        key = self.parse_key(key)
        if key:
            self.__join_key = key

    
    def set_network_key(self, key):
        key = self.parse_key(key)
        if key:
            self.__network_key = key
        
    def get_network_key(self):
        return self.__network_key
    
    def add_unicast_extended_session_key(self, extended_key):
        source, dest, key, nonce = self.parse_extended_key(extended_key)
        peer = Peer(source,dest, nonce)
        self.add_unicast_session_key(peer, key)


    def add_broadcast_extended_session_key(self, extended_key):
        source, dest, key, nonce = self.parse_extended_key(extended_key)
        peer = Peer(source, dest, nonce)
        self.add_broadcast_session_key(peer, key)

    def add_unicast_session_key(self, peer, key):
        key = self.parse_key(key)
        if key:
            self.__unicast_sessions_keys[peer] = key
    
    def add_broadcast_session_key(self, peer, key):
        key = self.parse_key(key)
        if key:
            self.__broadcast_sessions_keys[peer] = key
     
    def add_join_session_key(self, peer, key):
        key = self.parse_key(key)
        if key:
            self.__join_sessions_keys[peer] = key   
        
    def get_unicast_session_key(self, id1, id2):
        return self.__unicast_sessions_keys.get(Peer(id1, id2))
    
    def get_broadcast_session_key(self, id1, id2):
        return self.__broadcast_sessions_keys.get(Peer(id1, id2))
    
    def get_join_session_key(self, id1, id2):
        return self.__join_sessions_keys.get(Peer(id1, id2))
    
    def get_unicast_peer(self, id1, id2)->Peer:
        for peer in self.__unicast_sessions_keys.keys():
            if peer == Peer(id1,id2):
                return peer
        return None

    def get_broadcast_peer(self, id1, id2)->Peer:
        for peer in self.__broadcast_sessions_keys.keys():
            if peer == Peer(id1,id2):
                return peer
        return None
    
    def get_join_peer(self, id1, id2)->Peer:
        for peer in self.__join_sessions_keys.keys():
            if peer == Peer(id1,id2):
                return peer
        return None
            
    def parse_extended_key(self, key:str) -> Tuple[int, int, bytes, int]:
        if not isinstance(key, str) or "," not in key:
            return None

        extended_format = key.split(",")
        if len(extended_format) == 3:
            if extended_format[0].startswith("0x"):
                source = int(extended_format[0], 16)
            else:
                source = int(extended_format[0])


            if extended_format[1].startswith("0x"):
                dest = int(extended_format[1], 16)
            else:
                dest = int(extended_format[1])


            key_bytes = bytes.fromhex(extended_format[2].replace(":", ""))
            nonce = 1
            return (source, dest, key_bytes, nonce)

        elif len(extended_format) == 4:
            
            if extended_format[0].startswith("0x"):
                source = int(extended_format[0], 16)
            else:
                source = int(extended_format[0])


            if extended_format[1].startswith("0x"):
                dest = int(extended_format[1], 16)
            else:
                dest = int(extended_format[1])


            key_bytes = bytes.fromhex(extended_format[2].replace(":", ""))
            
            if extended_format[3].startswith("0x"):
                nonce = int(extended_format[3], 16)
            else:
                nonce = int(extended_format[3])
            return (source, dest, key_bytes, nonce)

        return None

    def parse_key(self, key)->bytes:
        if isinstance(key, str):
            if len(key) == 16:
                key = key.encode('ascii')
            else:
                try:
                    key = bytes.fromhex(key.replace(":",""))
                except ValueError:
                    return None
        if not isinstance(key, bytes) or len(key) != 16:
            return None
        return key
    
    def extract_keys(self, packet):
        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4FCS(packet)
        
        key = None
        transport_layer = packet.getlayer(WirelessHart_Transport_Layer_Hdr)
        
        if transport_layer is not None:
            for cmd in transport_layer.commands:
                if WirelessHart_Write_Network_Key_Request in cmd:
                    c = cmd[WirelessHart_Write_Network_Key_Request]
                    self.set_network_key(c.key_value)
                    
                #if WirelessHart_Write_Modify_Session_Command_Response or WirelessHart_Write_Modify_Session_Command_request in c:
                if cmd.command_number == 0x3c3:
                    c = cmd
                    if packet.response == 0:
                        id_1 = packet.nwk_dest_addr
                    else : 
                        id_1 = packet.nwk_src_addr
                        
                    peer = Peer(c.nickname, id_1)
                    #print("add key :"+ self.parse_key(c.key_value).hex()+"graph:"+hex(packet.graph_id))
                    match c.session_type:
                        case 0x0: #unicast
                            if packet.nwk_dest_addr_length == 0x0 and packet.nwk_src_addr_length == 0x0 : #short adress
                                self.add_unicast_session_key(peer, c.key_value)
                                peer = self.get_unicast_peer(c.nickname, packet.nwk_dest_addr)
                            else:
                                key = c.key_value
                                id_2 = c.nickname
                                nonce = c.peer_nonce_counter_value
                        case 0x1: #broadcast
                            peer = Peer(0xffff, c.nickname)
                            self.add_broadcast_session_key(peer, c.key_value)
                            peer = self.get_broadcast_peer(c.nickname, packet.nwk_dest_addr)
                        case 2: #join
                                self.add_join_session_key(peer, c.key_value)
                                peer = self.get_join_peer(c.nickname, packet.nwk_dest_addr) 
                    
                #if WirelessHart_Write_Device_Nickname_Request in c:
                if hasattr(cmd, "command_number"):
                    if cmd.command_number == 0x3C2:
                        if key:
                            self.add_unicast_session_key(Peer(cmd.nickname, id_2, nonce), key)
                else:
                    peer.set_nonce_counter(c.peer_nonce_counter_value)
            
    def attempt_to_decrypt(self, packet):
        """attempts to decrypt pkt by using the join key if pkt is join keyed encrypted else by using each 
        of the unicast, broadcast ans join session keys corresponding to src and dest network addresses"""
        if WirelessHart_Network_Security_SubLayer_Hdr not in packet:
            raise MissingSecurityHeader()

        communications = [] #list of (Peer, key)
        if packet.security_types == 0 : #session keyed

            communications.append((self.get_unicast_peer(packet.nwk_src_addr, packet.nwk_dest_addr), self.get_unicast_session_key(packet.nwk_src_addr, packet.nwk_dest_addr)))
            communications.append((self.get_unicast_peer(0x0001, packet.nwk_dest_addr), self.get_unicast_session_key(0x0001, packet.nwk_dest_addr)))
            communications.append((self.get_unicast_peer(packet.nwk_src_addr, 0x0001), self.get_unicast_session_key(packet.nwk_src_addr, 0x0001)))
            communications.append((self.get_broadcast_peer(0xffff, packet.nwk_src_addr), self.get_broadcast_session_key(0xffff, packet.nwk_src_addr)))
            communications.append((self.get_broadcast_peer(packet.nwk_src_addr, 0xffff), self.get_broadcast_session_key(packet.nwk_src_addr, 0xffff)))
            communications.append((self.get_join_peer(packet.nwk_src_addr, packet.nwk_dest_addr), self.get_join_session_key(packet.nwk_src_addr, packet.nwk_dest_addr)))            
        elif packet.security_types == 1 : #join keyed
            communications = [(None, self.__join_key)]
        elif packet.security_types == 15: #already decrypted
            return packet, True

        for (peer, key) in communications:
            
            if key:
                manager = WirelessHartNetworkLayerCryptoManager(key)
                decrypted, success = manager.decrypt(packet)
                if success:
                    decrypted = Dot15d4FCS(bytes(decrypted)) 
                    if peer:
                        peer.set_short_nonce_counter(packet.counter)
                    #self.extract_keys(decrypted)
                    return decrypted, True
        '''
        # one key seems to be missing, check what is not correctly decrypted here
        print("Decryption failed !!")
        print("pkt:", bytes(packet).hex())
        print(f"tried keys:{communications}")
        '''
        #packet.show()
        #exit()
        return packet, False

class WirelessHartNetworkKeyExtractor(TrafficAnalyzer):
    """
    Traffic analyser for Wireless Hart Network Key
    """
    _cache = []

    def reset(self):
        super().reset()
        self._network_key = None
            
    @property
    def output(self):
        return {
            "key": self._network_key
        }

    def process_packet(self, packet: Union[Dot15d4, Dot15d4FCS, bytes]):
        if isinstance(packet, bytes):
            packet = Dot15d4FCS(packet)

        pkt = packet.decrypted if hasattr(packet, "decrypted") and packet.decrypted is not None else packet
        transport_layer = pkt.getlayer(WirelessHart_Transport_Layer_Hdr)
        if transport_layer is None:
            return

        for cmd in transport_layer.commands:
            if WirelessHart_Write_Network_Key_Request in cmd and cmd.key_value not in self.__class__._cache:
                self.trigger()
                self.mark_packet(packet)
                self._network_key = cmd[WirelessHart_Write_Network_Key_Request].key_value
                self.__class__._cache.append(cmd.key_value)
                self.complete()

class WirelessHartSessionKeyExtractor(TrafficAnalyzer):
    """
    Traffic analyser for Wireless Hart Session Key
    """
    _cache = {}

    def reset(self):
        super().reset()
        self._key_type = None
        self._key = None
        self._source = None
        self._destination = None
        self._nonce_counter = None

    @property
    def output(self):
        return {
            "type": self._key_type, 
            "key": self._key,
            "source": self._source,
            "destination": self._destination,
            "nonce": self._nonce_counter
        }
    '''
    def process_packet(self, packet: Packet):
        if isinstance(packet, bytes):
            packet = Dot15d4FCS(packet)

        pkt = packet.decrypted if hasattr(packet, "decrypted") and packet.decrypted is not None else packet
        transport_layer = pkt.getlayer(WirelessHart_Transport_Layer_Hdr)

        if transport_layer is None:
            return

        for cmd in transport_layer.commands:

            if hasattr(cmd, "command_number") and cmd.command_number == 0x3c3:
                source = None
                destination = None

                source = cmd.nickname 

                if cmd.session_type == 0x0:
                    key_type = "unicast" 

                    if pkt.nwk_src_addr == source:
                        destination = pkt.parent_proxy_addr if hasattr(pkt, 'parent_proxy_addr') else 0x0001
                    else:
                        destination = pkt.nwk_src_addr if pkt.nwk_src_addr_length == 0 else 0x0001
                        
                    key = cmd.key_value
                    nonce_counter = cmd.peer_nonce_counter_value

                elif cmd.session_type == 0x1:
                    key_type = "broadcast" 
                    destination = 0xFFFF
                    key = cmd.key_value
                    nonce_counter = cmd.peer_nonce_counter_value

                elif cmd.session_type == 0x2:
                    key_type = "join" 
                    destination = 0x0001
                    key = cmd.key_value
                    nonce_counter = cmd.peer_nonce_counter_value

                if source is not None and destination is not None:
                    peer = Peer(source, destination)
                    
                    if peer in self.__class__._cache and self.__class__._cache[peer] == nonce_counter:
                        continue
                if source is not None and destination is not None:
                    peer = Peer(source, destination)
                    
                    if peer in self.__class__._cache and self.__class__._cache[peer] == nonce_counter:
                        continue

                self.__class__._cache[peer] = nonce_counter
                self.trigger()
                self.mark_packet(packet)
                
                self._key_type = key_type
                self._source = source
                self._key = key
                self._destination = destination
                self._nonce_counter = nonce_counter
                    
                self.complete()
    '''
    def process_packet(self, packet):
        triggered_this_packet = False

        if isinstance(packet, bytes):
            packet = Dot15d4FCS(packet)

        pkt = packet.decrypted if hasattr(packet, "decrypted") and packet.decrypted is not None else packet
        transport_layer = pkt.getlayer(WirelessHart_Transport_Layer_Hdr)
        
        if transport_layer is None:
            return

        for cmd in transport_layer.commands:
            
            if hasattr(cmd, "command_number") and cmd.command_number == 0x3c3:
                id_1 = pkt.nwk_src_addr if pkt.response != 0 else pkt.nwk_dest_addr
                peer = Peer(cmd.nickname, id_1)

                if cmd.session_type == 0x0:
                    if getattr(pkt, "nwk_dest_addr_length", None) == 0x0 and getattr(pkt, "nwk_src_addr_length", None) == 0x0:
                        
                        if peer in self.__class__._cache and self.__class__._cache[peer] == cmd.peer_nonce_counter_value:
                            continue

                        self._key_type = "unicast"
                        self._source = cmd.nickname
                        self._destination = id_1
                        self._key = cmd.key_value
                        self._nonce_counter = cmd.peer_nonce_counter_value
                        triggered_this_packet = True
                    else:
                        self._pending_key = cmd.key_value
                        self._pending_id2 = cmd.nickname
                        self._pending_nonce = cmd.peer_nonce_counter_value

                elif cmd.session_type == 0x1: # Broadcast
                    peer = Peer(0xffff, cmd.nickname)
                    if peer in self.__class__._cache and self.__class__._cache[peer] == cmd.peer_nonce_counter_value:
                        continue
                    
                    self._key_type = "broadcast"
                    self._source = cmd.nickname
                    self._destination = 0xFFFF
                    self._key = cmd.key_value
                    self._nonce_counter = cmd.peer_nonce_counter_value
                    triggered_this_packet = True

                elif cmd.session_type == 0x2: # Join
                    if peer in self.__class__._cache and self.__class__._cache[peer] == cmd.peer_nonce_counter_value:
                        continue
                    
                    self._key_type = "join"
                    self._source = cmd.nickname
                    self._destination = id_1
                    self._key = cmd.key_value
                    self._nonce_counter = cmd.peer_nonce_counter_value
                    triggered_this_packet = True

            elif hasattr(cmd, "command_number") and cmd.command_number == 0x3C2:
                if self._pending_key is not None:
                    peer = Peer(cmd.nickname, self._pending_id2, self._pending_nonce)
                    
                    if peer in self.__class__._cache and self.__class__._cache[peer] == self._pending_nonce:
                        continue
                    
                    self._key_type = "unicast"
                    self._source = cmd.nickname
                    self._destination = self._pending_id2
                    self._key = self._pending_key
                    self._nonce_counter = self._pending_nonce
                    triggered_this_packet = True


        if triggered_this_packet:
            final_peer = Peer(self._source, self._destination)
            self.__class__._cache[final_peer] = self._nonce_counter
            
            self.trigger()
            self.mark_packet(packet)
            self.complete()