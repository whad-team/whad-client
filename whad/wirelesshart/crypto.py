from scapy.packet import Raw
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Hdr, \
    WirelessHart_Network_Hdr, WirelessHart_Network_Security_SubLayer_Hdr, \
    WirelessHart_Transport_Layer_Hdr, WirelessHart_Write_Device_Nickname_Request, WirelessHart_Write_Modify_Session_Command_Request, WirelessHart_Write_Modify_Session_Command_Response, WirelessHart_Write_Network_Key_Request, WirelessHart_Write_Network_Key_Response
from whad.wirelesshart.exceptions import MissingSecurityHeader, \
    MissingCryptographicMaterial, MissingSecurityFlag
from whad.common.analyzer import TrafficAnalyzer
from Cryptodome.Cipher import AES
from struct import pack
from copy import copy
from scapy.config import conf

conf.dot15d4_protocol = "wirelesshart"


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
            del packet[Raw]
            decrypted_pkt = packet.copy()
            decrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr].security_types = 15
            
            decrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr].remove_payload()
            decrypted_pkt[WirelessHart_Network_Security_SubLayer_Hdr].add_payload(decrypted)

            decrypted_pkt.metadata = metadata
            
            decrypted_pkt.metadata.decrypted = True
            return (decrypted_pkt, True)

        except ValueError as e:
            print("error!", e)
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
                        (self._id1== other._id1 and self._id2==other._id2)
                            or (self._id1== other._id2 and self._id2==other._id1)
                    )
                )
    def get_nonce_counter(self):
        return self._nonce
    
    def set_nonce_counter(self, nonce):
        self._nonce = nonce & 0xFFFFFFFF
        
    def set_short_nonce_counter(self, counter):
        self._nonce = (self._nonce & 0xffffff00) | counter
        
    def incremenet_nonce(self):
        self.set_nonce_counter(self.get_nonce_counter()+1)
    
    def __hash__(self):
        return hash(tuple(sorted((self._id1, self._id2))))
    
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
                print("get unicast peer:", peer)
                return peer
        return None

    def get_broadcast_peer(self, id1, id2)->Peer:
        for peer in self.__broadcast_sessions_keys.keys():
            if peer == Peer(id1,id2):
                print("get broadcast peer:", peer)
                return peer
        return None
    
    def get_join_peer(self, id1, id2)->Peer:
        for peer in self.__join_sessions_keys.keys():
            if peer == Peer(id1,id2):
                print("get join peer:", peer)
                return peer
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
            communications.append((self.get_broadcast_peer(0xffff, packet.nwk_dest_addr), self.get_broadcast_session_key(0xffff, packet.nwk_dest_addr)))
            communications.append((self.get_broadcast_peer(packet.nwk_src_addr, 0xffff), self.get_broadcast_session_key(packet.nwk_src_addr, 0xffff)))
            communications.append((self.get_join_peer(packet.nwk_src_addr, packet.nwk_dest_addr), self.get_join_session_key(packet.nwk_src_addr, packet.nwk_dest_addr)))
            
        elif packet.security_types == 1 : #join keyed
            communications = [(None, self.__join_key)]

        for (peer, key) in communications:
            
            if key:
                manager = WirelessHartNetworkLayerCryptoManager(key)
                decrypted, success = manager.decrypt(packet)
                if success:
                    decrypted = Dot15d4FCS(bytes(decrypted)) 
                    if peer:
                        peer.set_short_nonce_counter(packet.counter)
                    self.extract_keys(decrypted)
                    return decrypted, True
        # one key seems to be missing, check what is not correctly decrypted here
        print("Decryption failed !!")
        print("pkt:", bytes(packet).hex())
        #packet.show()
        #exit()
        return packet, False