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

        except ValueError:
            packet.metadata = metadata
            return (packet, False)
        
class Peer:
    def __init__(self, id1, id2):
        self._id1 = id1
        self._id2 = id2
        
    def __eq__(self, other):
        return ( isinstance(other, Peer)
                and (
                        (self._id1== other._id1 and self._id2==other._id2)
                            or (self._id1== other._id2 and self._id2==other._id1)
                    )
                )
    def __hash__(self):
        return hash(tuple(sorted((self._id1, self._id2))))
class WirelessHartDecryptor:

    def __init__(self, *keys):
        self.__join_key = None
        self.__network_key = None
        self.__sessions_keys = {}
        #self.keys = list(keys)

    def set_join_key(self, key):
        key = self.parse_key(key)
        if key:
            self.__join_key = key
            print("joinkey;", key)
    
    def set_network_key(self, key):
        key = self.parse_key(key)
        if key:
            self.__network_key = key
            print("ntwork key:", key)
        
    def add_session_key(self, id1, id2, key):
        key = self.parse_key(key)
        peer = Peer(id1, id2)
        if key:
            self.__sessions_keys[peer] = key
            print("session key:", key)
        
        
    def get_session_key(self, id1, id2):
        return self.__sessions_keys.get(Peer(id1, id2))
        
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
    
    """def add_key(self, key):
        if isinstance(key, str):
            if len(key) == 16:
                key = key.encode('ascii')
            else:
                try:
                    key = bytes.fromhex(key.replace(":",""))
                except ValueError:
                    return False

        if not isinstance(key, bytes) or len(key) != 16:
            return False

        if key not in self.keys:
            self.keys.append(key)
            return True
        return False"""
    
    def extract_keys(self, packet):
        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4FCS(packet)
        
        transport_layer = packet.getlayer(WirelessHart_Transport_Layer_Hdr)
        if transport_layer is not None:
            dst = None
            for c in transport_layer.commands:
                if hasattr(c, "key_value"): #adding the keys if the command key_value is in the transport layer
                    #if WirelessHart_Write_Network_Key_Response or WirelessHart_Write_Network_Key_Request in c:
                    if c.command_number == 0x3C1:
                        self.set_network_key(c.key_value)
                    if c.command_number == 0x3C3:
                        match c.session_type:
                            case 0x0: #unicast
                                if packet.nwk_dest_addr_length == 0x0 and packet.nwk_src_addr_length == 0x0 : #short adress
                                    self.add_session_key(c.nickname, packet.nwk_dest_addr, c.key_value)
                                else:
                                    key = c.key_value
                                    dst = packet.nwk_dest_addr
                            case 0x1: #broadcast
                                self.add_session_key(c.nickname, 0xffff, c.key_value)
                            #case 0x2: #join
                                # todo 
                                
                    """if c.key_value not in self.keys:
                        self.add_key(c.key_value)"""
                        
                    #if WirelessHart_Write_Device_Nickname_Request in c:
                if c.command_number == 0x3C2:
                    if dst:
                        self.add_session_key(packet.nwk_src_addr, c.nickname, key)
                    

    def attempt_to_decrypt(self, packet):

        if WirelessHart_Network_Security_SubLayer_Hdr not in packet:
            raise MissingSecurityHeader()
        
        if packet.security_types == 0 : #session keyed
            key = self.get_session_key(packet.nwk_src_addr, packet.nwk_dest_addr)
        elif packet.security_types == 1 : #join keyed
            key = self.__join_key

        if key:
            manager = WirelessHartNetworkLayerCryptoManager(key)
            decrypted, success = manager.decrypt(packet)
            if success:
                decrypted = Dot15d4FCS(bytes(decrypted)) 
                self.extract_keys(decrypted)
                return decrypted, True
        # one key seems to be missing, check what is not correctly decrypted here
        print("Decryption failed !!")
        packet.show()
        #exit()
        return packet, False