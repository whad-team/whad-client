from scapy.packet import Raw
from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Hdr, \
    WirelessHart_Network_Hdr, WirelessHart_Network_Security_SubLayer_Hdr, \
    WirelessHart_Transport_Layer_Hdr
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
            packet[WirelessHart_Network_Security_SubLayer_Hdr].security_types = 15
            packet = packet / WirelessHart_Transport_Layer_Hdr(decrypted)
            packet.metadata = metadata
            return (packet, True)

        except ValueError:
            packet.metadata = metadata
            return (packet, False)

class WirelessHartDecryptor:

    def __init__(self, *keys):
        self.keys = list(keys)

    def add_key(self, key):
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
        return False


    def attempt_to_decrypt(self, packet):

        if WirelessHart_Network_Security_SubLayer_Hdr not in packet:
            raise MissingSecurityHeader()

        for key in self.keys:
            manager = WirelessHartNetworkLayerCryptoManager(key)
            decrypted, success = manager.decrypt(packet)
            if success:
                return decrypted, True
        # one key seems to be missing, check what is not correctly decrypted here
        packet.show()
        exit()
        return packet, False