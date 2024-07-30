from whad.zigbee.exceptions import MissingNetworkSecurityHeader
from Cryptodome.Cipher import AES
from scapy.layers.dot15d4 import Dot15d4,Dot15d4FCS
from scapy.layers.zigbee import ZigbeeSecurityHeader,ZigbeeNWK, ZigbeeAppCommandPayload, \
    ZigbeeAppDataPayload, ZigbeeNWKCommandPayload
from whad.scapy.layers.zll import ZLLScanRequest, ZLLScanResponse, ZLLNetworkJoinRouterRequest
from whad.common.analyzer import TrafficAnalyzer
from scapy.compat import raw
from scapy.config import conf
from scapy.all import Packet
from struct import pack

conf.dot15d4_protocol = "zigbee"

def e(key, plaintext):
    cipher = AES.new(plaintext, AES.MODE_ECB)
    output = cipher.encrypt(key)
    return output

def hash(input):
    output = b"\x00"*16
    M = input
    M += b"\x80"
    while len(M) % 16 != 0:
        M += b"\x00"
    M = M[:-2] + bytes([(0xFF & (len(input)*8 >> 8)),(0xFF & (len(input)*8 >> 0))])
    i = 0
    while i < len(M):
        bloc = M[i:i+16]
        ciphertext = e(bloc,output)
        output = b""
        for j in range(len(bloc)):
            output += bytes([ciphertext[j] ^ bloc[j]])
        i+=16
    return output

def hash_key(key, input):
    ipad = 0x36
    opad = 0x5c

    hash_in = hash_out = b""
    for i in key:
        hash_in += bytes([opad ^ i])
        hash_out += bytes([ipad ^ i])

    hash_out += bytes([input])
    hash_in += hash(hash_out)
    return hash(hash_in)


class CryptoManager:
    SECURITY_LEVELS = {
    	0x00: {"encryption":False,"integrity":False, "M":0},
    	0x01: {"encryption":False,"integrity":True, "M":4},
    	0x02: {"encryption":False,"integrity":True, "M":8},
    	0x03: {"encryption":False,"integrity":True, "M":16},
    	0x04: {"encryption":True,"integrity":False, "M":0},
    	0x05: {"encryption":True,"integrity":True, "M":4},
    	0x06: {"encryption":True,"integrity":True, "M":8},
    	0x07: {"encryption":True,"integrity":True, "M":16}
    }


    def __init__(self, key):
        self.key = key
        self.base_class = None
        self.nonce = None
        self.auth = None
        self.M = None
        self.encryption = None
        self.integrity = None
        self.patched = False

    def generateNonce(self, packet):
        source = raw(packet[ZigbeeSecurityHeader])[5:13] # prevent struct failure on windows ...
        fc = pack("I", packet[ZigbeeSecurityHeader].fc)
        security_header = bytes([(
            packet[ZigbeeSecurityHeader].nwk_seclevel |
            (packet[ZigbeeSecurityHeader].key_type << 3) |
            (packet[ZigbeeSecurityHeader].extended_nonce << 5)|
            (packet[ZigbeeSecurityHeader].reserved1 << 6)
        )])
        return source + fc + security_header

    def checkSecurityLevel(self, packet):
        # If network security level equals to zero, we assume it's the bug mentioned in wireshark source code and patch it
        if packet[ZigbeeSecurityHeader].nwk_seclevel == 0:
            self.patched = True
            packet[ZigbeeSecurityHeader].nwk_seclevel = 0x05 # patched security header: MIC-ENC-32
            M = 4
            encryption = True
            integrity = True
        else:
            # Parse network security level to check how to process the packet
            self.patched = False
            level = CryptoManager.SECURITY_LEVELS[packet[ZigbeeSecurityHeader].nwk_seclevel]
            encryption = level["encryption"]
            integrity = level["integrity"]
            if integrity:
                M = level["M"]
            else:
                M = 0
        return (packet, M, integrity, encryption)

    def generateAuth(self, packet):
        if self.encryption:
            auth = raw(packet[self.base_class:]).replace(packet.data,b"")
            if len(packet.mic) != 0:
                auth = auth.replace(packet.mic, b"")
        else:
            auth = raw(packet[self.base_class:])[:-self.M]
        return auth

    def extractCiphertextPayload(self, packet):
        if self.encryption:
            message = packet[ZigbeeSecurityHeader].data[:-self.M] if len(packet.mic) == 0 and self.patched else packet.data
            mic = packet[ZigbeeSecurityHeader].data[-self.M:] if len(packet.mic) == 0 and self.patched else packet.mic
        else:
            mic = raw(packet[self.base_class:])[-self.M:]
            message = b""
        return message, mic

    def generateMIC(self,packet):
        self.auth = self.generateAuth(packet)
        plaintext = packet.data if len(packet.mic) == 0 and self.patched else packet.data + packet.mic
        auth = len(self.auth).to_bytes(2, byteorder = 'big')+self.auth
        auth = auth + (32 - len(auth))*b"\x00" + plaintext+(16 - len(plaintext))*b"\x00"
        flags = (0 << 7) | ((0 if len(self.auth) == 0 else 1) << 6 ) | ((2 - 1) << 3) | ((self.M-2)//2 if self.M else 0)
        B0 = bytes([flags]) + self.nonce + pack(">H",len(plaintext))
        X0 = b"\x00"*16
        cipher = AES.new(self.key, AES.MODE_CBC, X0)
        padding = b""
        while len(padding + B0 + auth) % 16 != 0:
            padding += b"\x00"
        X1 = cipher.encrypt(padding + B0 + auth)
        return X1[-16:-12]

    def encrypt(self, packet):
        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4(packet)

        # don't process FCS if present
        if Dot15d4FCS in packet:
            packet = Dot15d4(raw(packet)[:-2])

        # raise MissingNetworkSecurityHeader exception if no security header is found
        if ZigbeeSecurityHeader not in packet:
            raise MissingNetworkSecurityHeader()

        if self.base_class is None:
            self.base_class = packet[ZigbeeSecurityHeader].underlayer.__class__

        # check security level (and patch the packet content if needed - see wireshark source code for details)
        packet, self.M, self.integrity, self.encryption = self.checkSecurityLevel(packet)

        # generate the nonce
        self.nonce = self.generateNonce(packet)

        # generate the AES-CCM parameters
        self.auth = self.generateAuth(packet)

        # Extract plaintext
        plaintext = packet.data[:-self.M] if len(packet.mic) == 0 and self.patched else packet.data
        # Encrypt and generate MIC
        cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=self.M)
        cipher.update(self.auth)

        ciphertext = cipher.encrypt(plaintext)

        mic = cipher.digest()
        packet.data = ciphertext
        packet.mic = mic

        # Restore security level if patched
        if self.patched:
            packet[ZigbeeSecurityHeader].nwk_seclevel = 0

        return packet

    def decrypt(self, packet):
        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4(packet)

        # don't process FCS if present
        if Dot15d4FCS in packet:
            packet = Dot15d4(raw(packet)[:-2])

        # raise MissingNetworkSecurityHeader exception if no security header is found
        if ZigbeeSecurityHeader not in packet:
            raise MissingNetworkSecurityHeader()

        if self.base_class is None:
            self.base_class = packet[ZigbeeSecurityHeader].underlayer.__class__

        # check security level (and patch the packet content if needed - see wireshark source code for details)
        packet, self.M, self.integrity, self.encryption = self.checkSecurityLevel(packet)

        # generate the nonce
        self.nonce = self.generateNonce(packet)

        # generate the AES-CCM parameters
        self.auth = self.generateAuth(packet)
        ciphertext, mic = self.extractCiphertextPayload(packet)

        # Perform the decryption and integrity check
        cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=self.M)
        cipher.update(self.auth)

        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(mic)
            packet.data = plaintext
            packet.mic = self.generateMIC(packet)
            # Reverse patching if needed
            if self.patched:
                packet[ZigbeeSecurityHeader].nwk_seclevel = 0

            return (packet, True)

        except ValueError:
            # Reverse patching if needed
            if self.patched:
                packet[ZigbeeSecurityHeader].nwk_seclevel = 0
            return (packet, False) # integrity check

class NetworkLayerCryptoManager(CryptoManager):

    def __init__(self, key):
        super().__init__(key)
        self.base_class = ZigbeeNWK

class ApplicationSubLayerCryptoManager(CryptoManager):

    def __init__(self, key, input):
        if input is None:
            generated_key = self.base_key = key
        else:
            self.input = input
            self.base_key = key
            generated_key = hash_key(key, self.input)
        super().__init__(generated_key)
        self.base_class = ZigbeeAppDataPayload

class ZigbeeDecryptor:
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

        if ZigbeeSecurityHeader not in packet:
            raise MissingNetworkSecurityHeader()

        if packet[ZigbeeSecurityHeader].underlayer.__class__ == ZigbeeNWK:
            for key in self.keys:
                manager = NetworkLayerCryptoManager(key)
                decrypted, success = manager.decrypt(packet)
                if success:
                    if packet.frametype == 0:
                        return ZigbeeAppDataPayload(decrypted.data), True
                    elif packet.frametype == 1:
                        return ZigbeeNWKCommandPayload(decrypted.data), True
                    else:
                        return decrypted.data, True
        else:
            for key in self.keys:
                manager = ApplicationSubLayerCryptoManager(key, 1)
                decrypted, success = manager.decrypt(packet)
                if success:
                    if packet.frametype == 0:
                        if packet.aps_frametype == 0:
                            return ZigbeeAppDataPayload(decrypted.data), True
                        else:
                            return ZigbeeAppCommandPayload(decrypted.data), True
                    elif packet.frametype == 1:
                        return ZigbeeNWKCommandPayload(decrypted.data), True
                    else:
                        return decrypted.data, True

                manager = ApplicationSubLayerCryptoManager(key, 0)
                decrypted, success = manager.decrypt(packet)
                if success:
                    if packet.frametype == 0:
                        if packet.aps_frametype == 0:
                            return ZigbeeAppDataPayload(decrypted.data), True
                        else:
                            return ZigbeeAppCommandPayload(decrypted.data), True
                    elif packet.frametype == 1:
                        return ZigbeeNWKCommandPayload(decrypted.data), True
                    else:
                        return decrypted.data, True

                manager = ApplicationSubLayerCryptoManager(key, 2)
                decrypted, success = manager.decrypt(packet)
                if success:
                    if packet.frametype == 0:
                        if packet.aps_frametype == 0:
                            return ZigbeeAppDataPayload(decrypted.data), True
                        else:
                            return ZigbeeAppCommandPayload(decrypted.data), True
                    elif packet.frametype == 1:
                        return ZigbeeNWKCommandPayload(decrypted.data), True
                    else:
                        return decrypted.data, True

        return packet, False


ZIGBEE_ZLL_KEYS = {
    "master_key":           b"\x9F\x55\x95\xF1\x02\x57\xC8\xA4\x69\xCB\xF4\x2B\xC9\x3F\xEE\x31",
    "certification_key":    b"\xC0\xC1\xC2\xC3\xC4\xC5\xC6\xC7\xC8\xC9\xCA\xCB\xCC\xCD\xCE\xCF",
}


class TransportKeyDistribution(TrafficAnalyzer):
    def reset(self):
        super().reset()
        self.transport_key = None

    def process_packet(self, packet):

        if ZigbeeSecurityHeader in packet and packet[ZigbeeSecurityHeader].key_type == 2:
            self.trigger()
            dec_packet = ZigbeeAppCommandPayload(bytes(packet.data))
            self.mark_packet(packet)
            self.transport_key = dec_packet.key
            self.complete()

    @property
    def output(self):
        return {
            "transport_key":self.transport_key
        }


class TouchlinkKeyManager(TrafficAnalyzer):
    def __init__(self, encrypted_key=None, unencrypted_key=None, transaction_id=None, response_id=None, key_index=None):
        self.reset()
        self.transaction_id = transaction_id
        self.response_id = response_id
        self.key_index = key_index
        self._encrypted_key = encrypted_key
        self._unencrypted_key = unencrypted_key

    def process_packet(self, packet):

        if ZLLScanRequest in packet:
            self.trigger()
            self.transaction_id = packet.inter_pan_transaction_id
            self.mark_packet(packet)
        elif ZLLScanResponse in packet:
            self.trigger()
            self.response_id = packet.response_id
            self.mark_packet(packet)
        elif ZLLNetworkJoinRouterRequest in packet:
            self.trigger()
            self.key_index = packet.key_index
            self._encrypted_key = packet.encrypted_network_key#.to_bytes(16, "big")
            self.mark_packet(packet)
            self.complete()

    @property
    def output(self):
        return {
            "key_index" : self.key_index,
            "encrypted_key": self._encrypted_key,
            "decrypted_key": self._decrypt_key(),
        }
    @property
    def encrypted_key(self):
        if self._encrypted_key is not None:
            return self._encrypted_key
        elif (
                self.transaction_id is not None and
                self.response_id is not None and
                self.key_index is not None and
                self._unencrypted_key is not None
        ):
            return self._encrypt_key()
        else:
            return None

    @property
    def unencrypted_key(self):
        if self._unencrypted_key is not None:
            return self._unencrypted_key
        elif (
                self.transaction_id is not None and
                self.response_id is not None and
                self.key_index is not None and
                self._encrypted_key is not None
        ):
            return self._decrypt_key()
        else:
            return None

    def reset(self):
        super().reset()
        self.transaction_id = None
        self.response_id = None
        self.key_index = None
        self._unencrypted_key = None
        self._encrypted_key = None


    def _encrypt_key(self):
        # If key index equals to zero, the key is encrypted using one single step with a key generated from transaction_id and response_id
        # (see Zigbee Cluster Specification v1.0 rev.6, section 13.3.4.10.4)
        if self.key_index == 0:
            # Generate the key
            development_key = b"PhLi" + pack(">I",self.transaction_id) + b"CLSN" + pack(">I",self.response_id)
            # Encrypt the unencrypted_key
            encryptor = AES.new(development_key, mode=AES.MODE_ECB)
            return encryptor.encrypt(self._unencrypted_key)
        else:
            # Select the right main key according to key index
            if self.key_index == 4:
                main_key = ZIGBEE_ZLL_KEYS["master_key"]
            elif self.key_index == 15:
                main_key = ZIGBEE_ZLL_KEYS["certification_key"]
            else:
                # No key found, return None and don't process further
                return None

            # Generate the plaintext vector
            plaintext = pack(">I",self.transaction_id)*2 + pack(">I",self.response_id)*2
            # Generate transport key
            step1 = AES.new(main_key, mode=AES.MODE_ECB)
            transport_key = step1.encrypt(plaintext)
            # Use transport key to decrypt network key
            step2 = AES.new(transport_key, mode=AES.MODE_ECB)
            return step2.encrypt(self._unencrypted_key)


    def _decrypt_key(self):
        # If key index equals to zero, the key is decrypted using one single step with a key generated from transaction_id and response_id
        # (see Zigbee Cluster Specification v1.0 rev.6, section 13.3.4.10.4)
        if self.key_index == 0:
            # Generate the key
            development_key = b"PhLi" + pack(">I",self.transaction_id) + b"CLSN" + pack(">I",self.response_id)
            # Decrypt the encrypted_key
            decryptor = AES.new(development_key, mode=AES.MODE_ECB)
            return decryptor.decrypt(self._encrypted_key)

        # If key not equals to zero, use a two-step decryption algorithm with known key
        # (see Zigbee Cluster Specification v1.0 rev.6, section 13.3.4.10.5)
        else:
            # Select the right main key according to key index
            if self.key_index == 4:
                main_key = ZIGBEE_ZLL_KEYS["master_key"]
            elif self.key_index == 15:
                main_key = ZIGBEE_ZLL_KEYS["certification_key"]
            else:
                # No key found, return None and don't process further
                return None

            # Generate the plaintext vector
            plaintext = pack(">I",self.transaction_id)*2 + pack(">I",self.response_id)*2
            # Generate transport key
            step1 = AES.new(main_key, mode=AES.MODE_ECB)
            transport_key = step1.encrypt(plaintext)
            # Use transport key to decrypt network key
            step2 = AES.new(transport_key, mode=AES.MODE_ECB)
            return step2.decrypt(self._encrypted_key)
