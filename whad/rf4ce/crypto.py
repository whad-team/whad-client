from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.rf4ce import RF4CE_Hdr
from whad.rf4ce.exceptions import MissingRF4CEHeader, \
    MissingCryptographicMaterial, MissingRF4CESecurityFlag
from Cryptodome.Cipher import AES
from struct import pack
from scapy.config import conf

conf.dot15d4_protocol = "rf4ce"

class RF4CECryptoManager:
    def __init__(self, key):
        self.key = key
        self.nonce = None
        self.auth = None

    def generateNonce(self, packet, source=None):
        # Check source validity
        if source is None:
            if packet.fcf_srcaddrmode == 3: # Long address
                source = pack("<Q", packet.src_addr)

        if source is None:
            return None

        frame_counter = pack("<I", packet.frame_counter)
        security_level = b"\x05" # always 5 in RF4CE
        # build and return the nonce
        return source + frame_counter + security_level

    def generateAuth(self, packet, destination=None):
        # Check destination validity
        if destination is None:
            if packet.fcf_destaddrmode == 3: # Long address
                destination = pack("<Q", packet.dest_addr)

        if destination is None:
            return None

        # Extract the header (force a rebuild)
        packet.reserved = 1
        packet = packet[RF4CE_Hdr:]
        header = bytes(packet)[:5]

        # Build and return the auth
        return header + destination

    def extractCiphertextPayload(self, packet):
        # If it is a vendor or a data packet, we need to take
        # into account supplementary fields
        start_of_payload = 2 if packet.frame_type in (1,3) else 1
        ciphertext = bytes(packet[RF4CE_Hdr:][start_of_payload:])
        return ciphertext, pack("<I", packet.mic)

    def extractPlaintextPayload(self, packet):
        start_of_payload = 2 if packet.frame_type in (1,3) else 1
        plaintext = bytes(packet[RF4CE_Hdr:][start_of_payload:])
        return plaintext

    def decrypt(self, packet, source=None, destination=None):
        # convert source and destination address if provided
        if isinstance(source, str) and ":" in source:
            source = bytes.fromhex(source.replace(":", ""))[::-1]

        if isinstance(destination, str) and ":" in destination:
            destination = bytes.fromhex(destination.replace(":", ""))[::-1]

        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4(packet)

        # don't process FCS if present
        if Dot15d4FCS in packet:
            # force a rebuild just in case
            packet.reserved = 1
            packet = bytes(packet)[:-2]
            packet = Dot15d4(packet)

        if RF4CE_Hdr not in packet:
            raise MissingRF4CEHeader()

        # Check if packet has security enabled
        if (
            hasattr(packet, "security_enabled")# and
            #packet.security_enabled == 1
        ):
            self.nonce = self.generateNonce(packet, source)
            if self.nonce is None:
                # Missing source address, nonce cannot be generated
                return (packet, False)

            self.auth = self.generateAuth(packet, destination)
            if self.auth is None:
                # Missing destination address, auth cannot be generated
                return (packet, False)

            ciphertext, mic = self.extractCiphertextPayload(packet)

            # Perform the decryption and integrity check
            cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=4)
            cipher.update(self.auth)
            plaintext = cipher.decrypt(ciphertext)
            try:
                cipher.verify(mic)

                # Rebuild the decrypted packet
                header = bytes(packet)[:-4-len(ciphertext)]
                packet = Dot15d4(header + plaintext + mic)

                return (packet, True)

            except ValueError:
                return (packet, False) # integrity check

        else:
            # Security is not enabled, raise an exception
            raise MissingRF4CESecurityFlag()


    def encrypt(self, packet, source=None, destination=None):
        # convert source and destination address if provided
        if isinstance(source, str) and ":" in source:
            source = bytes.fromhex(source.replace(":", ""))[::-1]

        if isinstance(destination, str) and ":" in destination:
            destination = bytes.fromhex(destination.replace(":", ""))[::-1]

        # convert into scapy packet if bytes only
        if isinstance(packet, bytes):
            packet = Dot15d4(packet)

        # don't process FCS if present
        if Dot15d4FCS in packet:
            # force a rebuild just in case
            packet.reserved = 1
            packet = bytes(packet)[:-2]
            packet = Dot15d4(packet)

        if RF4CE_Hdr not in packet:
            raise MissingRF4CEHeader()

        # Check if packet has security enabled
        if (
            hasattr(packet, "security_enabled")# and
            #packet.security_enabled == 1
        ):
            self.nonce = self.generateNonce(packet, source)
            if self.nonce is None:
                # Missing source address, nonce cannot be generated
                return (packet, False)

            self.auth = self.generateAuth(packet, destination)
            if self.auth is None:
                # Missing destination address, auth cannot be generated
                return (packet, False)

            packet.show()

            # Perform the decryption and integrity check
            cipher = AES.new(self.key, AES.MODE_CCM, nonce=self.nonce, mac_len=4)
            cipher.update(self.auth)

            plaintext = self.extractPlaintextPayload(packet)
            ciphertext = cipher.encrypt(plaintext)
            mic = cipher.digest()

            if packet.mic is None:
                cropping_length = len(plaintext)
            else:
                cropping_length = len(plaintext) + 4
            packet.reserved = 1
            header = bytes(packet)[:-cropping_length]
            packet = Dot15d4(header + ciphertext +  mic)
            # Set the security flag and force a rebuild
            packet.security_enabled = 1
            return packet

        else:
            # Security is not enabled, raise an exception
            raise MissingRF4CESecurityFlag()

class RF4CEDecryptor:
    def __init__(self, *keys):
        self.keys = list(keys)
        self.addresses = []

    def add_address(self, *addresses):
        for address in addresses:
            self.addresses.append(address)

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

    def addresses_combination(self):
        tmp_list = [
            ((a, b), (b, a))
            for idx, a in enumerate(self.addresses)
            for b in self.addresses[idx + 1:]
        ]

        address_list = []

        for entry in tmp_list:
            first_pair, second_pair = entry
            address_list += [first_pair, second_pair]

        return address_list

    def attempt_to_decrypt(self, packet):
        if (
            len(self.keys) == 0 or
            (
                len(self.addresses) == 0 and
                (
                    pkt.fcf_srcaddrmode != 3 or
                    pkt.fcf_destaddrmode != 3
                )
            )
        ):
            raise MissingCryptographicMaterial()

        if RF4CE_Hdr not in packet:
            return (None, False)

        if packet.security_enabled == 0:
            return (None, False)

        for key in self.keys:
            manager = RF4CECryptoManager(key)
            candidate_addresses = self.addresses_combination()
            for (source_address, destination_address) in candidate_addresses:
                try:
                    decrypted_packet, success = manager.decrypt(
                        packet,
                        source_address,
                        destination_address
                    )
                    if success:
                        return (decrypted_packet, True)

                except:
                    pass

        return (None, False)
'''
key = bytes.fromhex("32d277d18b5744de9da8726d2f88fe05")

address1 = "c4:19:d1:ae:35:0d:70:02"
address2 = "c4:19:d1:59:d2:a7:92:c5"
pkt1 = Dot15d4FCS(bytes.fromhex("61889c9a26153fbcfe2f85e10000c04111d775 960ad77a 1dce"))

d = RF4CEDecryptor(key)
d.add_address(address1, address2)
p, s = d.attempt_to_decrypt(pkt1)
p.show()
print(s)
'''
'''
# test key: 32d277d18b5744de9da8726d2f88fe05
key = bytes.fromhex("32d277d18b5744de9da8726d2f88fe05")

address1 = "c4:19:d1:ae:35:0d:70:02"
address2 = "c4:19:d1:59:d2:a7:92:c5"
pkt1 = Dot15d4FCS(bytes.fromhex("61889c9a26153fbcfe2f85e10000c04111d775 960ad77a 1dce"))
pkt2 = bytes.fromhex("41c87affffffff02700d35aed119c42a5ee10000010c4111544c00000000001353522d3030312d550000000000000001c00932b1")
decrypted, success = RF4CECryptoManager(key).decrypt(pkt1, address1, address2)

a = RF4CECryptoManager(key).encrypt(decrypted, address1, address2)
print(bytes(a).hex())
#decrypted.show()
#RF4CECryptoManager(key).decrypt(pkt2)
#61889c9a26153fbcfe2f960ad77a85e10000c04111d775
#61889c9a26153fbcfe2f85e10000c04111d775960ad77a1dce
'''
