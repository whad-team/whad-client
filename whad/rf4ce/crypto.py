from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.rf4ce import RF4CE_Hdr, \
    RF4CE_Cmd_Pair_Request, RF4CE_Cmd_Key_Seed
from whad.rf4ce.exceptions import MissingRF4CEHeader, \
    MissingCryptographicMaterial, MissingRF4CESecurityFlag
from whad.common.analyzer import TrafficAnalyzer
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

from struct import pack
from scapy.config import conf

conf.dot15d4_protocol = "rf4ce"

def generate_random_value(bits):
    """Generate a random value of provided bit size.

    :param int bits: Number of bits (8-bit aligned) to generate.
    :return bytes: Random bytes
    """
    return get_random_bytes(int(bits/8))


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
        packet.reserved = 1
        (packet.do_build())
        start_of_payload = 2 if packet.frame_type in (1,3) else 1
        ciphertext = bytes(packet[RF4CE_Hdr:][start_of_payload:])
        #print(ciphertext.hex())
        return ciphertext, pack("<I", packet.mic)

    def extractPlaintextPayload(self, packet):
        packet.reserved = 1
        (packet.do_build())
        start_of_payload = 2 if packet.frame_type in (1,3) else 1
        plaintext = bytes(packet[RF4CE_Hdr:][start_of_payload:])
        return plaintext

    def decrypt(self, packet, source=None, destination=None, rf4ce_only=False):
        fcs_present = False
        # convert source and destination address if provided
        if isinstance(source, str) and ":" in source:
            source = bytes.fromhex(source.replace(":", ""))[::-1]

        if isinstance(destination, str) and ":" in destination:
            destination = bytes.fromhex(destination.replace(":", ""))[::-1]

        if rf4ce_only:
            if RF4CE_Hdr in packet:
                packet.reserved = 1
                packet = RF4CE_Hdr(packet.do_build())

            if isinstance(packet, bytes):
                packet = RF4CE_Hdr(packet)
        else:
            # convert into scapy packet if bytes only
            if isinstance(packet, bytes):
                packet = Dot15d4(packet)

            # don't process FCS if present
            if Dot15d4FCS in packet:
                # force a rebuild just in case
                packet.reserved = 1
                packet = packet.do_build()[:-2]
                packet = Dot15d4(packet)

                fcs_present = True

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
                if rf4ce_only:
                    packet = RF4CE_Hdr(header + plaintext + mic)
                else:
                    packet = Dot15d4(header + plaintext + mic)
                    if fcs_present:
                        # rebuild Dot15d4FCS packet
                        packet = Dot15d4FCS(bytes(packet) + Dot15d4FCS.compute_fcs(None, bytes(packet)))

                return (packet, True)

            except ValueError:
                return (packet, False) # integrity check

        else:
            # Security is not enabled, raise an exception
            raise MissingRF4CESecurityFlag()


    def encrypt(self, packet, source=None, destination=None, rf4ce_only=False):
        fcs_present = False
        # convert source and destination address if provided
        if isinstance(source, str) and ":" in source:
            source = bytes.fromhex(source.replace(":", ""))[::-1]

        if isinstance(destination, str) and ":" in destination:
            destination = bytes.fromhex(destination.replace(":", ""))[::-1]

        if rf4ce_only:
            if RF4CE_Hdr in packet:
                packet.reserved = 1
                packet = RF4CE_Hdr(packet.do_build())

            if isinstance(packet, bytes):
                packet = RF4CE_Hdr(packet)
        else:
            # convert into scapy packet if bytes only
            if isinstance(packet, bytes):
                packet = Dot15d4(packet)

            # don't process FCS if present
            if Dot15d4FCS in packet:
                fcs_present = True
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

            if rf4ce_only:
                packet = RF4CE_Hdr(header + ciphertext + mic)
            else:
                packet = Dot15d4(header + ciphertext +  mic)
                if fcs_present:
                    # rebuild Dot15d4FCS packet
                    packet = Dot15d4FCS(bytes(packet) + Dot15d4FCS.compute_fcs(None, bytes(packet)))

            # Set the security flag and force a rebuild
            packet.security_enabled = 1

            return packet

        else:
            # Security is not enabled, raise an exception
            raise MissingRF4CESecurityFlag()

def xor(a, b):
    """
    Helper function to perform a xor operation between two bytes array.
    """
    return bytes(
        [
            a[i] ^ b[i] for i in range(min(len(a), len(b)))
        ]
    )

class RF4CEKeyDerivation(TrafficAnalyzer):
    def __init__(self, seeds_number=None, seeds=[]):
        self.reset()
        self.seeds_number = seeds_number
        self.seeds = seeds

    def process_packet(self, packet):
        if RF4CE_Cmd_Pair_Request in packet:
            self.trigger()
            self.mark_packet(packet)
            self.seeds_number = packet.key_exchange_transfer_count
        elif RF4CE_Cmd_Key_Seed in packet:
            self.trigger()
            self.mark_packet(packet)
            self.seeds.append(packet.seed_data)

        if (
                self.seeds_number is not None and
                len(self.seeds) == (1 + self.seeds_number)
        ):
            self.complete()

    @property
    def output(self):
        return {"key":self.key}

    @property
    def key(self):
        if (
                self.seeds_number is not None and
                len(self.seeds) == (1 + self.seeds_number)
        ):
            return self._generate_key()
        else:
            return None

    def reset(self):
        super().reset()
        self.seeds_number = None
        self.seeds = []

    def _generate_key(self):
        phase1 = b"\x00" * 80
        for current_seed in self.seeds:
            phase1 = xor(phase1, current_seed)

        phase2 = []
        for i in range(5):
            start = i*16
            end = (i+1)*16
            s = phase1[start:end]
            phase2.append(s)

        key = b"\x00"*16
        for current_seed in phase2:
            key = xor(key, current_seed)

        return key

class RF4CEDecryptor:
    def __init__(self, *keys):
        self.keys = list(keys)
        self.addresses = []

    def add_address(self, *addresses):
        for address in addresses:
            if isinstance(address, int):
                address = ":".join(["{:02x}".format(i) for i in pack('>Q', address)])
            if address not in self.addresses:
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
                    packet.fcf_srcaddrmode != 3 or
                    packet.fcf_destaddrmode != 3
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
