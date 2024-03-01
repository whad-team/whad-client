from scapy.layers.dot15d4 import Dot15d4, Dot15d4FCS
from whad.scapy.layers.rf4ce import RF4CE_Hdr
from whad.rf4ce.exceptions import MissingRF4CEHeader, MissingRF4CESecurityFlag
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

        # Extract the header
        header = bytes(packet[RF4CE_Hdr:])[:5]

        # Build and return the auth
        return header + destination

    def extractCiphertextPayload(self, packet):
        # If it is a vendor or a data packet, we need to take
        # into account supplementary fields
        start_of_payload = 2 if packet.frame_type in (1,3) else 1
        ciphertext = bytes(packet[RF4CE_Hdr:][start_of_payload:])
        return ciphertext

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
            packet = Dot15d4(raw(packet)[:-2])

        if RF4CE_Hdr not in packet:
            raise MissingRF4CEHeader()

        # force a rebuild just in case
        packet.reserved = 1
        packet.show()

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

            ciphertext = self.extractCiphertextPayload(packet)
            print("ciphertext", self.nonce.hex())
            print("ciphertext", self.auth.hex())
            print("ciphertext", ciphertext.hex())
        else:
            # Security is not enabled, raise an exception
            raise MissingRF4CESecurityFlag()



# test key: 32d277d18b5744de9da8726d2f88fe05
key = bytes.fromhex("32d277d18b5744de9da8726d2f88fe05")

address1 = "c4:19:d1:ae:35:0d:70:02"
address2 = "c4:19:d1:59:d2:a7:92:c5"
pkt1 = bytes.fromhex("61889c9a26153fbcfe2f85e10000c04111d775960ad77a1dce")
pkt2 = bytes.fromhex("41c87affffffff02700d35aed119c42a5ee10000010c4111544c00000000001353522d3030312d550000000000000001c00932b1")
RF4CECryptoManager(key).decrypt(pkt1, address1, address2)
RF4CECryptoManager(key).decrypt(pkt2)
