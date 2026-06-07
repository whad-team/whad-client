import pytest
from whad.lorawan.crypto import derive_appskey, derive_nwkskey, decrypt_packet, encrypt_packet
from whad.scapy.layers.lorawan import PHYPayload, JoinAccept, JoinRequest, MACPayloadUplink
from scapy.all import RawVal

class TestLoRaWANCrypto:

    @pytest.fixture
    def appkey(self):
        return bytes.fromhex("00000000000000000000000000000000")
    
    @pytest.fixture
    def encrypted_join_accept(self):
        return bytes.fromhex("20fed423bb9faca7e68a967a02fde49c41")

    def test_encrypt_join_accept(self, appkey, encrypted_join_accept):
        """Test encryption of Join Accept
        """
        # Build our Join Accept packet
        ja = PHYPayload()/JoinAccept(join_nonce=0x123456, home_netid=0x42, dev_addr=0xaabbcc)

        # Encrypt packet
        enc_ja = encrypt_packet(ja, appkey=appkey)

        # Check result
        assert bytes(enc_ja) == encrypted_join_accept

    def test_decrypt_join_accept(self, appkey, encrypted_join_accept):
        """Test Join Accept decryption
        """
        # Build our encrypted Join Accept
        enc_ja = PHYPayload(encrypted_join_accept)

        assert enc_ja.mtype == 1

        # Decrypt
        ja = decrypt_packet(enc_ja, appkey=appkey)

        # Check result
        assert ja.mtype == 1
        ja = ja.getlayer(JoinAccept)
        assert ja.join_nonce == 0x123456
        assert ja.home_netid == 0x42
        assert ja.dev_addr == 0xaabbcc
