from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from whad.ble.crypto import (
    aes_cmac,
    generate_diffie_hellman_shared_secret,
    generate_public_key_from_coordinates,
    generate_p256_keypair,
    generate_random_value,
    e,
    xor,
)
from cryptography.hazmat.primitives.asymmetric.ec import derive_private_key, SECP256R1
from random import randbytes


def aes_ccm(key, nonce, plaintext, additional_data=b""):
    """
    Implements AES_CCM, defined in Mesh Profile Specification, p.102 , Section 3.8.2.3.
    """
    cipher = AES.new(
        key, AES.MODE_CCM, nonce=nonce, mac_len=4, assoc_len=len(additional_data)
    )
    cipher.update(additional_data)
    ciphertext = cipher.encrypt(plaintext)
    mic = cipher.digest()
    return ciphertext, mic


def hmac_sha256(key, message):
    """
    Implements HMAC-SHA-256, defined in Mesh Protocol Specification, p. 190, Section 3.9.2.4
    """
    return HMAC.new(key, digestmod=SHA256).update(message).digest()


def s1(m):
    """
    Implements s1 SALT generation function,  defined in Mesh Profile Specification, p.102 , Section 3.8.2.4.
    """
    return aes_cmac(b"\x00" * 16, m)


def s2(m):
    """
    Implements s1 SALT generation function, defined in Mesh Protocol Specification p.190, Section 3.9.2.6
    """
    return hmac_sha256(b"\x00" * 32, m)


def k1(n, salt, p):
    """
    Implements k1 derivation function,  defined in Mesh Profile Specification, p.103 , Section 3.8.2.5.
    """
    t = aes_cmac(salt, n)
    return aes_cmac(t, p)


def k2(n, p):
    """
    Implements k2 network key material derivation function,  defined in Mesh Profile Specification, p.103 , Section 3.8.2.6.
    """
    salt = s1(b"smk2")
    t = aes_cmac(salt, n)
    t0 = b""
    t1 = aes_cmac(t, t0 + p + b"\x01")
    t2 = aes_cmac(t, t1 + p + b"\x02")
    t3 = aes_cmac(t, t2 + p + b"\x03")
    return (int.from_bytes((t1 + t2 + t3), byteorder="big") % (2**263)).to_bytes(
        33, byteorder="big"
    )


def k3(n):
    """
    Implements k3 derivation function,  defined in Mesh Profile Specification, p.104 , Section 3.8.2.7.
    """
    salt = s1(b"smk3")
    t = aes_cmac(salt, n)
    return (
        int.from_bytes(aes_cmac(t, b"id64" + b"\x01"), byteorder="big") % (2**64)
    ).to_bytes(8, byteorder="big")


def k4(n):
    """
    Implements k4 derivation function,  defined in Mesh Profile Specification, p.104 , Section 3.8.2.8.
    """
    salt = s1(b"smk4")
    t = aes_cmac(salt, n)
    return (
        int.from_bytes(aes_cmac(t, b"id6" + b"\x01"), byteorder="big") % (2**6)
    ).to_bytes(1, byteorder="big")


def k5(n, salt, p):
    """
    Implements k5 derivation function, defined in Mesh Protocol Specification, p.193, Section 3.9.2.11
    """
    t = hmac_sha256(salt, n)
    return hmac_sha256(t, p)


def generate_private_key_from_bytes(hex_key):
    """
    Converts the private key in bytes format to an EllipticCurvePrivateKey
    """
    return derive_private_key(
        int.from_bytes(hex_key, byteorder="big"),
        SECP256R1(),  # You can change this to the appropriate curve if needed
    )


"""
PROVISIONING SECURITY
"""


class ProvisioningBearerAdvCryptoManager:
    """
    This class implements the PB-ADV encryption and authentication mechanisms.
    """

    def __init__(
        self,
        alg="BTM_ECDH_P256_HMAC_SHA256_AES_CCM",
        private_key_provisionee=None,
        private_key_provisioner=None,
        public_key_coord_provisionee=None,
        public_key_coord_provisioner=None,
        rand_provisioner=None,
        rand_provisionee=None,
        auth_value=None,
        *,
        test=False,
    ):
        """
        Constructor for testing when we already have values
        """

        # if not intancited for test, do nothing
        self.alg = alg
        self.private_key_provisionee = private_key_provisionee
        self.private_key_provisioner = private_key_provisioner
        self.public_key_coord_provisionee = public_key_coord_provisionee
        self.public_key_coord_provisioner = public_key_coord_provisioner
        self.rand_provisioner = rand_provisioner
        self.rand_provisionee = rand_provisionee
        self.auth_value = auth_value

        self.session_key = None
        self.session_nonce = None
        self.confirmation_salt = None
        self.provisioning_salt = None
        self.confirmation_key = None
        self.confirmation_provisioner = None
        self.confirmation_provisionee = None

        # if in test mode, we directly compute the ecdh secret
        if test:
            self.compute_ecdh_secret()
        # if not in test, set default auth_value if no OOB will be used
        else:
            if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
                self.auth_value = b"\x00" * 16
            elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
                self.auth_value = b"\x00" * 32

    def set_alg(self, alg):
        self.alg = alg

    def compute_ecdh_secret(self):
        """
        Get the keys in the correct format to compute ECDH shared secret
        Only for test we need to process like this, overwritten in subclasses
        """
        if self.private_key_provisioner is not None:
            public_key_provisionee = generate_public_key_from_coordinates(
                int.from_bytes(self.public_key_coord_provisionee[0], "big"),
                int.from_bytes(self.public_key_coord_provisionee[1], "big"),
            )
            self.private_key_provisioner = generate_private_key_from_bytes(
                self.private_key_provisioner
            )
            self.ecdh_secret = generate_diffie_hellman_shared_secret(
                self.private_key_provisioner, public_key_provisionee
            )

        elif self.private_key_provisionee is not None:
            public_key_provisioner = generate_public_key_from_coordinates(
                int.from_bytes(self.public_key_coord_provisioner[0], "big"),
                int.from_bytes(self.public_key_coord_provisioner[1], "big"),
            )
            self.private_key_provisionee = generate_private_key_from_bytes(
                self.private_key_provisionee
            )
            self.ecdh_secret = generate_diffie_hellman_shared_secret(
                self.private_key_provisionee, public_key_provisioner
            )

    def compute_confirmation_salt(
        self,
        provisioning_invite_pdu,
        provisioning_capabilities_pdu,
        provisioning_start_pdu,
    ):
        """
        Computes the Confirmation Salt, defined in Mesh Protocol Specification, p. 593, Section 5.4.2.4.1
        pub_keys are concat of x and y coordinates
        """

        confirmation_inputs = (
            provisioning_invite_pdu
            + provisioning_capabilities_pdu
            + provisioning_start_pdu
            + self.public_key_coord_provisioner[0]
            + self.public_key_coord_provisioner[1]
            + self.public_key_coord_provisionee[0]
            + self.public_key_coord_provisionee[1]
        )

        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.confirmation_salt = s1(confirmation_inputs)

        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.confirmation_salt = s2(confirmation_inputs)

    def compute_confirmation_key(self):
        """
        Computes Confirmation Key, defined in Mesh Protocol Specification, p. 593, Section 5.4.2.4.1
        """
        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.confirmation_key = k1(
                self.ecdh_secret, self.confirmation_salt, b"prck"
            )

        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.confirmation_key = k5(
                self.ecdh_secret + self.auth_value, self.confirmation_salt, b"prck256"
            )

    def compute_confirmation_provisioner(self):
        """
        Computes Confirmation Provisioner, defined in Mesh Protocol Specification, p. 593, Section 5.4.2.4.1
        """
        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.confirmation_provisioner = aes_cmac(
                self.confirmation_key, self.rand_provisioner + self.auth_value
            )

        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.confirmation_provisioner = hmac_sha256(
                self.confirmation_key, self.rand_provisioner
            )

    def compute_confirmation_provisionee(self):
        """
        Computes Confirmation Provisionee, defined in Mesh Protocol Specification, p. 593, Section 5.4.2.4.1
        """
        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.confirmation_provisionee = aes_cmac(
                self.confirmation_key, self.rand_provisionee + self.auth_value
            )

        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.confirmation_provisionee = hmac_sha256(
                self.confirmation_key, self.rand_provisionee
            )

    def compute_provisioning_salt(self):
        """
        Computes the Provisioning Salt, defined in Mesh Protocol Specification, p. 602, Section 5.4.2.5
        """
        self.provisioning_salt = s1(
            self.confirmation_salt + self.rand_provisioner + self.rand_provisionee
        )

    def compute_session_key(self):
        """
        Computes Session Key, defined in Mesh Protocol Specification, p. 602 Section 5.4.2.5
        """
        self.session_key = k1(self.ecdh_secret, self.provisioning_salt, b"prsk")

    def compute_session_nonce(self):
        """
        Computes Session Nonce, defined in Mesh Protocol Specification, p. 602 Section 5.4.2.5
        """
        self.session_nonce = k1(self.ecdh_secret, self.provisioning_salt, b"prsn")[-13:]

    def encrypt(self, plaintext):
        """
        Encrypts the Provisioning Data, process defined in Mesh Protocol Specification, p. 603, Section 5.4.2.5
        """
        aes_ccm = AES.new(
            self.session_key, AES.MODE_CCM, nonce=self.session_nonce, mac_len=8
        )
        cipher = aes_ccm.encrypt(plaintext)
        mic = aes_ccm.digest()
        return cipher, mic

    def decrypt(self, cipher, mic):
        """
        Encrypts the Provisioning Data, process defined in Mesh Protocol Specification, p. 603, Section 5.4.2.5
        """
        aes_ccm = AES.new(
            self.session_key, AES.MODE_CCM, nonce=self.session_nonce, mac_len=8
        )
        plaintext = aes_ccm.decrypt(cipher)
        try:
            aes_ccm.verify(mic)
            return (plaintext, True)
        except ValueError:
            return (plaintext, False)


class ProvisioningBearerAdvCryptoManagerProvisioner(ProvisioningBearerAdvCryptoManager):
    def __init__(self, alg):
        super().__init__(alg=alg)  # does nothing, but better to have super...
        self.public_key_provisionee = None
        self.public_key_provisioner = None
        self.received_confirmation_provisionee = None

    def generate_keypair(self):
        """Generate the P256 private key / public key"""
        self.private_key_provisioner, self.public_key_provisioner = (
            generate_p256_keypair()
        )
        public_key_numbers = self.public_key_provisioner.public_numbers()
        self.public_key_coord_provisioner = (
            public_key_numbers.x.to_bytes(32, "big"),
            public_key_numbers.y.to_bytes(32, "big"),
        )

    def compute_ecdh_secret(self):
        """
        Get the keys in the correct format to compute ECDH shared secret
        """
        self.ecdh_secret = generate_diffie_hellman_shared_secret(
            self.private_key_provisioner, self.public_key_provisionee
        )

    def add_peer_public_key(self, public_key_x, public_key_y):
        self.public_key_provisionee = generate_public_key_from_coordinates(
            int.from_bytes(public_key_x, "big"),
            int.from_bytes(public_key_y, "big"),
        )

        self.public_key_coord_provisionee = (public_key_x, public_key_y)

    def generate_random(self):
        """
        Generates the random values used in Confirmation Process
        NOT SAFE
        """
        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.rand_provisioner = randbytes(16)
        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.rand_provisioner = randbytes(32)


class ProvisioningBearerAdvCryptoManagerProvisionee(ProvisioningBearerAdvCryptoManager):
    def __init__(self, alg):
        super().__init__(alg=alg)  # does nothing, but better to have super...
        self.public_key_provisionee = None
        self.public_key_provisioner = None
        self.received_confirmation_provisioner = None

    def generate_keypair(self):
        """Generate the P256 private key / public key"""
        self.private_key_provisionee, self.public_key_provisionee = (
            generate_p256_keypair()
        )

        # Get coordinates format for the Provisioning Packets
        public_key_numbers = self.public_key_provisionee.public_numbers()
        self.public_key_coord_provisionee = (
            public_key_numbers.x.to_bytes(32, "big"),
            public_key_numbers.y.to_bytes(32, "big"),
        )

    def compute_ecdh_secret(self):
        """
        Get the keys in the correct format to compute ECDH shared secret
        """
        self.ecdh_secret = generate_diffie_hellman_shared_secret(
            self.private_key_provisionee, self.public_key_provisioner
        )

    def add_peer_public_key(self, public_key_x, public_key_y):
        self.public_key_provisioner = generate_public_key_from_coordinates(
            int.from_bytes(public_key_x, "big"), int.from_bytes(public_key_y, "big")
        )

        self.public_key_coord_provisioner = (public_key_x, public_key_y)

    def generate_random(self):
        """
        Generates the random values used in Confirmation Process
        NOT SAFE
        """
        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.rand_provisionee = randbytes(16)
        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.rand_provisionee = randbytes(32)


"""
NETWORK LAYER SECURITY
"""


class NetworkLayerCryptoManager:
    """
    Manages one network bound to ONE network key and its key id.
    Handles crypto for Network PDUs as well as Secure Network Beacons and Mesh Private Beacons
    bound to this network.
    """

    def __init__(self, key_index, net_key=None, iv_index=b"\x00\x00\x00\x00"):
        # if no net_key given
        if net_key is None:
            self.net_key = generate_random_value(128)
        else:
            self.net_key = net_key

        self.key_index = key_index
        self.iv_index = iv_index

        self.__compute_sub_keys()

    def __compute_sub_keys(self):
        """
        Computes all keys binded to the network key. Mesh Spec Section 3.9.6.3 p.201
        """

        # NID, EncryptionKey and PrivacyKey
        self.nid, self.enc_key, self.privacy_key = (
            self.__compute_nid_enc_key_privacy_key()
        )

        # NetworkID
        self.network_id = self.__compute_network_id()

        # IdentityKey
        self.identity_key = self.__compute_identity_key()

        # BeaconKey
        self.beacon_key = self.__compute_beacon_key()

        # PrivateBeaconKey
        self.private_beacon_key = self.__compute_private_beacon_key()

    def __compute_identity_key(self):
        """
        Computes IdentityKey, Mesh Spec Section 3.9.6.3.3 p. 202
        """
        salt = s1(b"nkik")
        p = b"id128" + b"\x01"
        return k1(self.net_key, salt, p)

    def __compute_beacon_key(self):
        """
        Computes the BeaconKey, Mesh Spec Section 3.9.6.3.4 p. 203
        """
        salt = s1(b"nkbk")
        p = b"id128" + b"\x01"
        return k1(self.net_key, salt, p)

    def __compute_private_beacon_key(self):
        """
        Computes the PrivateBeaconKey, Mesh Spec Section 3.9.6.3.5 p. 203
        """
        salt = s1(b"nkpk")
        p = b"id128" + b"\x01"
        return k1(self.net_key, salt, p)

    def __compute_nid_enc_key_privacy_key(self):
        """
        Computes the NID, Encryption Key and PrivacyKey. Mesh Spec Section 3.9.6.3.1 p. 201
        ONLY FOR MANAGED FLOODING SO FAR
        """
        key = k2(self.net_key, b"\x00")
        nid = key[0]
        enc_key = key[1:17]
        privacy_key = key[17:33]
        return nid, enc_key, privacy_key

    def __compute_network_id(self):
        """
        Computes the Network ID. Mesh Spec Section 3.9.6.3.2 p. 202
        """
        return k3(self.net_key)

    def encrypt(self, raw_transport_pdu, net_pdu):
        """
        Encrypts the transport PDU. Mesh Spec Section 3.9.7.2 p. 206

        :param raw_transport_pdu: Plaintext transport PDU
        :type raw_transport_pdu: Bytes
        :param net_pdu Partial Network PDU with information to compute the NetworkNonce and the dest addr
        :type net_pdu: BTMesh_Network_PDU
        """

        # Mesh Spec Section 3.9.5.1 p. 194
        nonce = (
            b"\x00"
            + (net_pdu.network_ctl << 7 | net_pdu.ttl).to_bytes(1, "big")
            + net_pdu.seq_number
            + net_pdu.src_addr
            + b"\x00" * 2
            + self.iv_index
        )

        if net_pdu.network_ctl == 1:
            mac_len = 8
        else:
            mac_len = 4

        aes_ccm = AES.new(self.enc_key, AES.MODE_CCM, nonce=nonce, mac_len=mac_len)
        cipher = aes_ccm.encrypt(net_pdu.dst_addr + raw_transport_pdu)
        mic = aes_ccm.digest()
        # First 2 bytes -> enc_dst. Rest is enc Transport PDU and MIC
        return cipher + mic

    def decrypt(self, net_pdu):
        """
        Decrypts the transport PDU. Mesh Spec Section 3.9.7.2 p. 206

        :param net_pdu: Net_pdu received (after deobfuscation)
        :type net_pdu: BTMesh_Network_PDU
        :returns:  The plaintext of Network PDU and boolean for the MIC check
        :rtype: (Bytes, boolean)
        """

        # Mesh Spec Section 3.9.5.1 p. 194
        nonce = (
            b"\x00"
            + (net_pdu.network_ctl << 7 | net_pdu.ttl).to_bytes(1, "big")
            + net_pdu.seq_number.to_bytes(3, "big")
            + net_pdu.src_addr
            + b"\x00" * 2
            + self.iv_index
        )

        if net_pdu.network_ctl == 1:
            mac_len = 8
        else:
            mac_len = 4
        mic = net_pdu.enc_dst_enc_transport_pdu_mic[-mac_len:]
        cipher = net_pdu.enc_dst_enc_transport_pdu_mic[:-mac_len]
        aes_ccm = AES.new(self.enc_key, AES.MODE_CCM, nonce=nonce, mac_len=mac_len)
        plaintext = aes_ccm.decrypt(cipher)
        try:
            aes_ccm.verify(mic)
            return (plaintext, True)
        except ValueError:
            return (plaintext, False)

    def obfuscate_net_pdu(self, net_pdu):
        """
        Obfuscates the network_pdu (a complete one with encrypted transport PDU and MIC).
        Mesh Spec Section 3.9.7.3 p. 206

        :param net_pdu: Network PDU to be obfuscated
        :type net_pdu: BTMesh_Network_PDU
        :returns: Obfuscated part of Network PDU
        :rtype: Bytes
        """
        privacy_random = net_pdu.enc_dst_enc_transport_pdu_mic[0:7]
        privacy_plaintext = b"\x00" * 5 + self.iv_index + privacy_random
        pecb = e(self.privacy_key, privacy_plaintext)
        obfuscated_data = xor(
            (net_pdu.network_ctl << 7 | net_pdu.ttl).to_bytes(1, "big")
            + net_pdu.seq_number.to_bytes(3, "big")
            + net_pdu.src_addr.to_bytes(2, "big"),
            pecb[0:6],
        )
        return obfuscated_data

    def deobfuscate_net_pdu(self, obf_net_pdu):
        """
        Obfuscates the network_pdu (an obfuscated one).
        Mesh Spec Section 3.9.7.3 p. 206

        :param obf_net_pdu: Network PDU to be deobfuscated
        :type obf_net_pdu: BTMesh_Obsfucated_Network_PDU
        :returns: The raw blob of deobfuscated data
        :type: Bytes
        """
        obf_net_pdu.show()
        print(obf_net_pdu.obfuscated_data)
        privacy_random = obf_net_pdu.enc_dst_enc_transport_pdu_mic[0:7]
        privacy_plaintext = b"\x00" * 5 + self.iv_index + privacy_random
        pecb = e(self.privacy_key, privacy_plaintext)
        plaintext = xor(obf_net_pdu.obfuscated_data, pecb[0:6])
        return plaintext

    def check_secure_beacon_auth_value(self, security_beacon):
        """
        Checks if a received Secure Beacon of the Network as a correct Authentication Value.
        Mesh Specification Section 3.10.3 p. 214

        :param security_beacon: The received Secure Network Beacon
        :type security_beacon: BTMesh_Secure_Network_Beacon
        :returns: True if check ok, Flase otherwise
        :rtype: boolean
        """
        data = (
            (
                security_beacon.key_refresh_flag << 7
                | security_beacon.iv_update_flag << 6
                | security_beacon.unused
            ).to_bytes(1, "big")
            + security_beacon.nid
            + security_beacon.ivi
        )
        expected_auth_value = aes_cmac(self.beacon_key, data)
        return expected_auth_value == security_beacon.authentication_value

    def obfuscate_private_beacon(self, clear_private_beacon):
        """
        Obfuscates the Private Beacon Data. Generates the Random as well
        Mesh Spec Section 3.10.4.1 p. 217

        :param clear_private_beacon: The private Beacon to be obfuscated
        :type clear_private_beacon: BTMesh_Private_Beacon
        :returns: Raw blobs of obfuscated private beacon data, random data and authentication_tag
        :rtype: (Bytes, Bytes, Bytes)
        """
        private_beacon_data = (
            clear_private_beacon.key_refresh_flag << 7
            | clear_private_beacon.iv_update_flag << 6
            | clear_private_beacon.unused
        ).to_bytes(1, "big")

        # setup intermidiate values
        random = generate_random_value(104)
        b0 = b"\x19" + random + "b\x00\x05"
        c0 = b"\x00" + random + b"\x00\x00"
        c1 = b"\x01" + random + b"\x00\x01"

        p = private_beacon_data + b"\x00" * 11

        # authentication_tag computation
        t0 = e(self.private_beacon_key, b0)
        t1 = e(self.private_beacon_key, xor(t0, p))
        t2 = xor(t1, e(self.private_beacon_key, c0))
        authentication_tag = t2[0:8]

        # computation of obfuscated_data
        s = e(self.private_beacon_key, c1)
        obfuscated_data = xor(s[0:5], private_beacon_data)
        return random, obfuscated_data, authentication_tag

    def deobfuscate_private_beacon(self, private_beacon):
        """
        Deobfuscate an obfuscated private beacon.
        Mesh Spec Section 3.10.4.1 p. 217

        :param private_beacon: Private beacon to be deobfuscated
        :type private_beacon: BTMesh_Obsfucated_Private_Beacon
        :returns: Clear private_beacon_data and result of authentication_tag check
        :rtype: (Bytes, boolean)
        """

        # setup intermidiate values
        random = private_beacon.random
        b0 = b"\x19" + random + "b\x00\x05"
        c0 = b"\x00" + random + b"\x00\x00"
        c1 = b"\x01" + random + b"\x00\x01"

        # deobfuscate
        s = e(self.private_beacon_key, c1)
        private_beacon_data = xor(s[0:5], private_beacon.obfuscated_private_beacon_data)
        # Check authentication_tag
        p = private_beacon_data + b"\x00" * 11

        t0 = e(self.private_beacon_key, b0)
        t1 = e(self.private_beacon_key, xor(t0, p))
        t2 = xor(t1, e(self.private_beacon_key, c0))
        authentication_tag = t2[0:8]
        is_auth_tag_valid = authentication_tag == private_beacon.authentication_tag
        return private_beacon_data, is_auth_tag_valid
