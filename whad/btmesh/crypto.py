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
from os import urandom


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


def compute_virtual_addr_from_label_uuid(label):
    """
    Computes the virtual addr based on the label UUID
    Mesh Prt Specification Section 3.4.2.3

    :param label: Label UUID
    :type label: Bytes
    """
    salt = s1(b"vtad")
    va = int.from_bytes(aes_cmac(salt, label), "big") % (2**14)
    va = (va & 0b10 << 14).to_bytes(2, "big")
    return va


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
            self.set_auth_value(0)

    def set_alg(self, alg):
        self.alg = alg

    def set_auth_value(self, value):
        """
        Sets the auth value in the correct format

        :param value: The auth_value
        :type value: int | bytes
        """

        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            size = 16
        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            size = 32

        if type(value) is int:
            self.auth_value = value.to_bytes(size, "big")
        elif type(value) is str:
            try:
                self.auth_value = value.encode("ascii").ljust(size, b"\x00")[:size]
            except UnicodeEncodeError:
                return

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
            self.rand_provisioner = urandom(16)
        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.rand_provisioner = urandom(32)


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
            self.rand_provisionee = urandom(16)
        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.rand_provisionee = urandom(32)


"""
NETWORK LAYER SECURITY
"""


class NetworkLayerCryptoManager:
    """
    Manages one (sub)network bound to ONE network key and its key id.
    Handles crypto for Network PDUs as well as Secure Network Beacons and Mesh Private Beacons
    bound to this network. Lives in the net_key_list state of the ConfigurationServerModel
    Associated with on Subnet
    """

    def __init__(self, key_index, net_key=None):
        # if no net_key given
        if net_key is None:
            self.net_key = generate_random_value(128)
        else:
            self.net_key = net_key

        self.key_index = key_index
        # List of bound app key indexes to this network key
        self.app_key_indexes = []

        # Used when key is updated, old key is stored here only for decipher
        self.old_net_key = None

        self.__compute_sub_keys()

    def __compute_sub_keys(self):
        """
        Computes all keys binded to the network key. Mesh Spec Section 3.9.6.3 p.201
        """

        # NID, EncryptionKey and PrivacyKey
        # managed flooding
        self.nid_mf, self.enc_key_mf, self.privacy_key_mf = (
            self.__compute_nid_enc_key_privacy_key_managed_flooding()
        )

        # NID, EncryptionKey and PrivacyKey
        # directed forwarding
        self.nid_df, self.enc_key_df, self.privacy_key_df = (
            self.__compute_nid_enc_key_privacy_key_directed_forwarding()
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

    def __compute_nid_enc_key_privacy_key_managed_flooding(self):
        """
        Computes the NID, Encryption Key and PrivacyKey. Mesh Spec Section 3.9.6.3.1 p. 201
        For managed flooding credentials
        """
        key = k2(self.net_key, b"\x00")
        nid = key[0]
        enc_key = key[1:17]
        privacy_key = key[17:33]
        return nid, enc_key, privacy_key

    def __compute_nid_enc_key_privacy_key_directed_forwarding(self):
        """
        Computes the NID, Encryption Key and PrivacyKey. Mesh Spec Section 3.9.6.3.1 p. 201
        For directed forwarding credentials
        """
        key = k2(self.net_key, b"\x02")
        nid = key[0]
        enc_key = key[1:17]
        privacy_key = key[17:33]
        return nid, enc_key, privacy_key

    def __compute_network_id(self):
        """
        Computes the Network ID. Mesh Spec Section 3.9.6.3.2 p. 202
        """
        return int.from_bytes(k3(self.net_key), "big")

    def add_app_key_index(self, app_key_index):
        """
        Adds an AppKey index bounded to this network key

        :param app_key_crypto_manager: The App key index
        :type app_key_crypto_manager: index
        """
        if app_key_index not in self.app_key_indexes:
            self.app_key_indexes.append(app_key_index)

    def encrypt(self, raw_transport_pdu, clear_dst_addr, net_pdu, iv_index):
        """
        Encrypts the transport PDU. Mesh Spec Section 3.9.7.2 p. 206

        :param raw_transport_pdu: Plaintext transport PDU
        :type raw_transport_pdu: Bytes
        :param clear_dst_addr: The plaintext dst_addr to be encrypted
        :type clear_dst_addr: int
        :param net_pdu: Partial Network PDU with information to compute the NetworkNonce and the dest addr
        :type net_pdu: BTMesh_Network_PDU
        :param iv_index: The current iv_index
        :type iv_index: Bytes
        """

        clear_dst_addr = clear_dst_addr.to_bytes(2, "big")

        # Mesh Spec Section 3.9.5.1 p. 194
        nonce = (
            b"\x00"
            + (net_pdu.network_ctl << 7 | net_pdu.ttl).to_bytes(1, "big")
            + net_pdu.seq_number.to_bytes(3, "big")
            + net_pdu.src_addr.to_bytes(2, "big")
            + b"\x00" * 2
            + iv_index
        )

        if net_pdu.network_ctl == 1:
            mac_len = 8
        else:
            mac_len = 4

        # check nid in net_pdu to figure out creds to use
        if net_pdu.nid == self.nid_mf:
            aes_ccm = AES.new(
                self.enc_key_mf, AES.MODE_CCM, nonce=nonce, mac_len=mac_len
            )
        elif net_pdu.nid == self.nid_df:
            aes_ccm = AES.new(
                self.enc_key_df, AES.MODE_CCM, nonce=nonce, mac_len=mac_len
            )
        cipher = aes_ccm.encrypt(clear_dst_addr + raw_transport_pdu)
        mic = aes_ccm.digest()
        # First 2 bytes -> enc_dst. Rest is enc Transport PDU and MIC
        return cipher + mic

    def decrypt(self, net_pdu, iv_index):
        """
        Decrypts the transport PDU. Mesh Spec Section 3.9.7.2 p. 206

        :param net_pdu: Net_pdu received (after deobfuscation)
        :type net_pdu: BTMesh_Network_PDU
        :param iv_index: The current IV_index
        :type iv_index: Bytes
        :returns:  The plaintext of Network PDU and boolean for the MIC check
        :rtype: (Bytes, boolean)
        """

        # Mesh Spec Section 3.9.5.1 p. 194
        nonce = (
            b"\x00"
            + (net_pdu.network_ctl << 7 | net_pdu.ttl).to_bytes(1, "big")
            + net_pdu.seq_number.to_bytes(3, "big")
            + net_pdu.src_addr.to_bytes(2, "big")
            + b"\x00" * 2
            + iv_index
        )

        if net_pdu.network_ctl == 1:
            mac_len = 8
        else:
            mac_len = 4
        mic = net_pdu.enc_dst_enc_transport_pdu_mic[-mac_len:]
        cipher = net_pdu.enc_dst_enc_transport_pdu_mic[:-mac_len]

        # check nid in net_pdu to figure out creds to use
        if net_pdu.nid == self.nid_mf:
            aes_ccm = AES.new(
                self.enc_key_mf, AES.MODE_CCM, nonce=nonce, mac_len=mac_len
            )
        elif net_pdu.nid == self.nid_df:
            aes_ccm = AES.new(
                self.enc_key_df, AES.MODE_CCM, nonce=nonce, mac_len=mac_len
            )

        plaintext = aes_ccm.decrypt(cipher)
        try:
            aes_ccm.verify(mic)
            return (plaintext, True)
        except ValueError:
            return (plaintext, False)

    def obfuscate_net_pdu(self, net_pdu, iv_index):
        """
        Obfuscates the network_pdu (a complete one with encrypted transport PDU and MIC).
        Mesh Spec Section 3.9.7.3 p. 206

        :param net_pdu: Network PDU to be obfuscated
        :type net_pdu: BTMesh_Network_PDU
        :param iv_index: The current IV_index
        :type iv_index: Bytes
        :returns: Obfuscated part of Network PDU
        :rtype: Bytes
        """
        privacy_random = net_pdu.enc_dst_enc_transport_pdu_mic[0:7]
        privacy_plaintext = b"\x00" * 5 + iv_index + privacy_random

        # check nid to figure out which credentials to use
        if net_pdu.nid == self.nid_mf:
            pecb = e(self.privacy_key_mf, privacy_plaintext)
        elif net_pdu.nid == self.nid_df:
            pecb = e(self.privacy_key_df, privacy_plaintext)

        obfuscated_data = xor(
            (net_pdu.network_ctl << 7 | net_pdu.ttl).to_bytes(1, "big")
            + net_pdu.seq_number.to_bytes(3, "big")
            + net_pdu.src_addr.to_bytes(2, "big"),
            pecb[0:6],
        )
        return obfuscated_data

    def deobfuscate_net_pdu(self, obf_net_pdu, iv_index):
        """
        Obfuscates the network_pdu (an obfuscated one).
        Mesh Spec Section 3.9.7.3 p. 206

        :param obf_net_pdu: Network PDU to be deobfuscated
        :type obf_net_pdu: BTMesh_Obsfucated_Network_PDU
        :param iv_index: The current IV_index
        :type iv_index: Bytes
        :returns: The raw blob of deobfuscated data
        :type: Bytes
        """
        privacy_random = obf_net_pdu.enc_dst_enc_transport_pdu_mic[0:7]
        privacy_plaintext = b"\x00" * 5 + iv_index + privacy_random

        # check nid to figure out which credentials to use
        if obf_net_pdu.nid == self.nid_mf:
            pecb = e(self.privacy_key_mf, privacy_plaintext)
        elif obf_net_pdu.nid == self.nid_df:
            pecb = e(self.privacy_key_df, privacy_plaintext)

        plaintext = xor(obf_net_pdu.obfuscated_data, pecb[0:6])
        return plaintext

    def compute_secure_beacon_auth_value(self, security_beacon):
        """
        Computes the authentication value of the Security Mesh Beacon. Can be to verify it or to compute in order to send it.
        Mesh Specification Section 3.10.3 p. 214

        :param security_beacon: The partiel Secure Network Beacon (no authentication_value)
        :type security_beacon: BTMesh_Secure_Network_Beacon
        :returns: Authentication Value
        :rtype: Bytes
        """
        data = (
            (
                security_beacon.key_refresh_flag | security_beacon.iv_update_flag << 1
            ).to_bytes(1, "big")
            + security_beacon.nid.to_bytes(8, "big")
            + security_beacon.ivi.to_bytes(4, "big")
        )
        expected_auth_value = aes_cmac(self.beacon_key, data)
        return expected_auth_value[0:8]

    def check_secure_beacon_auth_value(self, security_beacon):
        """
        Checks if a received Secure Beacon of the Network as a correct Authentication Value.
        Mesh Specification Section 3.10.3 p. 214

        :param security_beacon: The received Secure Network Beacon
        :type security_beacon: BTMesh_Secure_Network_Beacon
        :returns: True if check ok, Flase otherwise
        :rtype: boolean
        """
        expected_auth_value = self.compute_secure_beacon_auth_value(security_beacon)
        return expected_auth_value == security_beacon.authentication_value

    def obfuscate_private_beacon(self, clear_private_beacon, random=None):
        """
        Obfuscates the Private Beacon Data. Generates the Random as well
        Mesh Spec Section 3.10.4.1 p. 217

        :param clear_private_beacon: The private Beacon to be obfuscated (no random or authentication_tag, only flags)
        :type clear_private_beacon: BTMesh_Private_Beacon
        :param random: Set fixed random, TESTS ONLY
        :returns: Raw blobs of (in order) random data, obfuscated private beacon data and authentication_tag
        :rtype: (Bytes, Bytes, Bytes)
        """
        private_beacon_data = (
            clear_private_beacon.key_refresh_flag
            | clear_private_beacon.iv_update_flag << 1
        ).to_bytes(1, "big") + clear_private_beacon.ivi.to_bytes(4, "big")

        # setup intermidiate values
        if random is None:
            random = generate_random_value(104)

        b0 = b"\x19" + random + b"\x00\x05"
        c0 = b"\x01" + random + b"\x00\x00"
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
        b0 = b"\x19" + random + b"\x00\x05"
        c0 = b"\x01" + random + b"\x00\x00"
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


class UpperTransportLayerAppKeyCryptoManager:
    """
    Manages upper layer cyptography (application keys). All keys for one network are managed here.
    This manages ONE application key.
    The UpperTransportLayer state manages all the application keys bound to the network it sits in.
    """

    def __init__(self, app_key=None, key_index=0, net_key_index=0):
        """
        Creates the app key from a given value (or random generation)

        :param app_key: Value of the app key, defaults to None
        :type app_key: Bytes, optional
        :param key_index: app_key_index of the key, defaults to 0
        :type key_index: int, optional
        :param net_key_index: Index of the net_key this app_key is bound to, defaults to 0
        :type net_key_index: int, optional
        """
        if app_key is None:
            self.app_key = generate_random_value(128)
        else:
            self.app_key = app_key

        # Application Key Identifier
        self.aid = self.__compute_aid()

        # index of the net key this app key in bound to
        self.net_key_index = net_key_index

        self.key_index = key_index

    def __compute_aid(self):
        return int.from_bytes(k4(self.app_key), "big")

    """
    Need to have an encrypting/decrypting function for each combination of :
    - type of destination address
    - unsegmeneted/segmented on lower transport
    For encryption -> always size_trans_mic = 32 bits (since we can either choose OR forced to 32 so ...)
    For decryption -> depends if unseg/seg. If unseg, 32 bits. If seg, depends on field in Lower Transport
    """

    def __compute_seq_auth(self, iv_index, seq_number):
        """
        Compute the SeqAuth value (Mesh Spec Section 3.5.3.1)

        :param iv_index: [TODO:description]
        :type iv_index: [TODO:type]
        :param seq_number: [TODO:description]
        :type seq_number: [TODO:type]
        """
        return iv_index + seq_number.to_bytes(3, "big")

    def __compute_nonce(self, aszmic, seq_auth, src_addr, dst_addr, iv_index):
        return (
            b"\x01"
            + ((aszmic << 7) & 0x80).to_bytes(1, "big")
            + seq_auth[-3:]
            + src_addr
            + dst_addr
            + iv_index
        )

    def encrypt(
        self,
        access_message,
        aszmic,
        seq_number,
        src_addr,
        dst_addr,
        iv_index,
        label_uuid=None,
    ):
        """
        Encrypts the access_message with this application key.
        Mesh Spec Section 3.9.7.1 p. 205

        :param access_message: Raw Access message to be encrypted
        :type access_message: Bytes
        :param aszmic: Size of MIC value (0 or 1). For Nonce
        :type aszmic: int
        :param seq_number: segment number Value (of first segment)
        :type seq_number: int
        :param src_addr: Source addr of the packet
        :type src_addr: int
        :param dst_addr: Destination addr of the packet
        :type dst_addr: int
        :param iv_index: Current IV index
        :type iv_index: Bytes
        :param label_uuid: Label UUID associated with the virtual addr (Mesh Spec Section 3.4.2.3) if dst_addr is virtual addr
        :type label_uuid: Bytes
        :returns: The encrypted message concatenated with mic and the seq_auth value
        :rtype: (Bytes, int)
        """
        src_addr = src_addr.to_bytes(2, "big")
        dst_addr = dst_addr.to_bytes(2, "big")

        seq_auth = self.__compute_seq_auth(iv_index, seq_number)
        nonce = self.__compute_nonce(aszmic, seq_auth, src_addr, dst_addr, iv_index)

        if aszmic == 1:
            mac_len = 8
        else:
            mac_len = 4

        # check if dst_addr is virtual
        if (dst_addr[0] >> 6) & 0b11 == 0b10:
            aes_ccm = AES.new(
                self.app_key,
                AES.MODE_CCM,
                nonce=nonce,
                mac_len=mac_len,
                assoc_len=len(label_uuid),
            )
            aes_ccm.update(label_uuid)

        else:
            aes_ccm = AES.new(
                self.app_key,
                AES.MODE_CCM,
                nonce=nonce,
                mac_len=mac_len,
            )

        cipher = aes_ccm.encrypt(access_message)
        mic = aes_ccm.digest()
        return cipher + mic, int.from_bytes(seq_auth, "big")

    def decrypt(
        self,
        enc_data,
        aszmic,
        seq_number,
        src_addr,
        dst_addr,
        iv_index,
        label_uuid=None,
    ):
        """
        Decrypts the access_message with this application key.
        Mesh Spec Section 3.9.7.1 p. 205

        :param enc_data: Raw encrypted access message and mic
        :type enc_data: Bytes
        :param aszmic: Size of MIC value (0 or 1). For Nonce
        :type aszmic: int
        :param seq_number: segment number Value (of first segment)
        :type seq_number: int
        :param src_addr: Source addr of the packet
        :type src_addr: int
        :param dst_addr: Destination addr of the packet
        :type dst_addr: int
        :param iv_index: Current IV index
        :type iv_index: Bytes
        :param label_uuid: List of Label UUID that match with the virtual addr (Mesh Spec Section 3.4.2.3) if dst_addr is virtual addr.
        :type label_uuid: list(Bytes)
        :returns: The plaintext, wether authentication was valid and in case of virtual addr, the matching lable UUID that worked for the authentication
        :rtype: (Byte|None, (boolean Bytes|None)) or (Byte|None, boolean)
        """
        src_addr = src_addr.to_bytes(2, "big")
        dst_addr = dst_addr.to_bytes(2, "big")

        seq_auth = self.__compute_seq_auth(iv_index, seq_number)
        nonce = self.__compute_nonce(aszmic, seq_auth, src_addr, dst_addr, iv_index)

        if aszmic == 1:
            mac_len = 8
        else:
            mac_len = 4

        mic = enc_data[-mac_len:]
        cipher = enc_data[:-mac_len]

        # check if dst_addr is not virtual, simple decipher
        aes_ccm = AES.new(
            self.app_key,
            AES.MODE_CCM,
            nonce=nonce,
            mac_len=mac_len,
        )
        plaintext = aes_ccm.decrypt(cipher)
        try:
            aes_ccm.verify(mic)
            return (plaintext, True)
        except ValueError:
            return (plaintext, False)

    def decrypt_virtual(
        self,
        enc_data,
        aszmic,
        seq_number,
        src_addr,
        dst_addr,
        iv_index,
        label_uuids,
    ):
        """
        Decrypts the access_message with this application key if dest address is virtual
        Mesh Spec Section 3.9.7.1 p. 205

        :param enc_data: Raw encrypted access message and mic
        :type enc_data: Bytes
        :param aszmic: Size of MIC value (0 or 1). For Nonce
        :type aszmic: int
        :param seq_number: segment number Value (of first segment)
        :type seq_number: int
        :param src_addr: Source addr of the packet
        :type src_addr: int
        :param dst_addr: Destination addr of the packet
        :type dst_addr: int
        :param iv_index: Current IV index
        :type iv_index: Bytes
        :param label_uuids: List of Label UUID that match with the virtual addr (Mesh Spec Section 3.4.2.3) if dst_addr is virtual addr.
        :type label_uuids: list(Bytes)
        :returns: The plaintext, wether authentication was valid and in case of virtual addr, the matching lable UUID that worked for the authentication
        :rtype: (Byte|None, boolean, Bytes|None)
        """
        src_addr = src_addr.to_bytes(2, "big")
        dst_addr = dst_addr.to_bytes(2, "big")

        seq_auth = self.__compute_seq_auth(iv_index, seq_number)
        nonce = self.__compute_nonce(aszmic, seq_auth, src_addr, dst_addr, iv_index)

        if aszmic == 1:
            mac_len = 8
        else:
            mac_len = 4

        mic = enc_data[-mac_len:]
        cipher = enc_data[:-mac_len]

        # if dst_addr is virtual, need to check for all valid label UUID
        # check for each label UUID if it works for the authentication
        for label in label_uuids:
            aes_ccm = AES.new(
                self.app_key,
                AES.MODE_CCM,
                nonce=nonce,
                mac_len=mac_len,
                assoc_len=len(label),
            )
            aes_ccm.update(label)
            plaintext = aes_ccm.decrypt(cipher)
            try:
                aes_ccm.verify(mic)
                return (plaintext, True, label)
            except ValueError:
                continue

        # if no match when virtual addr, return False
        return (None, False, None)


class UpperTransportLayerDevKeyCryptoManager:
    """
    This manages a Device Key (that used in the UpperTransportLayer).
    ONE PER NODE (in theory) (bound to all networks).
    Generated after provisioning complete.
    """

    def __init__(self, provisioning_crypto_manager=None, device_key=None):
        """
        Either takes the ProvisioningBearerAdvCryptoManager object used during provisioning to derive the dev_key
        Or give directly the Device Key if already known.

        :param provisioning_capabilities_pdu: Provisioning Layer crypto manager (after provisioning is finished)
        :type net_key: ProvisioningBearerAdvCryptoManager
        :param device_key: Device Key (only for tests)
        :type device_key:Bytes
        """

        if device_key is not None:
            self.device_key = device_key
        elif provisioning_crypto_manager is not None:
            self.device_key = k1(
                provisioning_crypto_manager.ecdh_secret,
                provisioning_crypto_manager.provisioning_salt,
                b"prdk",
            )

        # place holder (used only in app keys)
        self.aid = -1

    def __compute_nonce(self, aszmic, seq_auth, src_addr, dst_addr, iv_index):
        return (
            b"\x02"
            + ((aszmic << 7) & 0x80).to_bytes(1, "big")
            + seq_auth[-3:]
            + src_addr
            + dst_addr
            + iv_index
        )

    def __compute_seq_auth(self, iv_index, seq_number):
        """
        Compute the SeqAuth value (Mesh Spec Section 3.5.3.1)

        :param iv_index: [TODO:description]
        :type iv_index: [TODO:type]
        :param seq_number: [TODO:description]
        :type seq_number: [TODO:type]
        """
        return iv_index + seq_number.to_bytes(3, "big")

    def encrypt(self, access_message, aszmic, seq_number, src_addr, dst_addr, iv_index):
        """
        Encrypts the access_message with the Device Key
        Mesh Spec Section 3.9.7.1 p. 205

        :param access_message: Raw Access message to be encrypted
        :type access_message: Bytes
        :param aszmic: Size of MIC value (0 or 1). For Nonce
        :type aszmic: int
        :param seq_number: segment number Value (of first segment)
        :type seq_number: Bytes
        :param src_addr: Source addr of the packet
        :type src_addr: int
        :param dst_addr: Destination addr of the packet
        :type dst_addr: int
        :param iv_index: Current IV index
        :type iv_index: Bytes
        :returns: The encrypted message concatenated with mic and the seq_auth value
        :rtype: (Bytes, Bytes)
        """
        src_addr = src_addr.to_bytes(2, "big")
        dst_addr = dst_addr.to_bytes(2, "big")

        seq_auth = self.__compute_seq_auth(iv_index, seq_number)
        nonce = self.__compute_nonce(aszmic, seq_auth, src_addr, dst_addr, iv_index)

        if aszmic == 1:
            mac_len = 8
        else:
            mac_len = 4

        aes_ccm = AES.new(
            self.device_key,
            AES.MODE_CCM,
            nonce=nonce,
            mac_len=mac_len,
        )

        cipher = aes_ccm.encrypt(access_message)
        mic = aes_ccm.digest()
        return cipher + mic, int.from_bytes(seq_auth, "big")

    def decrypt(self, enc_data, aszmic, seq_number, src_addr, dst_addr, iv_index):
        """
        Decrypts the access_message with the Device Key
        Mesh Spec Section 3.9.7.1 p. 205

        :param enc_data: Raw encrypted data and mic
        :type enc_data: Bytes
        :param aszmic: Size of MIC value (0 or 1). For Nonce
        :type aszmic: int
        :param seq_number: segment number Value (of first segment)
        :type seq_number: int
        :param src_addr: Source addr of the packet
        :type src_addr: int
        :param dst_addr: Destination addr of the packet
        :type dst_addr: int
        :param iv_index: Current IV index
        :type iv_index: Bytes
        :returns: The plaintext, wether authentication was valid.
        :rtype: (Byte, boolean)
        """

        src_addr = src_addr.to_bytes(2, "big")
        dst_addr = dst_addr.to_bytes(2, "big")

        seq_auth = self.__compute_seq_auth(iv_index, seq_number)
        nonce = self.__compute_nonce(aszmic, seq_auth, src_addr, dst_addr, iv_index)
        if aszmic == 1:
            mac_len = 8
        else:
            mac_len = 4

        mic = enc_data[-mac_len:]
        cipher = enc_data[:-mac_len]

        aes_ccm = AES.new(
            self.device_key,
            AES.MODE_CCM,
            nonce=nonce,
            mac_len=mac_len,
        )
        plaintext = aes_ccm.decrypt(cipher)
        try:
            aes_ccm.verify(mic)
            return (plaintext, True)
        except ValueError:
            return (plaintext, False)
