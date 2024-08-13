from Cryptodome.Cipher import AES
from Cryptodome.Hash import HMAC, SHA256
from whad.ble.crypto import (
    aes_cmac,
    generate_diffie_hellman_shared_secret,
    generate_public_key_from_coordinates,
    generate_p256_keypair,
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


class ProvisioningBearerAdvCryptoManager:
    """
    This class implements the PB-ADV encryption and authentication mechanisms.
    """

    def __init__(
        self,
        alg="BTM_ECDH_P256_HMAC_SHA256_AES_CCM",
        private_key_device=None,
        private_key_provisioner=None,
        public_key_coord_device=None,
        public_key_coord_provisioner=None,
        rand_provisioner=None,
        rand_device=None,
        auth_value=None,
        *,
        test=False,
    ):
        """
        Constructor for testing when we already have values
        """

        # if not intancited for test, do nothing
        self.alg = alg
        self.private_key_device = private_key_device
        self.private_key_provisioner = private_key_provisioner
        self.public_key_coord_device = public_key_coord_device
        self.public_key_coord_provisioner = public_key_coord_provisioner
        self.rand_provisioner = rand_provisioner
        self.rand_device = rand_device
        self.auth_value = auth_value

        self.session_key = None
        self.session_nonce = None
        self.confirmation_salt = None
        self.provisioning_salt = None
        self.confirmation_key = None
        self.confirmation_provisioner = None
        self.confirmation_device = None

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
            public_key_device = generate_public_key_from_coordinates(
                int.from_bytes(self.public_key_coord_device[0], "big"),
                int.from_bytes(self.public_key_coord_device[1], "big"),
            )
            self.private_key_provisioner = generate_private_key_from_bytes(
                self.private_key_provisioner
            )
            self.ecdh_secret = generate_diffie_hellman_shared_secret(
                self.private_key_provisioner, public_key_device
            )

        elif self.private_key_device is not None:
            public_key_provisioner = generate_public_key_from_coordinates(
                int.from_bytes(self.public_key_coord_provisioner[0], "big"),
                int.from_bytes(self.public_key_coord_provisioner[1], "big"),
            )
            self.private_key_device = generate_private_key_from_bytes(
                self.private_key_device
            )
            self.ecdh_secret = generate_diffie_hellman_shared_secret(
                self.private_key_device, public_key_provisioner
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
            + self.public_key_coord_device[0]
            + self.public_key_coord_device[1]
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

    def compute_confirmation_device(self):
        """
        Computes Confirmation Device, defined in Mesh Protocol Specification, p. 593, Section 5.4.2.4.1
        """
        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.confirmation_device = aes_cmac(
                self.confirmation_key, self.rand_device + self.auth_value
            )

        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.confirmation_device = hmac_sha256(
                self.confirmation_key, self.rand_device
            )

    def compute_provisioning_salt(self):
        """
        Computes the Provisioning Salt, defined in Mesh Protocol Specification, p. 602, Section 5.4.2.5
        """
        self.provisioning_salt = s1(
            self.confirmation_salt + self.rand_provisioner + self.rand_device
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
        self.public_key_device = None
        self.public_key_provisioner = None
        self.received_confirmation_device = None

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
            self.private_key_provisioner, self.public_key_device
        )

    def add_peer_public_key(self, public_key_x, public_key_y):
        self.public_key_device = generate_public_key_from_coordinates(
            int.from_bytes(public_key_x, "big"),
            int.from_bytes(public_key_y, "big"),
        )

        self.public_key_coord_device = (public_key_x, public_key_y)

    def generate_random(self):
        """
        Generates the random values used in Confirmation Process
        NOT SAFE
        """
        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.rand_provisioner = randbytes(16)
        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.rand_provisioner = randbytes(32)


class ProvisioningBearerAdvCryptoManagerDevice(ProvisioningBearerAdvCryptoManager):
    def __init__(self, alg):
        super().__init__(alg=alg)  # does nothing, but better to have super...
        self.public_key_device = None
        self.public_key_provisioner = None
        self.received_confirmation_provisioner = None

    def generate_keypair(self):
        """Generate the P256 private key / public key"""
        self.private_key_device, self.public_key_device = generate_p256_keypair()

        # Get coordinates format for the Provisioning Packets
        public_key_numbers = self.public_key_device.public_numbers()
        self.public_key_coord_device = (
            public_key_numbers.x.to_bytes(32, "big"),
            public_key_numbers.y.to_bytes(32, "big"),
        )

    def compute_ecdh_secret(self):
        """
        Get the keys in the correct format to compute ECDH shared secret
        """
        self.ecdh_secret = generate_diffie_hellman_shared_secret(
            self.private_key_device, self.public_key_provisioner
        )

    def add_peer_public_key(self, public_key_x, public_key_y):
        self.public_key_provisioner = generate_public_key_from_coordinates(
            public_key_x, public_key_y
        )

        self.public_key_coord_provisioner = (public_key_x, public_key_y)

    def generate_random(self):
        """
        Generates the random values used in Confirmation Process
        NOT SAFE
        """
        if self.alg == "BTM_ECDH_P256_CMAC_AES128_AES_CCM":
            self.rand_device = randbytes(16)
        elif self.alg == "BTM_ECDH_P256_HMAC_SHA256_AES_CCM":
            self.rand_device = randbytes(32)
