"""Security Management Protocol

BleSMP provides these different pairing strategies:

- "Legacy Just Works"
- "Legacy Passkey Entry"
- "LESC JustWorks"
- "LESC Numeric Comparison"
- "LESC Passkey Entry"

"""
from struct import pack, unpack
from binascii import hexlify
from random import randint
from time import sleep


from scapy.layers.bluetooth import SM_Pairing_Request, SM_Pairing_Response, SM_Hdr,\
    SM_Confirm, SM_Random, SM_Failed, SM_Encryption_Information, SM_Master_Identification, \
    SM_Identity_Information, SM_Signing_Information, SM_Identity_Address_Information, \
    SM_DHKey_Check, SM_Public_Key
from whad.ble.crypto import LinkLayerCryptoManager, generate_random_value, c1, s1, f4, g2, \
    f5, f6, generate_public_key_from_coordinates, generate_diffie_hellman_shared_secret, \
    generate_p256_keypair
from whad.ble.bdaddr import BDAddress
from whad.ble.stack.smp.constants import *
from whad.ble.stack.smp.exceptions import SMInvalidParameterFormat

from whad.common.stack import Layer, alias, source, instance, LayerState, state

import json
import logging
logger = logging.getLogger(__name__)


class BLEKey:
    def __init__(self, key, key_size=None, type="LTK"):
        self.__key = key
        self.__key_size = 8*len(key) if key_size is None else key_size
        self.__type = type

    @property
    def value(self):
        return self.__key

    def __repr__(self):
        return "%s('%s' - %d bits)" % (self.__type, self.__key.hex().lower(), self.__key_size)

class LongTermKey(BLEKey):
    def __init__(self, key, rand=b"\x00"*8, ediv=0, key_size=None):
        super().__init__(key, key_size=key_size, type="LTK")
        self.__rand = rand
        self.__ediv = ediv

    @property
    def rand(self):
        return self.__rand

    @property
    def ediv(self):
        return self.__ediv

class IdentityResolvingKey(BLEKey):
    def __init__(self, key, key_size=None):
        super().__init__(key, key_size=key_size, type="IRK")


class ConnectionSignatureResolvingKey(BLEKey):
    def __init__(self, key, key_size=None):
        super().__init__(key, key_size=key_size, type="CSRK")

class CryptographicMaterial:

    @classmethod
    def from_json(cls, json_value):
        report = json.loads(json_value)
        cm = CryptographicMaterial(

            BDAddress(report["address"], random = (report["address_type"] == 1)),

            ltk = LongTermKey(
                bytes.fromhex(report["ltk"]),
                rand=bytes.fromhex(report["rand"]),
                ediv=report["ediv"]
            ) if "ltk" in report else None,

            irk = IdentityResolvingKey(
                bytes.fromhex(report["irk"])
            ) if "irk" in report else None,

            csrk = ConnectionSignatureResolvingKey(
                bytes.fromhex(report["csrk"])
            ) if "csrk" in report else None
        )
        return cm

    def to_json(self):
        report = {
            "address" : ":".join(["{:02x}".format(i) for i in self.__address.value[::-1]]),
            "address_type" : self.__address.type
        }
        if self.has_ltk():
            report["ltk"] = self.ltk.value.hex()
            report["rand"] = self.ltk.rand.hex()
            report["ediv"] = self.ltk.ediv
        if self.has_irk():
            report["irk"] = self.irk.value.hex()
        if self.has_csrk():
            report["csrk"] = self.csrk.value.hex()

        return json.dumps(report)


    def __init__(self, address, ltk=None, irk=None, csrk=None):
        self.__address = address
        if isinstance(ltk, bytes):
            self.__ltk = LongTermKey(ltk)
        else:
            self.__ltk = ltk

        if isinstance(irk, bytes):
            self.__irk = IdentityResolvingKey(irk)
        else:
            self.__irk = irk

        if isinstance(csrk, bytes):
            self.__csrk = ConnectionSignatureResolvingKey(csrk)
        else:
            self.__csrk = csrk

    def has_ltk(self):
        return self.__ltk is not None

    def has_irk(self):
        return self.__irk is not None

    def has_csrk(self):
        return self.__csrk is not None

    @property
    def ltk(self):
        return self.__ltk

    @property
    def irk(self):
        return self.__irk

    @property
    def csrk(self):
        return self.__csrk

    @property
    def address(self):
        return self.__address


    def __repr__(self):
        output = (
            "CryptographicMaterial(" +
            ", ".join(
                ["address = " + str(self.__address),
                (("ltk = " + str(self.ltk)) if self.ltk is not None else ""),
                (("irk = " + str(self.irk)) if self.irk is not None else ""),
                (("csrk = " + str(self.csrk)) if self.csrk is not None else "")
                ]
            ) + ")"
        )
        return output

class SM_Peer(object):
    """
    SM_Peer stores all pairing-specific data regarding a peer.
    """


    def __init__(self, address):
        """Instanciate a SM_Peer.

        By default, peers are configured to only accept Legacy JustWorks pairing.
        """

        logger.info('Initiate SM_Peer object for peer %s' % address)

        # Peer address and address type
        self.__address = address

        # Key distribution (by default, corresponds to Legacy JustWorks)
        self.__kd_link_key = True
        self.__kd_sign_key = True
        self.__kd_enc_key = True
        self.__kd_id_key = True

        # Default security parameters
        self.__oob = False
        self.__bonding = False
        self.__mitm = False
        self.__lesc = True
        self.__keypress = False
        self.__ct2 = False
        self.__max_key_size = 16

        # Crypto parameters
        self.__confirm = None
        self.__rand = None
        self.__stk = None
        self.__ltk = None

        # Distribution parameters
        self.__dist_ltk = False
        self.__dist_ediv_rand = False
        self.__dist_irk = False
        self.__dist_csrk = False

        self.__distributed_ltk = None
        self.__distributed_rand = None
        self.__distributed_ediv = None
        self.__distributed_address = None
        self.__distributed_address_type = None
        self.__distributed_irk  = None
        self.__distributed_csrk = None

        # Pairing method
        self.__pairing_method = PM_LEGACY_JUSTWORKS

        # IO Capabilities
        self.__io_cap = IOCAP_DISPLAY_ONLY

    @property
    def address(self):
        return self.__address.value

    @property
    def address_type(self):
        return self.__address.type

    def support_lesc(self):
        return self.__lesc

    def support_oob(self):
        return self.__oob

    def requires_bonding(self):
        return self.__bonding

    def support_mitm(self):
        return self.__mitm

    def set_security_parameters(self,
        lesc=None, mitm=None, bonding=None, keypress=None,
        ct2=None, max_key_size=None, oob=None):
        """Set security parameters for the current SM peer.

        :param lesc: Enable/disable LE Secure Connection for this peer
        :type lesc: bool, optional
        :param mitm: Enable/disable MITM for this peer
        :type mitm: bool, optional
        :param bonding: Enable/disable bonding for this peer
        :type bonding: bool, optional
        :param keypress: Enable/disable keypress notification for this peer
        :type keypress: bool, optional
        :param ct2: Enable/disable ct2 (h7 function support) for this peer
        :type ct2: bool, optional
        :param max_key_size: Set max key size for this peer
        :type ct2: int, optional
        :param oob: Use OOB data
        :type oob: bool, optional
        """
        if isinstance(lesc, bool):
            self.__lesc = lesc
        if isinstance(mitm, bool):
            self.__mitm = mitm
        if isinstance(bonding, bool):
            self.__bonding = bonding
        if isinstance(keypress, bool):
            self.__keypress = keypress
        if isinstance(ct2, bool):
            self.__ct2 = ct2
        if isinstance(oob, bool):
            self.__oob = oob
        if max_key_size is not None and isinstance(max_key_size, int):
            self.__max_key_size = max_key_size

    @property
    def iocap(self):
        """Return this peer IO capabilities
        """
        return self.__io_cap

    @iocap.setter
    def iocap(self, value):
        if value in [
            IOCAP_DISPLAY_ONLY,
            IOCAP_DISPLAY_YESNO,
            IOCAP_KEYBD_DISPLAY,
            IOCAP_KEYBD_ONLY,
            IOCAP_NOINPUT_NOOUTPUT
            ]:

            self.__io_cap = value
        else:
            raise SMInvalidParameterFormat


    @property
    def oob(self):
        return OOB_DISABLED if not self.__oob else OOB_ENABLED

    @property
    def authentication(self):
        """Rebuild authentication byte from internal status

        :return: Pairing Request/Response AuthReq value
        :rtype: int
        """
        flags = 0x00
        if self.__bonding:
            flags |= 0x01
        if self.__mitm:
            flags |= 0x04
        if self.__lesc:
            flags |= 0x08
        if self.__keypress:
            flags |= 0x10
        if self.__ct2:
            flags |= 0x20
        return flags

    ##
    # Key distribution
    ##

    def distribute_keys(self, link_key=False, sign_key=False, id_key=False, enc_key=False):
        """Mark keys to be distributed to peer.

        :param bool ltk: Will distribute LTK if set to True
        :param bool ediv: Will distribute EDIV if set to True
        :param bool rand: Will distribute RAND if set to True
        :param bool irk: Will distribute IRK if set to True
        :param bool address: Will distribute address if set to True
        :param bool csrk: Will distribute CSRK if set to True
        """
        self.__kd_link_key = link_key
        self.__kd_sign_key = sign_key
        self.__kd_id_key = id_key
        self.__kd_enc_key = enc_key

        if self.__pairing_method in [PM_LEGACY_JUSTWORKS, PM_LEGACY_PASSKEY]:
            keys = []
            if self.__kd_enc_key:
                keys.append('ltk, ediv, rand')
                self.__dist_ltk = True
                self.__dist_ediv_rand = True
            if self.__kd_id_key:
                keys.append('irk')
                self.__dist_irk = True
            if self.__kd_sign_key:
                keys.append('csrk')
                self.__dist_csrk = True
            logger.debug('Set distribute key for peer: %s' % (','.join(keys)))
        elif self.__pairing_method in [PM_LESC_JUSTWORKS, PM_LESC_NUMCOMP, PM_OOB]:
            keys=[]
            if self.__kd_id_key:
                keys.append('irk')
                self.__dist_irk = True
            if self.__kd_sign_key:
                keys.append('csrk')
                self.__dist_csrk = True
            if self.__kd_link_key:
                keys.append('ltk')
                self.__dist_ltk = True
            logger.debug('Set distribute key for peer: %s' % (','.join(keys)))

    def get_key_distribution(self):
        """Get the key distribution byte from the peer.

        This method is used to convert the internal key distribution model
        into an integer value that may be used in a Pairing Request or Pairing Response.

        :return: Key distribution byte
        :rtype: int
        """
        kd = 0x00
        if self.__kd_enc_key:
            kd |= 0x01
        if self.__kd_id_key:
            kd |= 0x02
        if self.__kd_sign_key:
            kd |= 0x04
        if self.__kd_link_key:
            kd |= 0x08
        return kd

    def indicate_ltk_distribution(self, ltk):
        self.__distributed_ltk = ltk

    def indicate_rand_ediv_distribution(self, rand, ediv):
        self.__distributed_rand = rand
        self.__distributed_ediv = ediv

    def indicate_irk_distribution(self, irk):
        self.__distributed_irk = irk

    def indicate_csrk_distribution(self, csrk):
        self.__distributed_csrk = csrk

    def indicate_address_distribution(self, address, address_type):
        self.__distributed_address = address
        self.__distributed_address_type = address_type

    def is_key_distribution_complete(self):
        """
        Indicate if all keys have been distributed.
        """
        if self.__kd_enc_key and self.__distributed_ltk is None:
            return False
        if self.__kd_enc_key and (self.__distributed_rand is None or self.__distributed_ediv is None):
            return False
        if self.__kd_id_key and (self.__distributed_irk is None):
            return False
        if self.__kd_id_key and (self.__distributed_address is None and self.__distributed_address_type is None):
            return False
        if self.__kd_sign_key and (self.__distributed_csrk is None):
            return False
        return True

    @property
    def ltk(self):
        return self.__distributed_ltk

    @property
    def random(self):
        return self.__distributed_rand

    @property
    def ediv(self):
        return self.__distributed_ediv

    @property
    def irk(self):
        return self.__distributed_irk

    @property
    def csrk(self):
        return self.__distributed_csrk

    def must_dist_ltk(self):
        return self.__dist_ltk

    def must_dist_ediv_rand(self):
        return self.__dist_ediv_rand

    def must_dist_irk(self):
        return self.__dist_irk

    def must_dist_csrk(self):
        return self.__dist_csrk

    @property
    def max_key_size(self):
        return self.__max_key_size

    ##
    # Pairing method
    ##

    def set_pairing_method(self, pairing_method):
        """Set pairing method

        :param int pairing_method: Pairing method as defined in PM_* in BleSMP.
        """
        self.__pairing_method = pairing_method
        logger.info('Pairing method set to %d' % self.__pairing_method)

    @property
    def pairing_method(self):
        return self.__pairing_method


    ##
    # Crypto getters/setters/generators
    ##

    def generate_legacy_rand(self):
        """Generate a Rand value based on [Vol 3] Part H. Section 2.3.5.5
        """
        # Rand
        self.__rand = generate_random_value(128)
        logger.info('(%s) Generated RAND value: %s' % (
            self.__address,
            hexlify(self.__rand)
        ))

    @property
    def rand(self):
        return self.__rand

    @rand.setter
    def rand(self, value):
        """RAND must be 128-bit long byte array
        """
        if isinstance(value, bytes) and len(value) == 16:
            self.__rand = value
            logger.debug('(%s) Set RAND value: %s' % (
                self.__address,
                hexlify(value)
            ))
        else:
            raise SMInvalidParameterFormat()

    @property
    def confirm(self):
        return self.__confirm

    @confirm.setter
    def confirm(self, value):
        """CONFIRM must be 128-bit long byte array
        """
        if isinstance(value, bytes) and len(value) == 16:
            self.__confirm = value
            logger.debug('(%s) Set confirm value: %s' % (
                self.__address,
                hexlify(value)
            ))
        else:
            raise SMInvalidParameterFormat()

    def check_peer_confirm(self, tk, preq, pres, peer, initiator=True):
        """Check peer confirm value
        """
        logger.debug('(%s) RAND value: %s' % (
            self.__address,
            hexlify(self.__rand)
        ))
        logger.debug('(%s) CONFIRM value: %s' % (
            self.__address,
            hexlify(self.__confirm)
        ))
        # First, compute confirm based on rand
        if initiator:
            _confirm = self.compute_legacy_confirm_value(
                tk,
                preq,
                pres,
                self.address,
                self.address_type,
                peer.address,
                peer.address_type,
            )
        else:
            _confirm = self.compute_legacy_confirm_value(
                tk,
                preq,
                pres,
                peer.address,
                peer.address_type,
                self.address,
                self.address_type
            )
        return _confirm == self.get_confirm_value()




    def compute_legacy_confirm_value(self, tk, preq, pres, init_addr, init_addr_type, resp_addr, resp_addr_type):
        _confirm = c1(
            tk,
            self.__rand[::-1],
            pres[::-1],
            preq[::-1],
            pack('<B', init_addr_type),
            init_addr[::-1],
            pack('<B', resp_addr_type),
            resp_addr[::-1]
        )
        logger.info('(%s) Using RAND to compute confirm: %s' % (
            self.__address,
            hexlify(self.__rand)
        ))
        logger.info('(%s) Computed CONFIRM: %s' % (
            self.__address,
            hexlify(_confirm)
        ))
        return _confirm


class SecurityManagerState(LayerState):

    STATE_IDLE = 0x00
    STATE_PAIRING_REQ = 0x01
    STATE_PAIRING_RSP = 0x02
    STATE_LEGACY_PAIRING_CONFIRM_SENT = 0x03
    STATE_LEGACY_PAIRING_CONFIRM_RECVD = 0x04
    STATE_LEGACY_PAIRING_RANDOM_SENT = 0x05
    STATE_LEGACY_PAIRING_RANDOM_RECVD = 0x06
    STATE_LESC_PUBKEY_SENT = 0x07
    STATE_LESC_PUBKEY_RECVD = 0x08
    STATE_LESC_PAIRING_CONFIRM_SENT = 0x09
    STATE_LESC_PAIRING_RANDOM_SENT = 0x0A
    STATE_LESC_PAIRING_RANDOM_RECVD = 0x0B
    STATE_LESC_DHK_CHECK_SENT = 0x0C
    STATE_LESC_DHK_CHECK_RECVD = 0x0D
    STATE_PAIRING_DONE = 0x0E
    STATE_DISTRIBUTE_KEY = 0x0F
    STATE_LESC_PUBKEY_RECVD_STAGEN = 0x10
    STATE_LESC_PAIRING_CONFIRM_SENT_STAGEN = 0x11
    STATE_LESC_PAIRING_RANDOM_SENT_STAGEN = 0x12
    STATE_BONDING_DONE = 0xFF

    def __init__(self):
        super().__init__()

        # Global configuration
        self.justworks = True
        self.lesc = False

        # Capabilities
        self.capabilities = IOCAP_NOINPUT_NOOUTPUT

        # Peers' states
        self.initiator = None
        self.responder = None

        # Current state
        self.state = SecurityManagerState.STATE_IDLE

        # Crypto manager
        self.cm = None

        # Initiator Key Distribution
        self.ikd = None

        # Responder Key Distribution
        self.rkd = None

        # Pairing material
        self.pairing_req = None
        self.pairing_resp = None
        self.tk = b'\x00'*16
        self.stk = b'\x00'*16
        self.ltk = b'\x00'*16
        self.mackey = None

        # Initiator role
        self.enc_initiator = False

        # LE Secure Connections
        self.private_key = None
        self.public_key = None

        self.peer_public_key = None
        self.shared_secret = None

        # Method
        self.method = None

        # Passkey counter
        self.passkey_value = None
        self.passkey_counter = 1

@alias('smp')
@state(SecurityManagerState)
class SMPLayer(Layer):


    ##########
    # Helpers
    ##########

    def key_generation_method_selection(self, initiator, responder):
        """
        This method returns the key generation method to select according to
        the exchanged initiator and responder parameters.
        """
        use_lesc = False
        # If initiator and responder supports LE Secure Connections,
        # use Table 2.7, Vol. 3, Part H, Bluetooth Core Specification v5.3, p. 1573
        if initiator.support_lesc() and responder.support_lesc():
            use_lesc = True
            if initiator.support_oob() or responder.support_oob():
                return PM_OOB
            elif not initiator.support_mitm() and not responder.support_mitm():
                return PM_LESC_JUSTWORKS
        # if at least one of the device does not support LE Secure Connections,
        # use Table 2.6, Vol. 3, Part H, Bluetooth Core Specification v5.3, p. 1572
        else:
            use_lesc = False
            if initiator.support_oob() and responder.support_oob():
                return PM_OOB
            elif not initiator.support_mitm() and not responder.support_mitm():
                return PM_LEGACY_JUSTWORKS

        # If we reach this point, we need to define pairing according to IO capabilities
        # (see Table 2.8, Vol. 3, Part H, Bluetooth Core Specification v5.3, p. 1573)
        try:
            return IOCAP_KEY_GENERATION_MAPPING[(initiator.iocap, responder.iocap)][int(use_lesc)]
        except IndexError:
            # it looks like an error occured, let's return None
            return None

    def is_initiator(self):
        return self.state.enc_initiator

    def check_initiator_legacy_confirm(self, tk):
        """Check initiator peer confirm value given a TK and the corresponding random value.

        :param SM_Peer: Peer to check
        :param bytes tk: Temporary Key
        :param Packet preq: Pairing request
        :param Packet pres: Pairing response
        :param SM_Peer initiator: Pairing initiator
        :param SM_Peer responder: Pairing responder
        """
        logger.debug('[check_initiator_legacy_confirm] RAND=%s' % hexlify(self.state.initiator.rand))
        # Compute expected confirm value
        expected_confirm = self.compute_legacy_confirm_value(
            tk,
            self.state.initiator.rand,
            self.state.pairing_req,
            self.state.pairing_resp,
            self.state.initiator,
            self.state.responder
        )
        logger.debug('[check_initiator_legacy_confirm] Computed CONFIRM=%s' % hexlify(expected_confirm))
        logger.debug('[check_initiator_legacy_confirm] Expected CONFIRM=%s' % hexlify(self.state.initiator.confirm))

        # Compare with confirm value
        return (expected_confirm == self.state.initiator.confirm)

    def check_responder_legacy_confirm(self, tk, preq, pres, initiator, responder):
        """Check responder peer confirm value given a TK and the corresponding random value.

        :param SM_Peer: Peer to check
        :param bytes tk: Temporary Key
        :param Packet preq: Pairing request
        :param Packet pres: Pairing response
        :param SM_Peer initiator: Pairing initiator
        :param SM_Peer responder: Pairing responder
        """
        logger.debug('[check_responder_legacy_confirm] RAND=%s' % hexlify(self.state.initiator.rand))

        # Compute expected confirm value
        expected_confirm = self.compute_legacy_confirm_value(
            tk,
            self.state.responder.rand,
            self.state.pairing_req,
            self.state.pairing_resp,
            self.state.initiator,
            self.state.responder
        )

        logger.debug('[check_initiator_legacy_confirm] Computed CONFIRM=%s' % hexlify(expected_confirm))
        logger.debug('[check_initiator_legacy_confirm] Expected CONFIRM=%s' % hexlify(self.state.responder.confirm))

        # Compare with confirm value
        return (expected_confirm == self.state.responder.confirm)

    def compute_exchange_value(self, mackey, initiator, responder, r, iocap):
        e = f6(
            mackey,
            initiator.rand,
            responder.rand,
            b"\x00"*12+pack('>I', r),
            iocap,
            pack('<B', initiator.address_type) +
            initiator.address[::-1],
            pack('<B', responder.address_type) +
            responder.address[::-1]
        )

        return e

    def compute_ltk_and_mackey(self, shared_secret, initiator, responder):
        print(initiator.address, responder.address)
        output = f5(
            shared_secret,
            initiator.rand,
            responder.rand,
            pack('<B', initiator.address_type) +
            initiator.address[::-1],
            pack('<B', responder.address_type) +
            responder.address[::-1]
        )

        mac_key, ltk = output[:16], output[16:] # 16 MSB -> macKey, 16 LSB -> LTK
        return mac_key, ltk

    def compute_lesc_numeric_comparison(self, initiator_public_key, responder_public_key, initiator_rand, responder_rand):
        _value = g2(
            bytes.fromhex("{:064x}".format(initiator_public_key.public_numbers().x)),
            bytes.fromhex("{:064x}".format(responder_public_key.public_numbers().x)),
            initiator_rand,
            responder_rand
        )
        cropped_digits = unpack(">I", _value)[0] % (10**6)
        return cropped_digits

    def check_lesc_confirm_value(self, initiator_public_key, responder_public_key, random_number, r, value):
        _expected_value = self.compute_lesc_confirm_value(
            initiator_public_key,
            responder_public_key,
            random_number,
            r
        )
        print("Computed LESC value: ", _expected_value)
        return _expected_value == value

    def compute_lesc_confirm_value(self, initiator_public_key, responder_public_key, random_number, r):
        _confirm = f4(
            bytes.fromhex("{:064x}".format(responder_public_key.public_numbers().x)),
            bytes.fromhex("{:064x}".format(initiator_public_key.public_numbers().x)),
            random_number,
            r
        )
        logger.info('Computed LESC CONFIRM: %s' % (
            hexlify(_confirm)
        ))
        return _confirm

    def compute_legacy_confirm_value(self, tk, rand, preq, pres, initiator, responder):
        """Compute Confirm value as described in [Vol 3] Part H, Section 2.3.5.5

        This value is not ready to be set in a SM_Confirm packet as-is, it needs
        to be byte-reversed to be correctly decoded.

        :param bytes tk: Temporary Key
        :param bytes rand: Random to encrypt
        :param Packet preq: Pairing request
        :param Packet pres: Pairing response
        :param SM_Peer initiator: Pairing initiator
        :param SM_Peer responder: Pairing responder

        :return: Confirm value
        :rtype: bytes
        """
        logger.debug('TK=%s RAND=%s, PRES=%s PREQ=%s INITA_TYPE=%02x INITA=%s RESPA_TYPE=%02x RESPA=%s' % (
            hexlify(tk),
            hexlify(rand),
            hexlify(bytes(SM_Hdr()/pres)[::-1]),
            hexlify(bytes(SM_Hdr()/preq)[::-1]),
            initiator.address_type,
            hexlify(initiator.address[::-1]),
            responder.address_type,
            hexlify(responder.address[::-1])
        ))

        # Compute the confirm value for the provided parameters
        # We need to:
        # - convert `preq` to bytes in reverse order including SM_Hdr
        # - convert `pres` to bytes in reverse order including SM_Hdr
        # - reverse order of BD addresses
        # - pack address types as 8-bit data (prefixed by 7 zeroes)

        _confirm = c1(
            tk,
            rand,
            bytes(SM_Hdr()/pres)[::-1],
            bytes(SM_Hdr()/preq)[::-1],
            pack('<B', initiator.address_type),
            initiator.address[::-1],
            pack('<B', responder.address_type),
            responder.address[::-1]
        )
        return _confirm



    def get_passkey_entry(self):
        print("Enter passkey entry: ")
        passkey_entry = input()
        return int(passkey_entry)

    def get_pin_code(self):
        self_iocap = self.state.initiator.iocap if self.is_initiator() else self.state.responder.iocap

        if self_iocap == IOCAP_KEYBD_ONLY:
            print("Enter pin code: ")
            pin_code = input()
            return int(pin_code)
        else:
            pin_code = randint(0, 999999)
            print("Randomly generated pin code: ", pin_code)
            return pin_code

    ##########################################
    # Incoming requests and responses
    ##########################################

    @instance('l2cap')
    def on_packet(self, instance, smp_pkt):
        """SMP packet reception callback

        This method dispatches every LE SMP packet received.

        :param Packet packet: Scapy packet containing SMP material
        """
        if SM_Pairing_Request in smp_pkt:
            self.on_pairing_request(smp_pkt.getlayer(SM_Pairing_Request))
        elif SM_Pairing_Response in smp_pkt:
            self.on_pairing_response(smp_pkt.getlayer(SM_Pairing_Response))
        elif SM_Confirm in smp_pkt:
            self.on_pairing_confirm(smp_pkt.getlayer(SM_Confirm))
        elif SM_Random in smp_pkt:
            self.on_pairing_random(smp_pkt.getlayer(SM_Random))
        elif SM_Encryption_Information in smp_pkt:
            self.on_encryption_information(smp_pkt.getlayer(SM_Encryption_Information))
        elif SM_Master_Identification in smp_pkt:
            self.on_master_identification(smp_pkt.getlayer(SM_Master_Identification))
        elif SM_Identity_Information in smp_pkt:
            self.on_identity_information(smp_pkt.getlayer(SM_Identity_Information))
        elif SM_Identity_Address_Information in smp_pkt:
            self.on_identity_address_information(smp_pkt.getlayer(SM_Identity_Address_Information))
        elif SM_Signing_Information in smp_pkt:
            self.on_signing_information(smp_pkt.getlayer(SM_Signing_Information))
        elif SM_Public_Key in smp_pkt:
            self.on_public_key(smp_pkt.getlayer(SM_Public_Key))
        elif SM_DHKey_Check in smp_pkt:
            self.on_dhkey_check(smp_pkt.getlayer(SM_DHKey_Check))

    def initiate_pairing(
                            self,
                            oob=False,
                            bonding=True,
                            mitm=False,
                            lesc=True,
                            keypress=False,
                            max_key_size=16,
                            iocap=IOCAP_DISPLAY_ONLY,
                            enc_key=True,
                            id_key=True,
                            sign_key=True,
                            link_key=True
        ):
        """
        Initiate a pairing procedure.
        """

        if self.state.state == SecurityManagerState.STATE_IDLE:
            logger.info('Pairing Request initiation ...')

            # Get the current connection handle
            conn_handle = self.get_layer('l2cap').state.conn_handle

            # Get the current link layer state
            local_conn = self.get_layer('ll').state.get_connection(conn_handle)

            # Get the local and remote addresses values and types
            local_peer_addr = local_conn['local_peer_addr']
            local_peer_addr_type = local_conn['local_peer_addr_type']
            local_addr_object = BDAddress.from_bytes(
                local_peer_addr,
                addr_type = BDAddress.PUBLIC if
                            local_peer_addr_type == 0 else
                            BDAddress.RANDOM
            )

            remote_peer_addr = local_conn['remote_peer_addr']
            remote_peer_addr_type = local_conn['remote_peer_addr_type']

            remote_addr_object = BDAddress.from_bytes(
                remote_peer_addr,
                addr_type = BDAddress.PUBLIC if
                            remote_peer_addr_type == 0 else
                            BDAddress.RANDOM
            )

            # We are the initiator
            self.state.enc_initiator = True

            # Create the responder SM_Peer instance
            # (along with all its parameters are defined in the pairing request)
            self.state.initiator = SM_Peer(local_addr_object)

            self.state.initiator.set_security_parameters(
                oob=oob,
                bonding=bonding,
                mitm=mitm,
                lesc=lesc,
                keypress=keypress,
                max_key_size = max_key_size
            )

            self.state.initiator.iocap = iocap

            # Store initiator key distribution options
            self.state.initiator.distribute_keys(
                enc_key = enc_key,
                id_key = id_key,
                sign_key = sign_key,
                link_key = link_key
            )

            # Send our pairing response
            pairing_req = SM_Pairing_Request(
                iocap=self.state.initiator.iocap,
                oob=self.state.initiator.oob,
                authentication=self.state.initiator.authentication,
                max_key_size=self.state.initiator.max_key_size,
                initiator_key_distribution=self.state.initiator.get_key_distribution(),
                responder_key_distribution=self.state.initiator.get_key_distribution()
            )

            # Save pairing request
            self.state.pairing_req = pairing_req

            self.send_data(pairing_req)

            # Update current state
            self.state.state = SecurityManagerState.STATE_PAIRING_RSP
        else:
            logger.info('We are in an inconsistent state, returning to idle.')

            # Return to IDLE mode
            self.__state = SecurityManagerState.STATE_IDLE

    def on_public_key(self, public_key_pkt):
        """Method called when a public key is received.

        :param SM_Public_Key public_key_pkt: Public Key packet
        """



        # We received the public key, now transmit our own
        if self.state.state == SecurityManagerState.STATE_PAIRING_REQ:
            public_key_pkt.show()
            # Extract X and Y from public key packet
            x = int(public_key_pkt.key_x[::-1].hex(), 16)
            y = int(public_key_pkt.key_y[::-1].hex(), 16)

            # We can now generate the ECDH shared secret
            self.state.peer_public_key = generate_public_key_from_coordinates(x, y)
            self.state.shared_secret = generate_diffie_hellman_shared_secret(self.state.private_key, self.state.peer_public_key)

            print("Shared secret", self.state.shared_secret)
            own_x = bytes.fromhex("{:064x}".format(self.state.public_key.public_numbers().x))[::-1]
            own_y = bytes.fromhex("{:064x}".format(self.state.public_key.public_numbers().y))[::-1]

            self.send_data(
                SM_Public_Key(
                    key_x = own_x,
                    key_y = own_y
                )
            )

            # Generate a RAND and compute CONFIRM
            self.state.responder.generate_legacy_rand()

            if self.state.method != PM_LESC_PASSKEY:
                self.state.responder.confirm = self.compute_lesc_confirm_value(
                    self.state.peer_public_key,  # we are the responder, peer is the initiator
                    self.state.public_key,  # set our own public key
                    self.state.responder.rand,
                    b"\x00" # r equals 0 in JustWorks and NumComp
                )

                logger.debug('[send_pairing_confirm] Computed CONFIRM=%s' % hexlify(self.state.responder.confirm))

                self.send_data(
                    SM_Confirm(
                        confirm=self.state.responder.confirm[::-1]
                    )
                )
                # Update current state
                self.state.state = SecurityManagerState.STATE_LESC_PAIRING_CONFIRM_SENT
            else:

                # Set counter to 1
                self.state.passkey_counter = 1

                self.state.state = SecurityManagerState.STATE_LESC_PUBKEY_RECVD_STAGEN

        elif self.state.state == SecurityManagerState.STATE_LESC_PUBKEY_SENT:
            public_key_pkt.show()
            # Extract X and Y from public key packet
            x = int(public_key_pkt.key_x[::-1].hex(), 16)
            y = int(public_key_pkt.key_y[::-1].hex(), 16)

            # We can now generate the ECDH shared secret
            self.state.peer_public_key = generate_public_key_from_coordinates(x, y)
            self.state.shared_secret = generate_diffie_hellman_shared_secret(self.state.private_key, self.state.peer_public_key)

            print("Shared secret", self.state.shared_secret)

            if self.state.method != PM_LESC_PASSKEY:
                self.state.state = SecurityManagerState.STATE_LESC_PUBKEY_RECVD
            else:
                # Set counter to 1
                self.state.passkey_counter = 1
                # Collect passkey entry
                self.state.passkey_value = self.get_passkey_entry()

                # Generate Nai
                self.state.initiator.generate_legacy_rand()

                self.state.initiator.confirm = self.compute_lesc_confirm_value(
                    self.state.peer_public_key,  # set our own public key
                    self.state.public_key,  # we are the initiator, peer is the responder
                    self.state.initiator.rand,
                    bytes([((self.state.passkey_value >> (self.state.passkey_counter - 1)) & 1) + 0x80])
                )

                self.send_data(
                    SM_Confirm(
                        confirm = self.state.initiator.confirm[::-1]
                    )
                )

                self.state.state = SecurityManagerState.STATE_LESC_PAIRING_CONFIRM_SENT_STAGEN

    def on_pairing_request(self, pairing_req):
        """Method called when a pairing request is received.

        :param SM_Pairing_Request pairing_req: Pairing request packet
        """
        logger.info('Received Pairing Request')

        # Make sure we are in a state that allows this pairing request
        if self.state.state == SecurityManagerState.STATE_IDLE:
            logger.info('Pairing Request accepted, processing ...')

            # Save pairing request
            self.state.pairing_req = pairing_req


            # Get the current connection handle
            conn_handle = self.get_layer('l2cap').state.conn_handle

            # Get the current link layer state
            local_conn = self.get_layer('ll').state.get_connection(conn_handle)

            # Get the local and remote addresses values and types
            local_peer_addr = local_conn['local_peer_addr']
            local_peer_addr_type = local_conn['local_peer_addr_type']

            local_addr_object = BDAddress.from_bytes(
                local_peer_addr,
                addr_type = BDAddress.PUBLIC if
                            local_peer_addr_type == 0 else
                            BDAddress.RANDOM
            )

            remote_peer_addr = local_conn['remote_peer_addr']
            remote_peer_addr_type = local_conn['remote_peer_addr_type']

            remote_addr_object = BDAddress.from_bytes(
                remote_peer_addr,
                addr_type = BDAddress.PUBLIC if
                            remote_peer_addr_type == 0 else
                            BDAddress.RANDOM
            )

            # We are definitely not the initiator but the responder
            self.state.enc_initiator = False
            self.state.responder = SM_Peer(local_addr_object)

            # Create the initiator SM_Peer instance
            # (along with all its parameters are defined in the pairing request)
            self.state.initiator = SM_Peer(remote_addr_object)

            self.state.initiator.set_security_parameters(
                oob=(pairing_req.oob == 0x01),
                bonding=((pairing_req.authentication & 0x03) != 0),
                mitm=((pairing_req.authentication & 0x04) != 0),
                lesc=((pairing_req.authentication & 0x08) != 0),
                keypress=((pairing_req.authentication & 0x10) != 0),
                max_key_size = pairing_req.max_key_size
            )
            self.state.initiator.iocap = pairing_req.iocap

            # Store initiator key distribution options
            self.state.initiator.distribute_keys(
                enc_key = ((pairing_req.initiator_key_distribution & 0x01) != 0),
                id_key = ((pairing_req.initiator_key_distribution & 0x02) != 0),
                sign_key =((pairing_req.initiator_key_distribution & 0x04) != 0),
                link_key = ((pairing_req.initiator_key_distribution & 0x08) != 0)
            )

            # Send our pairing response
            pairing_resp = SM_Pairing_Response(
                iocap=self.state.responder.iocap,
                oob=self.state.responder.oob,
                authentication=self.state.responder.authentication,
                max_key_size=self.state.responder.max_key_size,
                initiator_key_distribution=self.state.initiator.get_key_distribution(),
                responder_key_distribution=self.state.responder.get_key_distribution()
            )

            # Save pairing response
            self.state.pairing_resp = pairing_resp

            self.send_data(pairing_resp)


            # Check key generation method in use
            self.state.method = self.key_generation_method_selection(self.state.initiator, self.state.responder)

            if self.state.method == PM_LEGACY_JUSTWORKS:
                self.state.tk = b"\x00" * 16
            elif self.state.method == PM_LEGACY_PASSKEY:
                pin = self.get_pin_code() # TODO: allow to pass a callback here to customize PIN entry
                self.state.tk = bytes.fromhex("00"*12 + "{:08x}".format(pin))
            elif self.state.method in (PM_LESC_NUMCOMP, PM_LESC_JUSTWORKS, PM_LESC_PASSKEY):
                # Generate the P256 keypair
                self.state.private_key, self.state.public_key = generate_p256_keypair()

            print("Method: ", self.state.method)
            # Update current state
            self.state.state = SecurityManagerState.STATE_PAIRING_REQ

        else:
            logger.info('Unexpected packet received, report error and return to idle.')

            # Notify error
            error = SM_Failed(
                reason = SM_ERROR_UNSPEC_REASON
            )
            self.send_data(error)

            # Return to IDLE mode
            self.__state = SecurityManagerState.STATE_IDLE



    def on_dhkey_check(self, dhkey_check):
        """Method called when a Diffie Hellman check is received.

        :param SM_DHKey_Check dhkey_check: Diffie Hellman check packet
        """
        logger.info('Received Diffie Hellman check')

        # Make sure we are in a state that allows this diffie hellman check packet
        if self.state.state == SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT:
            logger.info('Diffie Hellman check accepted, processing ...')
            self.state.ltk, self.state.mackey = self.compute_ltk_and_mackey(
                self.state.shared_secret,
                self.state.initiator,
                self.state.responder
            )

            self.state.rand, self.state.ediv = b"\x00"*8, 0
            # Indicate LTK as distributed
            self.state.initiator.indicate_ltk_distribution(self.state.ltk)
            self.state.initiator.indicate_rand_ediv_distribution(self.state.rand, self.state.ediv)
            self.state.responder.indicate_ltk_distribution(self.state.ltk)
            self.state.responder.indicate_rand_ediv_distribution(self.state.rand, self.state.ediv)

            if self.state.method != PM_LESC_PASSKEY:
                rb = 0 # in num comp and just works, TODO: adapt for passkey
            else:
                rb = self.state.passkey_value
            # Let's compute EA
            ea = self.compute_exchange_value(
                self.state.mackey,
                self.state.initiator,
                self.state.responder,
                rb,
                bytes(
                    [
                        self.state.initiator.authentication,
                        self.state.initiator.oob,
                        self.state.initiator.iocap
                    ]
                )
            )
            # If we received a valid EA, generate EB and transmit it
            if ea == dhkey_check.dhkey_check[::-1]:
                eb = self.compute_exchange_value(
                    self.state.mackey,
                    self.state.responder,
                    self.state.initiator,
                    rb,
                    bytes(
                        [
                            self.state.responder.authentication,
                            self.state.responder.oob,
                            self.state.responder.iocap
                        ]
                    )
                )
                self.send_data(
                    SM_DHKey_Check(
                        dhkey_check=eb[::-1]
                    )
                )

                # Get the current connection handle
                conn_handle = self.get_layer('l2cap').state.conn_handle

                # Get the current link layer state
                local_conn = self.get_layer('ll').state.register_encryption_key(conn_handle, self.state.ltk)


                self.state.state = SecurityManagerState.STATE_LESC_DHK_CHECK_SENT
            # otherwise, fail.
            else:
                logger.info('Invalid exchange value received, report error and return to idle.')

                # Notify error
                error = SM_Failed(
                    reason = SM_ERROR_DHKEY_CHECK_FAILED
                )
                self.send_data(error)

                # Return to IDLE mode
                self.__state = SecurityManagerState.STATE_IDLE

        elif self.state.state == SecurityManagerState.STATE_LESC_DHK_CHECK_SENT:

            if self.state.method == PM_LESC_PASSKEY:
                rb = self.state.passkey_value
            else:
                rb = 0

            # Compute EB
            eb = self.compute_exchange_value(
                self.state.mackey,
                self.state.responder,
                self.state.initiator,
                rb,
                bytes(
                    [
                        self.state.responder.authentication,
                        self.state.responder.oob,
                        self.state.responder.iocap
                    ]
                )
            )
            # Compare it with the received data

            if eb == dhkey_check.dhkey_check[::-1]:

                # Get the current connection handle
                conn_handle = self.get_layer('l2cap').state.conn_handle

                # Get the current link layer state
                local_conn = self.get_layer('ll').state.register_encryption_key(conn_handle, self.state.ltk)
                # Start encryption
                self.get_layer('ll').start_encryption(conn_handle, 0, 0)

                self.state.state = SecurityManagerState.STATE_LESC_DHK_CHECK_RECVD

            # otherwise, fail.
            else:
                logger.info('Invalid exchange value received, report error and return to idle.')

                # Notify error
                error = SM_Failed(
                    reason = SM_ERROR_DHKEY_CHECK_FAILED
                )
                self.send_data(error)

                # Return to IDLE mode
                self.__state = SecurityManagerState.STATE_IDLE

        else:
            logger.info('Unexpected packet received, report error and return to idle.')

            # Notify error
            error = SM_Failed(
                reason = SM_ERROR_UNSPEC_REASON
            )
            self.send_data(error)

            # Return to IDLE mode
            self.__state = SecurityManagerState.STATE_IDLE

    def on_pairing_response(self, pairing_resp):
        """Method called when a pairing response is received.

        :param SM_Pairing_Response pairing_resp: Pairing response packet
        """
        logger.info('Received Pairing Response')

        # Make sure we are in a state that allows this pairing request
        if self.state.state == SecurityManagerState.STATE_PAIRING_RSP:
            logger.info('Pairing Response accepted, processing ...')

            # Save pairing response
            self.state.pairing_resp = pairing_resp


            # Get the current connection handle
            conn_handle = self.get_layer('l2cap').state.conn_handle

            # Get the current link layer state
            local_conn = self.get_layer('ll').state.get_connection(conn_handle)

            remote_peer_addr = local_conn['remote_peer_addr']
            remote_peer_addr_type = local_conn['remote_peer_addr_type']

            remote_addr_object = BDAddress.from_bytes(
                remote_peer_addr,
                addr_type = BDAddress.PUBLIC if
                            remote_peer_addr_type == 0 else
                            BDAddress.RANDOM
            )

            #Configure the responder
            self.state.responder = SM_Peer(remote_addr_object)

            self.state.responder.set_security_parameters(
                oob=(pairing_resp.oob == 0x01),
                bonding=((pairing_resp.authentication & 0x03) != 0),
                mitm=((pairing_resp.authentication & 0x04) != 0),
                lesc=((pairing_resp.authentication & 0x08) != 0),
                keypress=((pairing_resp.authentication & 0x10) != 0),
                max_key_size = pairing_resp.max_key_size
            )
            self.state.responder.iocap = pairing_resp.iocap

            # Store responder key distribution options
            self.state.responder.distribute_keys(
                enc_key = ((pairing_resp.responder_key_distribution & 0x01) != 0),
                id_key = ((pairing_resp.responder_key_distribution & 0x02) != 0),
                sign_key =((pairing_resp.responder_key_distribution & 0x04) != 0),
                link_key = ((pairing_resp.responder_key_distribution & 0x08) != 0)
            )


            # Check key generation method in use
            self.state.method = self.key_generation_method_selection(self.state.initiator, self.state.responder)

            if self.state.method == PM_LEGACY_JUSTWORKS:
                self.state.tk = b"\x00" * 16
            elif self.state.method == PM_LEGACY_PASSKEY:
                pin = self.get_pin_code() # TODO: allow to pass a callback here to customize PIN entry
                self.state.tk = bytes.fromhex("00"*12 + "{:08x}".format(pin))
            elif self.state.method in (PM_LESC_NUMCOMP, PM_LESC_JUSTWORKS, PM_LESC_PASSKEY):
                # Generate the P256 keypair
                self.state.private_key, self.state.public_key = generate_p256_keypair()

            if self.state.method in (PM_LEGACY_JUSTWORKS, PM_LEGACY_PASSKEY):
                # Generate a RAND and compute CONFIRM
                self.state.initiator.generate_legacy_rand()
                self.state.initiator.confirm = self.compute_legacy_confirm_value(
                    self.state.tk,
                    self.state.initiator.rand,
                    self.state.pairing_req,
                    self.state.pairing_resp,
                    self.state.initiator,
                    self.state.responder
                )
                logger.debug('[send_pairing_confirm] Computed CONFIRM=%s' % hexlify(self.state.initiator.confirm))

                # Send CONFIRM value (again, we need to reverse its bytes)
                confirm_value = SM_Confirm(
                    confirm = self.state.initiator.confirm[::-1]
                )
                self.send_data(confirm_value)

                # Update current state
                self.state.state = SecurityManagerState.STATE_LEGACY_PAIRING_CONFIRM_SENT
            else:

                # Let's transmit our public key
                own_x = bytes.fromhex("{:064x}".format(self.state.public_key.public_numbers().x))[::-1]
                own_y = bytes.fromhex("{:064x}".format(self.state.public_key.public_numbers().y))[::-1]

                self.send_data(
                    SM_Public_Key(
                        key_x = own_x,
                        key_y = own_y
                    )
                )
                self.state.state = SecurityManagerState.STATE_LESC_PUBKEY_SENT

        else:
            logger.info('Unexpected packet received, report error and return to idle.')

            # Notify error
            error = SM_Failed(
                reason = SM_ERROR_UNSPEC_REASON
            )
            self.send_data(error)

            # Return to IDLE mode
            self.__state = SecurityManagerState.STATE_IDLE

    def on_pairing_confirm(self, confirm):
        """Method called whan a pairing confirm value is received.
        """
        # Make sure we have already sent a pairing request before
        logger.info('Received Pairing Confirm value')
        if self.state.state == SecurityManagerState.STATE_PAIRING_REQ:
            logger.info('Pairing Confirm value is expected, processing ...')

            # Store remote peer Confirm value (value is stored byte-reversed in Packet)
            self.state.initiator.confirm = confirm.confirm[::-1]

            # Generate a RAND and compute CONFIRM
            self.state.responder.generate_legacy_rand()
            self.state.responder.confirm = self.compute_legacy_confirm_value(
                self.state.tk,
                self.state.responder.rand,
                self.state.pairing_req,
                self.state.pairing_resp,
                self.state.initiator,
                self.state.responder
            )
            logger.debug('[on_pairing_confirm] Computed CONFIRM=%s' % hexlify(self.state.responder.confirm))

            # Send CONFIRM value (again, we need to reverse its bytes)
            confirm_value = SM_Confirm(
                confirm = self.state.responder.confirm[::-1]
            )
            self.send_data(confirm_value)

            # Update current state
            self.state.state = SecurityManagerState.STATE_LEGACY_PAIRING_CONFIRM_SENT


        elif self.state.state == SecurityManagerState.STATE_LEGACY_PAIRING_CONFIRM_SENT:

            # Store remote peer Confirm value (value is stored byte-reversed in Packet)
            self.state.responder.confirm = confirm.confirm[::-1]

            # Send back our random
            rand_value = SM_Random(
                random = self.state.initiator.rand[::-1]
            )
            self.send_data(rand_value)

            self.state.state = SecurityManagerState.STATE_LEGACY_PAIRING_RANDOM_SENT

        elif self.state.state == SecurityManagerState.STATE_LESC_PUBKEY_RECVD:
            logger.info('Pairing Confirm value is expected, processing ...')

            # Store remote peer Confirm value (value is stored byte-reversed in Packet)
            self.state.responder.confirm = confirm.confirm[::-1]
            self.state.initiator.generate_legacy_rand()

            # Send back our random
            rand_value = SM_Random(
                random = self.state.initiator.rand[::-1]
            )
            self.send_data(rand_value)

            # Update current state
            self.state.state = SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT

        elif self.state.state in (
            SecurityManagerState.STATE_LESC_PUBKEY_RECVD_STAGEN,
            SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT_STAGEN
        ):
            logger.info('Pairing Confirm value is expected, processing ...')
            print("rcvd confirm #",self.state.passkey_counter)
            if self.state.passkey_counter == 1:
                # Collect passkey entry
                self.state.passkey_value = self.get_passkey_entry()

            # Extract confirm value
            self.state.initiator.confirm = confirm.confirm[::-1]

            # Generate Nbi
            self.state.responder.generate_legacy_rand()

            self.state.responder.confirm = self.compute_lesc_confirm_value(
                self.state.peer_public_key,  # we are the responder, peer is the initiator
                self.state.public_key,  # set our own public key
                self.state.responder.rand,
                bytes([((self.state.passkey_value >> (self.state.passkey_counter - 1)) & 1) + 0x80])
            )

            self.send_data(
                SM_Confirm(
                    confirm = self.state.responder.confirm[::-1]
                )
            )

            self.state.state = SecurityManagerState.STATE_LESC_PAIRING_CONFIRM_SENT_STAGEN

        elif self.state.state == SecurityManagerState.STATE_LESC_PAIRING_CONFIRM_SENT_STAGEN:
            logger.info('Pairing Confirm value is expected, processing ...')
            print("rcvd confirm #",self.state.passkey_counter)

            # Extract confirm value
            self.state.responder.confirm = confirm.confirm[::-1]

            # Transmit random
            self.send_data(
                SM_Random(
                    random = self.state.initiator.rand[::-1]
                )
            )
            self.state.state = SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT_STAGEN

        else:
            logger.info('Pairing Confirm dropped because current state is %d' % self.state.state)

            # Notify error
            error = SM_Failed(
                reason = SM_ERROR_UNSPEC_REASON
            )
            self.send_data(error)

            # Return to IDLE mode
            self.state.state = SecurityManagerState.STATE_IDLE

    def check_lesc_numeric_comparison(self, value):
        print("Computed value is: ", value)
        print("y to continue process, n to discard")
        user_input = input()
        return user_input.upper().startswith("Y")


    def on_pairing_random(self, random_pkt):
        """Handling random packet
        """
        logger.info('Received Pairing Random value')
        if self.state.state == SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT:
            logger.info('Pairing Random value is expected, processing ...')

            # Save initiator RAND (reverse byte order)
            self.state.responder.rand = random_pkt.random[::-1]
            if self.check_lesc_confirm_value(
                    self.state.public_key,
                    self.state.peer_public_key,
                    self.state.responder.rand,
                    b"\x00",
                    self.state.responder.confirm
            ):
                # Confirm value is valid !
                # Now, we need to display the value for numeric comparison
                if self.state.method == PM_LESC_JUSTWORKS:
                    continue_pairing = True
                else:
                    value = self.compute_lesc_numeric_comparison(
                        self.state.public_key,
                        self.state.peer_public_key,
                        self.state.initiator.rand,
                        self.state.responder.rand
                    )

                    continue_pairing = self.check_lesc_numeric_comparison(value)

                if continue_pairing:
                    print("Accepted numeric comparison, continuing...")
                    self.state.ltk, self.state.mackey = self.compute_ltk_and_mackey(
                        self.state.shared_secret,
                        self.state.initiator,
                        self.state.responder
                    )

                    self.state.rand, self.state.ediv = b"\x00"*8, 0
                    # Indicate LTK as distributed
                    self.state.initiator.indicate_ltk_distribution(self.state.ltk)
                    self.state.initiator.indicate_rand_ediv_distribution(self.state.rand, self.state.ediv)
                    self.state.responder.indicate_ltk_distribution(self.state.ltk)
                    self.state.responder.indicate_rand_ediv_distribution(self.state.rand, self.state.ediv)

                    rb = 0 # in num comp and just works, TODO: adapt for passkey
                    # Let's compute EA
                    ea = self.compute_exchange_value(
                        self.state.mackey,
                        self.state.initiator,
                        self.state.responder,
                        0,
                        bytes(
                            [
                                self.state.initiator.authentication,
                                self.state.initiator.oob,
                                self.state.initiator.iocap
                            ]
                        )
                    )
                    #Transmit EA
                    self.send_data(
                        SM_DHKey_Check(
                            dhkey_check=ea[::-1]
                        )
                    )

                    self.state.state = SecurityManagerState.STATE_LESC_DHK_CHECK_SENT
                else:
                    logger.info('Invalid Numeric comparison (expected %s)' % (
                        str(value),
                    ))

                    # Send error
                    error = SM_Failed(
                        reason = SM_ERROR_NUMCOMP_FAILED
                    )
                    self.send_data(error)

                    # Return to IDLE
                    self.state.state = SecurityManagerState.STATE_IDLE
            else:
                # Send error
                error = SM_Failed(
                    reason = SM_ERROR_CONFIRM_VALUE_FAILED
                )
                self.send_data(error)

                # Return to IDLE
                self.state.state = SecurityManagerState.STATE_IDLE


        elif self.state.state == SecurityManagerState.STATE_LESC_PAIRING_CONFIRM_SENT:
            logger.info('Pairing Random value is expected, processing ...')

            # Save initiator RAND (reverse byte order)
            self.state.initiator.rand = random_pkt.random[::-1]

            # Send back our random
            rand_value = SM_Random(
                random = self.state.responder.rand[::-1]
            )
            self.send_data(rand_value)
            if self.state.method == PM_LESC_JUSTWORKS:
                continue_pairing = True
            else:
                # Now, we need to display the value for numeric comparison
                value = self.compute_lesc_numeric_comparison(
                    self.state.peer_public_key,
                    self.state.public_key,
                    self.state.initiator.rand,
                    self.state.responder.rand
                )

                continue_pairing = self.check_lesc_numeric_comparison(value)
            if continue_pairing:
                print("Accepted numeric comparison, continuing...")
                self.state.state = SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT
            else:
                logger.info('Invalid Numeric comparison (expected %s)' % (
                    str(value),
                ))

                # Send error
                error = SM_Failed(
                    reason = SM_ERROR_NUMCOMP_FAILED
                )
                self.send_data(error)

                # Return to IDLE
                self.state.state = SecurityManagerState.STATE_IDLE

        elif self.state.state == SecurityManagerState.STATE_LEGACY_PAIRING_CONFIRM_SENT:
            logger.info('Pairing Random value is expected, processing ...')

            # Save initiator RAND (reverse byte order)
            self.state.initiator.rand = random_pkt.random[::-1]

            if self.check_initiator_legacy_confirm(self.state.tk):
                logger.info('Initiator CONFIRM successfully verified')
                # Send back our random
                rand_value = SM_Random(
                    random = self.state.responder.rand[::-1]
                )
                self.send_data(rand_value)

                # Compute our stk
                self.__stk = s1(
                    self.state.tk,
                    self.state.responder.rand,
                    self.state.initiator.rand
                )

                logger.debug('[on_pairing_random] STK=%s' % hexlify(self.state.stk))

                # Next state
                self.state.state = SecurityManagerState.STATE_LEGACY_PAIRING_RANDOM_SENT

                # Notify connection that we successfully negociated STK and that
                # the corresponding material is available.

                # Get the current connection handle
                conn_handle = self.get_layer('l2cap').state.conn_handle

                # Get the current link layer state
                local_conn = self.get_layer('ll').state.register_encryption_key(conn_handle, self.__stk)

                #self.__l2cap.connection.set_stk(self.__stk)

            else:
                logger.info('Invalid Initiator CONFIRM value (expected %s)' % (
                    hexlify(self.state.initiator.confirm),
                ))

                # Send error
                error = SM_Failed(
                    reason = SM_ERROR_CONFIRM_VALUE_FAILED
                )
                self.send_data(error)

                # Return to IDLE
                self.state.state = SecurityManagerState.STATE_IDLE

        elif self.state.state == SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT_STAGEN:
            self.state.responder.rand = random_pkt.random[::-1]
            ri = bytes([((self.state.passkey_value >> (self.state.passkey_counter - 1)) & 1) + 0x80])
            print(ri)
            computed_confirm = self.compute_lesc_confirm_value(
                self.state.public_key,
                self.state.peer_public_key,
                self.state.responder.rand,
                ri
            )
            print("Computed: ", computed_confirm.hex())
            print("Received: ", self.state.responder.confirm.hex())

            if computed_confirm == self.state.responder.confirm:
                if self.state.passkey_counter == 20:
                    self.state.ltk, self.state.mackey = self.compute_ltk_and_mackey(
                        self.state.shared_secret,
                        self.state.initiator,
                        self.state.responder
                    )

                    self.state.rand, self.state.ediv = b"\x00"*8, 0
                    # Indicate LTK as distributed
                    self.state.initiator.indicate_ltk_distribution(self.state.ltk)
                    self.state.initiator.indicate_rand_ediv_distribution(self.state.rand, self.state.ediv)
                    self.state.responder.indicate_ltk_distribution(self.state.ltk)
                    self.state.responder.indicate_rand_ediv_distribution(self.state.rand, self.state.ediv)

                    ra = self.state.passkey_value
                    # Let's compute EA
                    ea = self.compute_exchange_value(
                        self.state.mackey,
                        self.state.initiator,
                        self.state.responder,
                        ra,
                        bytes(
                            [
                                self.state.initiator.authentication,
                                self.state.initiator.oob,
                                self.state.initiator.iocap
                            ]
                        )
                    )

                    # Then transmit it
                    self.send_data(
                        SM_DHKey_Check(
                            dhkey_check = ea[::-1]
                        )
                    )
                    self.state.state = SecurityManagerState.STATE_LESC_DHK_CHECK_SENT

                else:
                    # Increment counter
                    self.state.passkey_counter += 1

                    # Generate Nai
                    self.state.initiator.generate_legacy_rand()

                    self.state.initiator.confirm = self.compute_lesc_confirm_value(
                        self.state.peer_public_key,  # set our own public key
                        self.state.public_key,  # we are the initiator, peer is the responder
                        self.state.initiator.rand,
                        bytes([((self.state.passkey_value >> (self.state.passkey_counter - 1)) & 1) + 0x80])
                    )

                    self.send_data(
                        SM_Confirm(
                            confirm = self.state.initiator.confirm[::-1]
                        )
                    )

                    self.state.state = SecurityManagerState.STATE_LESC_PAIRING_CONFIRM_SENT_STAGEN
            else:

                logger.info('Invalid responder CONFIRM value (expected %s)' % (
                    hexlify(self.state.responder.confirm),
                ))

                # Send error
                error = SM_Failed(
                    reason = SM_ERROR_CONFIRM_VALUE_FAILED
                )
                self.send_data(error)

                # Return to IDLE
                self.state.state = SecurityManagerState.STATE_IDLE



        elif self.state.state == SecurityManagerState.STATE_LESC_PAIRING_CONFIRM_SENT_STAGEN:
            self.state.initiator.rand = random_pkt.random[::-1]

            print("val", self.state.passkey_value)
            ri = bytes([((self.state.passkey_value >> (self.state.passkey_counter - 1)) & 1) + 0x80])
            print(ri)
            computed_confirm = self.compute_lesc_confirm_value(
                self.state.public_key,
                self.state.peer_public_key,
                self.state.initiator.rand,
                ri
            )
            print("Computed: ", computed_confirm.hex())
            print("Received: ", self.state.initiator.confirm.hex())

            if computed_confirm == self.state.initiator.confirm:
                self.send_data(
                    SM_Random(
                        random = self.state.responder.rand[::-1]
                    )
                )

                if self.state.passkey_counter == 20:
                    print("here")
                    self.state.state = SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT
                else:
                    self.state.passkey_counter += 1
                    self.state.state = SecurityManagerState.STATE_LESC_PAIRING_RANDOM_SENT_STAGEN
            else:

                logger.info('Invalid Initiator CONFIRM value (expected %s)' % (
                    hexlify(self.state.initiator.confirm),
                ))

                # Send error
                error = SM_Failed(
                    reason = SM_ERROR_CONFIRM_VALUE_FAILED
                )
                self.send_data(error)

                # Return to IDLE
                self.state.state = SecurityManagerState.STATE_IDLE



        elif self.state.state == SecurityManagerState.STATE_LEGACY_PAIRING_RANDOM_SENT:
            logger.info('Pairing Random value is expected, processing ...')

            # Save responder RAND (reverse byte order)
            self.state.responder.rand = random_pkt.random[::-1]

            if self.check_responder_legacy_confirm(
                self.state.tk,
                self.state.pairing_req,
                self.state.pairing_resp,
                self.state.initiator,
                self.state.responder
            ):
                logger.info('Responder CONFIRM successfully verified')

                # Compute our stk
                self.__stk = s1(
                    self.state.tk,
                    self.state.responder.rand,
                    self.state.initiator.rand
                )


                logger.debug('[on_pairing_random] STK=%s' % hexlify(self.state.stk))

                # Next state
                self.state.state = SecurityManagerState.STATE_LEGACY_PAIRING_RANDOM_RECVD

                # Notify connection that we successfully negociated STK and that
                # the corresponding material is available.

                # Get the current connection handle
                conn_handle = self.get_layer('l2cap').state.conn_handle

                # Get the current link layer state
                local_conn = self.get_layer('ll').state.register_encryption_key(conn_handle, self.__stk)

                self.get_layer('ll').start_encryption(conn_handle, 0, 0)

            else:
                logger.info('Invalid Responder CONFIRM value (expected %s)' % (
                    hexlify(self.state.responder.confirm),
                ))

                # Send error
                error = SM_Failed(
                    reason = SM_ERROR_CONFIRM_VALUE_FAILED
                )
                self.send_data(error)

                # Return to IDLE
                self.state.state = SecurityManagerState.STATE_IDLE

        else:
            logger.info('Pairing Random dropped because current state is %d' % self.state.state)

            # Notify error
            error = SM_Failed(
                reason = SM_ERROR_UNSPEC_REASON
            )
            self.send_data(error)

            # Return to IDLE mode
            self.state.state = SecurityManagerState.STATE_IDLE

    def on_channel_encrypted(self):
        """Handling LL_START_ENC_RSP (channel successfully encrypted).

        This method is called when we successfully received and decrypted an
        encrypted LL_START_ENC_RSP packet from the remote peer.
        """
        # Previous state was STATE_LEGACY_PAIRING_RANDOM_SENT
        # since LL_ENC_REQ / LL_ENC_RSP / LL_START_ENC_REQ / LL_START_ENC_RSP
        # sequence has been handled by the link-layer manager.

        if self.state.state == SecurityManagerState.STATE_LEGACY_PAIRING_RANDOM_SENT:
            logger.info('[smp] Channel is now successfully encrypted')
            self.perform_key_distribution()

        elif self.state.state == SecurityManagerState.STATE_LEGACY_PAIRING_RANDOM_RECVD:
            logger.info('[smp] Channel is now successfully encrypted')
            if self.state.initiator.is_key_distribution_complete():
                self.perform_key_distribution()

        elif self.state.state == SecurityManagerState.STATE_LESC_DHK_CHECK_SENT:
            logger.info('[smp] Channel is now successfully encrypted')
            self.perform_key_distribution()
        else:
            logger.error('[smp] Received an unexpected notification (LL_START_ENC_RSP)')

    def perform_key_distribution(self):

        if self.is_initiator():
            # If LTK is not None, it has been derivated from DHKey in LE SC
            # don't distribute LTK, only IRK and CSRK
            if self.state.ltk is None:
                self.state.ltk = generate_random_value(8*self.state.responder.max_key_size)
                self.state.rand = generate_random_value(8*8)
                self.state.ediv = randint(0, 0x10000)

                # Perform key distribution to responder
                sleep(.5)
                if self.state.responder.must_dist_ltk():
                    logger.info('[smp] sending generated LTK ...')
                    self.send_data(SM_Encryption_Information(
                        ltk=self.state.ltk
                    ))
                    logger.info('[smp] LTK sent.')
                if self.state.responder.must_dist_ediv_rand():
                    logger.info('[smp] sending generated EDIV/RAND ...')
                    self.send_data(SM_Master_Identification(ediv = self.state.ediv, rand = self.state.rand))
                logger.info('[smp] EDIV/RAND sent.')
            if self.state.responder.must_dist_irk():
                logger.info('[smp] sending generated IRK ...')
                self.state.irk = generate_random_value(8*self.state.responder.max_key_size)
                self.send_data(SM_Identity_Information(
                    irk = self.state.irk
                ))
                logger.info('[smp] IRK sent.')
                self.send_data(
                    SM_Identity_Address_Information(
                        atype = self.state.initiator.address_type,
                        address = self.state.initiator.address
                    )
                )
                logger.info('[smp] Address information sent.')


            if self.state.responder.must_dist_csrk():
                logger.info('[smp] sending generated CSRK ...')
                self.state.csrk = generate_random_value(8*self.state.responder.max_key_size)
                self.send_data(SM_Signing_Information(
                    csrk=self.state.csrk
                ))
                logger.info('[smp] CSRK sent.')

            self.bonding_done()

        else:
            if self.state.ltk is None:
                self.state.ltk = generate_random_value(8*self.state.initiator.max_key_size)
                self.state.rand = generate_random_value(8*8)
                self.state.ediv = randint(0, 0x10000)

                # Perform key distribution to initiator
                sleep(.5)
                if self.state.initiator.must_dist_ltk():
                    logger.info('[smp] sending generated LTK ...')
                    self.send_data(SM_Encryption_Information(
                        ltk=self.state.ltk
                    ))
                    logger.info('[smp] LTK sent.')
                if self.state.initiator.must_dist_ediv_rand():
                    logger.info('[smp] sending generated EDIV/RAND ...')
                    self.send_data(SM_Master_Identification(ediv = self.state.ediv, rand = self.state.rand))
                    logger.info('[smp] EDIV/RAND sent.')
            if self.state.initiator.must_dist_irk():
                logger.info('[smp] sending generated IRK ...')
                self.state.irk = generate_random_value(8*self.state.responder.max_key_size)
                self.send_data(SM_Identity_Information(
                    irk = self.state.irk
                ))
                logger.info('[smp] IRK sent.')
                self.send_data(
                    SM_Identity_Address_Information(
                        atype = self.state.responder.address_type,
                        address = self.state.responder.address
                    )
                )
                logger.info('[smp] Address information sent.')
            if self.state.initiator.must_dist_csrk():
                logger.info('[smp] sending generated CSRK ...')
                self.state.csrk = generate_random_value(8*self.state.responder.max_key_size)
                self.send_data(SM_Signing_Information(
                    csrk=self.state.csrk
                ))
                logger.info('[smp] CSRK sent.')

            self.state.state = SecurityManagerState.STATE_DISTRIBUTE_KEY

    def on_encryption_information(self, encryption_information):
        if self.is_initiator():
            self.state.initiator.indicate_ltk_distribution(encryption_information.ltk)
            if self.state.initiator.is_key_distribution_complete():
                self.perform_key_distribution()
        else:
            self.state.responder.indicate_ltk_distribution(encryption_information.ltk)
            if self.state.responder.is_key_distribution_complete():
                self.bonding_done()

    def on_master_identification(self, master_identification):
        if self.is_initiator():
            self.state.initiator.indicate_rand_ediv_distribution(master_identification.rand, master_identification.ediv)
            if self.state.initiator.is_key_distribution_complete():
                self.perform_key_distribution()
        else:
            self.state.responder.indicate_rand_ediv_distribution(master_identification.rand, master_identification.ediv)
            if self.state.responder.is_key_distribution_complete():
                self.bonding_done()


    def on_identity_information(self, identity_information):
        if self.is_initiator():
            self.state.initiator.indicate_irk_distribution(identity_information.irk)
            if self.state.initiator.is_key_distribution_complete():
                self.perform_key_distribution()
        else:
            self.state.responder.indicate_irk_distribution(identity_information.irk)
            if self.state.responder.is_key_distribution_complete():
                self.bonding_done()


    def on_identity_address_information(self, identity_address_information):
        if self.is_initiator():
            self.state.initiator.indicate_address_distribution(identity_address_information.address, identity_address_information.atype)
            if self.state.initiator.is_key_distribution_complete():
                self.perform_key_distribution()
        else:
            self.state.responder.indicate_address_distribution(identity_address_information.address, identity_address_information.atype)
            if self.state.responder.is_key_distribution_complete():
                self.bonding_done()


    def on_signing_information(self, signing_information):
        if self.is_initiator():
            self.state.initiator.indicate_csrk_distribution(signing_information.csrk)
            if self.state.initiator.is_key_distribution_complete():
                self.perform_key_distribution()
        else:
            self.state.responder.indicate_csrk_distribution(signing_information.csrk)
            if self.state.responder.is_key_distribution_complete():
                self.bonding_done()


    def bonding_done(self):
        print("Bonding done.")
        if self.is_initiator():
            if self.state.ltk is not None:
                print("Distributed LTK: ", self.state.ltk.hex())
            if self.state.rand is not None:
                print("Distributed RAND: ", self.state.rand.hex())
            if self.state.ediv is not None:
                print("Distributed EDIV: ", hex(self.state.ediv))
            if self.state.irk is not None:
                print("Distributed IRK: ", self.state.irk.hex())
            if self.state.csrk is not None:
                print("Distributed CSRK: ", self.state.csrk.hex())

            if self.state.initiator.ltk is not None:
                print("Received LTK: ", self.state.initiator.ltk.hex())
            if self.state.initiator.rand is not None:
                print("Received RAND: ", self.state.initiator.random.hex())
            if self.state.initiator.ediv is not None:
                print("Received EDIV: ", hex(self.state.initiator.ediv))
            if self.state.initiator.irk is not None:
                print("Received IRK: ", self.state.initiator.irk.hex())
            if self.state.initiator.csrk is not None:
                print("Received CSRK: ", self.state.initiator.csrk.hex())
        else:
            if self.state.ltk is not None:
                print("Distributed LTK: ", self.state.ltk.hex())
            if self.state.rand is not None:
                print("Distributed RAND: ", self.state.rand.hex())
            if self.state.ediv is not None:
                print("Distributed EDIV: ", hex(self.state.ediv))
            if self.state.irk is not None:
                print("Distributed IRK: ", self.state.irk.hex())
            if self.state.csrk is not None:
                print("Distributed CSRK: ", self.state.csrk.hex())

            if self.state.responder.ltk is not None:
                print("Received LTK: ", self.state.responder.ltk.hex())
            if self.state.responder.rand is not None:
                print("Received RAND: ", self.state.responder.random.hex())
            if self.state.responder.ediv is not None:
                print("Received EDIV: ", hex(self.state.responder.ediv))
            if self.state.responder.irk is not None:
                print("Received IRK: ", self.state.responder.irk.hex())
            if self.state.responder.csrk is not None:
                print("Received CSRK: ", self.state.responder.csrk.hex())

        self.state.state = SecurityManagerState.STATE_BONDING_DONE

    def send_data(self, packet):
        self.send('l2cap', SM_Hdr()/packet)

'''
@alias('smp')
class BleSMP(Layer):

    STATE_IDLE = 0x00
    STATE_PAIRING_REQ = 0x01
    STATE_PAIRING_RSP = 0x02
    STATE_LEGACY_PAIRING_CONFIRM_SENT = 0x03
    STATE_LEGACY_PAIRING_CONFIRM_RECVD = 0x04
    STATE_LEGACY_PAIRING_RANDOM_SENT = 0x05
    STATE_LEGACY_PAIRING_RANDOM_RECVD = 0x06
    STATE_LESC_PUBKEY_SENT = 0x07
    STATE_LESC_PUBKEY_RECVD = 0x08
    STATE_LESC_PAIRING_CONFIRM_SENT = 0x09
    STATE_LESC_PAIRING_RANDOM_SENT = 0x0A
    STATE_LESC_PAIRING_RANDOM_RECVD = 0x0B
    STATE_LESC_DHK_CHECK_SENT = 0x0C
    STATE_LESC_DHK_CHECK_RECVD = 0x0D
    STATE_PAIRING_DONE = 0x0E
    STATE_DISTRIBUTE_KEY = 0x0F
    STATE_BONDING_DONE = 0xFF

    def __init__(self, l2cap, justworks=True, lesc=False, capabilities=IOCAP_NOINPUT_NOOUTPUT):
        self.__l2cap = l2cap

        # Peers' states
        self.__initiator = None
        self.__responder = None

        # Current state
        self.__state = BleSMP.STATE_IDLE

        # Crypto manager
        self.__cm = None

        # Initiator Key Distribution
        self.__ikd = None

        # Responder Key Distribution
        self.__rkd = None

        # Pairing material
        self.__pairing_req = None
        self.__pairing_resp = None
        self.__tk = b'\x00'*16
        self.__stk = b'\x00'*16
        self.__ltk = b'\x00'*16

        # Initiator role
        self.__enc_initiator = False


    def is_initiator(self):
        return self.__enc_initiator

    ##
    # Helpers
    ##

    def compute_legacy_confirm_value(self, tk, rand, preq, pres, initiator, responder):
        """Compute Confirm value as described in [Vol 3] Part H, Section 2.3.5.5

        This value is not ready to be set in a SM_Confirm packet as-is, it needs
        to be byte-reversed to be correctly decoded.

        :param bytes tk: Temporary Key
        :param bytes rand: Random to encrypt
        :param Packet preq: Pairing request
        :param Packet pres: Pairing response
        :param SM_Peer initiator: Pairing initiator
        :param SM_Peer responder: Pairing responder

        :return: Confirm value
        :rtype: bytes
        """
        logger.debug('TK=%s RAND=%s, PRES=%s PREQ=%s INITA_TYPE=%02x INITA=%s RESPA_TYPE=%02x RESPA=%s' % (
            hexlify(tk),
            hexlify(rand),
            hexlify(bytes(SM_Hdr()/pres)[::-1]),
            hexlify(bytes(SM_Hdr()/preq)[::-1]),
            initiator.address_type,
            hexlify(initiator.address[::-1]),
            responder.address_type,
            hexlify(responder.address[::-1])
        ))

        # Compute the confirm value for the provided parameters
        # We need to:
        # - convert `preq` to bytes in reverse order including SM_Hdr
        # - convert `pres` to bytes in reverse order including SM_Hdr
        # - reverse order of BD addresses
        # - pack address types as 8-bit data (prefixed by 7 zeroes)

        _confirm = c1(
            tk,
            rand,
            bytes(SM_Hdr()/pres)[::-1],
            bytes(SM_Hdr()/preq)[::-1],
            pack('<B', initiator.address_type),
            initiator.address[::-1],
            pack('<B', responder.address_type),
            responder.address[::-1]
        )
        return _confirm

    def check_initiator_confirm(self, tk):
        """Check initiator peer confirm value given a TK and the corresponding random value.

        :param SM_Peer: Peer to check
        :param bytes tk: Temporary Key
        :param Packet preq: Pairing request
        :param Packet pres: Pairing response
        :param SM_Peer initiator: Pairing initiator
        :param SM_Peer responder: Pairing responder
        """
        logger.debug('[check_initiator_confirm] RAND=%s' % hexlify(self.__initiator.rand))
        # Compute expected confirm value
        expected_confirm = self.compute_legacy_confirm_value(
            tk,
            self.__initiator.rand,
            self.__pairing_req,
            self.__pairing_resp,
            self.__initiator,
            self.__responder
        )
        logger.debug('[check_initiator_confirm] Computed CONFIRM=%s' % hexlify(expected_confirm))
        logger.debug('[check_initiator_confirm] Expected CONFIRM=%s' % hexlify(self.__initiator.confirm))

        # Compare with confirm value
        return (expected_confirm == self.__initiator.confirm)

    def check_responder_confirm(self, tk, preq, pres, initiator, responder):
        """Check responder peer confirm value given a TK and the corresponding random value.

        :param SM_Peer: Peer to check
        :param bytes tk: Temporary Key
        :param Packet preq: Pairing request
        :param Packet pres: Pairing response
        :param SM_Peer initiator: Pairing initiator
        :param SM_Peer responder: Pairing responder
        """
        logger.debug('[check_responder_confirm] RAND=%s' % hexlify(self.__initiator.rand))

        # Compute expected confirm value
        expected_confirm = self.compute_legacy_confirm_value(
            tk,
            self.__responder.rand,
            self.__pairing_req,
            self.__pairing_resp,
            self.__initiator,
            self.__responder
        )

        logger.debug('[check_initiator_confirm] Computed CONFIRM=%s' % hexlify(expected_confirm))
        logger.debug('[check_initiator_confirm] Expected CONFIRM=%s' % hexlify(self.__responder.confirm))

        # Compare with confirm value
        return (expected_confirm == self.__responder.confirm)


    def on_smp_packet(self, packet):
        """SMP packet reception callback

        This method dispatches every LE SMP packet received.

        :param Packet packet: Scapy packet containing SMP material
        """
        if SM_Pairing_Request in packet:
            self.on_pairing_request(packet.getlayer(SM_Pairing_Request))
        elif SM_Pairing_Response in packet:
            self.on_pairing_response(packet.getlayer(SM_Pairing_Response))
        elif SM_Confirm in packet:
            self.on_pairing_confirm(packet.getlayer(SM_Confirm))
        elif SM_Random in packet:
            self.on_pairing_random(packet.getlayer(SM_Random))

    def send(self, packet):
        self.__l2cap.send(SM_Hdr()/packet, channel=0x06)

    def on_pairing_request(self, pairing_req):
        """Method called when a pairing request is received.

        :param SM_Pairing_Request pairing_req: Pairing request packet
        """
        logger.info('Received Pairing Request')

        # Make sure we are in a state that allows this pairing request
        if self.__state == BleSMP.STATE_IDLE:
            logger.info('Pairing Request accepted, processing ...')

            # Save pairing request
            self.__pairing_req = pairing_req

            # We are definitely not the initiator but the responder
            self.__enc_initiator = False
            self.__responder = SM_Peer(self.__l2cap.connection.local_peer)

            # Create the initiator SM_Peer instance
            # (along with all its parameters are defined in the pairing request)
            self.__initiator = SM_Peer(self.__l2cap.connection.remote_peer)
            self.__initiator.set_security_parameters(
                oob=(pairing_req.oob == 0x01),
                bonding=((pairing_req.authentication & 0x03) != 0),
                mitm=((pairing_req.authentication & 0x04) != 0),
                lesc=((pairing_req.authentication & 0x08) != 0),
                keypress=((pairing_req.authentication & 0x10) != 0),
                max_key_size = pairing_req.max_key_size
            )
            self.__initiator.iocap = pairing_req.iocap

            # Store initiator key distribution options
            self.__initiator.distribute_keys(
                enc_key = ((pairing_req.responder_key_distribution & 0x01) != 0),
                id_key = ((pairing_req.responder_key_distribution & 0x02) != 0),
                sign_key =((pairing_req.responder_key_distribution & 0x04) != 0),
                link_key = ((pairing_req.responder_key_distribution & 0x08) != 0)
            )

            # Send our pairing response
            pairing_resp = SM_Pairing_Response(
                iocap=self.__responder.iocap,
                oob=self.__responder.oob,
                authentication=self.__responder.authentication,
                max_key_size=self.__responder.max_key_size,
                initiator_key_distribution=self.__initiator.get_key_distribution(),
                responder_key_distribution=self.__responder.get_key_distribution()
            )

            # Save pairing response
            self.__pairing_resp = pairing_resp

            self.send(pairing_resp)

            # Update current state
            self.__state = BleSMP.STATE_PAIRING_REQ

        else:
            logger.info('Unexpected packet received, report error and return to idle.')

            # Notify error
            error = SM_Failed(
                reason = SM_ERROR_UNSPEC_REASON
            )
            self.send(error)

            # Return to IDLE mode
            self.__state = BleSMP.STATE_IDLE

    def on_pairing_confirm(self, confirm):
        """Method called whan a pairing confirm value is received.
        """
        # Make sure we have already sent a pairing request before
        logger.info('Received Pairing Confirm value')
        if self.__state == BleSMP.STATE_PAIRING_REQ:
            logger.info('Pairing Confirm value is expected, processing ...')

            # Store remote peer Confirm value (value is stored byte-reversed in Packet)
            self.__initiator.confirm = confirm.confirm[::-1]

            # Generate a RAND and compute CONFIRM
            self.__responder.generate_legacy_rand()
            self.__responder.confirm = self.compute_legacy_confirm_value(
                self.__tk,
                self.__responder.rand,
                self.__pairing_req,
                self.__pairing_resp,
                self.__initiator,
                self.__responder
            )
            logger.debug('[on_pairing_confirm] Computed CONFIRM=%s' % hexlify(self.__responder.confirm))

            # Send CONFIRM value (again, we need to reverse its bytes)
            confirm_value = SM_Confirm(
                confirm = self.__responder.confirm[::-1]
            )
            confirm_value.show()
            self.send(confirm_value)

            # Update current state
            self.__state = BleSMP.STATE_LEGACY_PAIRING_CONFIRM_SENT

        else:
            logger.info('Pairing Confirm dropped because current state is %d' % self.__state)

            # Notify error
            error = SM_Failed(
                reason = SM_ERROR_UNSPEC_REASON
            )
            self.send(error)

            # Return to IDLE mode
            self.__state = BleSMP.STATE_IDLE

    def on_pairing_random(self, random_pkt):
        """Handling random packet
        """
        logger.info('Received Pairing Random value')
        if self.__state == BleSMP.STATE_LEGACY_PAIRING_CONFIRM_SENT:
            logger.info('Pairing Random value is expected, processing ...')

            # Save initiator RAND (reverse byte order)
            self.__initiator.rand = random_pkt.random[::-1]

            self.check_initiator_confirm(self.__tk)
            if self.check_initiator_confirm(self.__tk):
                logger.info('Initiator CONFIRM successfully verified')
                # Send back our random
                rand_value = SM_Random(
                    random = self.__responder.rand[::-1]
                )
                self.send(rand_value)

                # Compute our stk
                self.__stk = s1(
                    self.__tk,
                    self.__responder.rand,
                    self.__initiator.rand
                )

                logger.debug('[on_pairing_random] STK=%s' % hexlify(self.__stk))

                # Next state
                self.__state = BleSMP.STATE_LEGACY_PAIRING_RANDOM_SENT

                # Notify connection that we successfully negociated STK and that
                # the corresponding material is available.
                self.__l2cap.connection.set_stk(self.__stk)
            else:
                logger.info('Invalid Initiator CONFIRM value (expected %s)' % (
                    hexlify(self.__initiator.confirm),
                ))

                # Send error
                error = SM_Failed(
                    reason = SM_ERROR_CONFIRM_VALUE_FAILED
                )
                self.send(error)

                # Return to IDLE
                self.__state = BleSMP.STATE_IDLE

        else:
            logger.info('Pairing Random dropped because current state is %d' % self.__state)

            # Notify error
            error = SM_Failed(
                reason = SM_ERROR_UNSPEC_REASON
            )
            self.send(error)

            # Return to IDLE mode
            self.__state = BleSMP.STATE_IDLE

    def on_channel_encrypted(self):
        """Handling LL_START_ENC_RSP (channel successfully encrypted).

        This method is called when we successfully received and decrypted an
        encrypted LL_START_ENC_RSP packet from the remote peer.
        """
        # Previous state was STATE_LEGACY_PAIRING_RANDOM_SENT
        # since LL_ENC_REQ / LL_ENC_RSP / LL_START_ENC_REQ / LL_START_ENC_RSP
        # sequence has been handled by the link-layer manager.

        if self.__state == BleSMP.STATE_LEGACY_PAIRING_RANDOM_SENT:
            logger.info('[smp] Channel is now successfully encrypted')

            self.__ltk = generate_random_value(2**self.__initiator.max_key_size)
            self.__rand = generate_random_value(2**8)
            self.__ediv = randint(0, 0x10000)

            # Perform key distribution to initiator
            sleep(.5)
            if self.__initiator.must_dist_ltk():
                logger.info('[smp] sending generated LTK ...')
                self.send(SM_Encryption_Information(
                    ltk=self.__ltk
                ))
                logger.info('[smp] LTK sent.')
            if self.__initiator.must_dist_ediv_rand():
                logger.info('[smp] sending generated EDIV/RAND ...')
                self.send(SM_Master_Identification(ediv = self.__ediv, rand = self.__rand))
                logger.info('[smp] EDIV/RAND sent.')
            if self.__initiator.must_dist_irk():
                logger.info('[smp] sending generated IRK ...')
                self.__irk = generate_random_value(16)
                self.send(SM_Identity_Information(
                    irk = self.__irk
                ))
                logger.info('[smp] IRK sent.')
            if self.__initiator.must_dist_csrk():
                logger.info('[smp] sending generated CSRK ...')
                self.__csrk = generate_random_value(16)
                self.send(SM_Signing_Information(
                    csrk=self.__csrk
                ))
                logger.info('[smp] CSRK sent.')
            self.__state = BleSMP.STATE_BONDING_DONE
        else:
            logger.error('[smp] Received an unexpected notification (LL_START_ENC_RSP)')



def test_confirm():
    from whad.ble.bdaddr import BDAddress
    preq = b'\x07\x07\x10\x00\x00\x01\x01'
    pres = b'\x05\x00\x08\x00\x00\x03\x02'
    tk = b'\x00'*16
    initiator = SM_Peer(BDAddress('A1:A2:A3:A4:A5:A6', random=True))
    responder = SM_Peer(BDAddress('B1:B2:B3:B4:B5:B6'))
    rand = b'\x57\x83\xD5\x21\x56\xAD\x6F\x0E\x63\x88\x27\x4E\xC6\x70\x2E\xE0'
    confirm = b'\x1E\x1E\x3F\xEF\x87\x89\x88\xEA\xD2\xA7\x4D\xC5\xBE\xF1\x3B\x86'
    print('initiator: %s' % hexlify(initiator.address[::-1]))
    print(initiator.address_type)
    _confirm = c1(
        tk,
        rand,
        pres,
        preq,
        pack('<B', initiator.address_type),
        initiator.address[::-1],
        pack('<B', responder.address_type),
        responder.address[::-1]
    )

    print('Computed CONFIRM: %s' % hexlify(_confirm))
    print('Expected CONFIRM: %s' % hexlify(confirm))
'''
