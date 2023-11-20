import argparse
import re
from binascii import unhexlify


class InvalidUUIDException(Exception):
    """Base class for Invalid HandleException -- The attribute handle given was not valid on this server."""

    def __init__(self, uuid):
        self.code = 0x01
        self.name = "Invalid UUID"
        self.description = "The supplied UUID (%s) is not a valid 16-bit or 128-bit UUID. "\
                           "(ex: 2a1b or 000AA000-0BB0-10C0-80A0-00805F9B34FB" % uuid

"""
Validators for various BLESuite input parameters supplied by the user. The use of these validators is mostly limited
to import/export and CLI features.
"""


class InvalidBDADDRException(Exception):

    def __init__(self, address):
        self.code = 0x02
        self.name = "Invalid BD_ADDR"
        self.description = "The supplied BD_ADDR (%s) is not valid. Use format 00:11:22:33:44:55" % address


class InvalidAddressTypeByName(Exception):

    def __init__(self, address_type):
        self.code = 0x02
        self.name = "Invalid address type name"
        self.description = "The supplied address type name (%s) is not valid. Options: ['public', 'random']" % address_type


class InvalidATTHandle(Exception):

    def __init__(self, handle):
        self.code = 0x03
        self.name = "Invalid ATT handle"
        self.description = "The supplied attribute handle (%s) is not valid. The integer value must be >= 1 and <= 0xffff" % handle


class InvalidATTSecurityMode(Exception):

    def __init__(self, mode, level):
        self.code = 0x04
        self.name = "Invalid ATT security mode"
        self.description = "The supplied attribute security mode (%s, %s) is not valid. Options: (Security Mode, Security Level)" \
                           "[(0,0) -- No Access, (1,1) -- Open, (1,2) -- Requires encryption and does not require" \
                           " authenticated pairing," \
                           "(1,3) -- Requires encryption and requires authenticated pairing, (1,4) -- Requires encryption" \
                           " with Secure Connections pairing, (2,1) -- Data signing and does not require authenticated" \
                           " pairing, (2,2) -- Data signing and requires authenticated pairing]" % (mode, level)


class InvalidATTProperty(Exception):

    def __init__(self, att_property):
        self.code = 0x05
        self.name = "Invalid ATT property"
        self.description = "The supplied attribute property (%s) is not valid. Options: ['read', 'write']" % att_property


class InvalidGATTProperty(Exception):

    def __init__(self, gatt_property):
        self.code = 0x06
        self.name = "Invalid GATT property"
        self.description = "The supplied GATT property (%s) is not valid. Options: ['broadcast', 'read', 'write', " \
                           "'notify', 'indicate', 'authenticated signed writes', 'extended properties']" % gatt_property


class InvalidSMLTK(Exception):

    def __init__(self, ltk):
        self.code = 0x07
        self.name = "Invalid SM LTK"
        self.description = "The supplied SM LTK (%s) is not valid. Expects hex string (ie 'AB7F2A...')" % ltk


class InvalidSMRandom(Exception):

    def __init__(self, rand):
        self.code = 0x08
        self.name = "Invalid SM Random"
        self.description = "The supplied SM Random (%s) is not valid. Expects hex string (ie 'AB7F2A...')" % rand


class InvalidSMIRK(Exception):

    def __init__(self, ltk):
        self.code = 0x09
        self.name = "Invalid SM IRK"
        self.description = "The supplied SM IRK (%s) is not valid. Expects hex string (ie 'AB7F2A...')" % ltk


class InvalidSMCSRK(Exception):

    def __init__(self, ltk):
        self.code = 0x0a
        self.name = "Invalid SM LTK"
        self.description = "The supplied SM CSRK (%s) is not valid. Expects hex string (ie 'AB7F2A...')" % ltk


def validate_bluetooth_address_cli(address):
    """
    Validates BT address string

    :param address: BT Address
    :type: str
    :return: address
    """
    if address is not None:
        match = re.search("^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$"
                          , address)
        if match is not None and match.group(0) is not None:
            return address

    raise argparse.ArgumentTypeError("%s is an invalid Bluetooth address (BD_ADDR)" % address)


def validate_bluetooth_address(address):
    """
    Validates BT address string

    :param address: BT Address
    :type: str
    :return: address
    """
    if address is not None:
        match = re.search("^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$"
                          , address)
        if match is not None and match.group(0) is not None:
            return address

    raise InvalidBDADDRException(address)


def validate_attribute_uuid(uuid):
    from whad.ble.profile.attribute import UUID
    if uuid is None:
        raise InvalidUUIDException(uuid)
    # When attribute UUID is read from JSON, it can be encoded as unicode, which will break the UUID class
    try:
        UUID(uuid)
    except InvalidUUIDException:
        raise InvalidUUIDException(uuid)
    return uuid


def validate_address_type_name(address_type_name):
    if address_type_name is None:
        return InvalidAddressTypeByName(address_type_name)
    address_type_name = address_type_name.lower()
    if address_type_name == "public" or address_type_name == "random":
        return address_type_name

    raise InvalidAddressTypeByName(address_type_name)


def validate_int_att_handle(int_handle):
    if int_handle is None or int_handle < 0x01 or int_handle > 0xffff:
        raise InvalidATTHandle
    return int_handle


def validate_att_security_mode(mode, level):
    supported_modes = [
        (0, 0), (1, 1), (1, 2), (1, 3), (1, 4), (2, 1), (2, 2)
    ]

    if (mode, level) not in supported_modes:
        raise InvalidATTSecurityMode(mode, level)
    return mode, level


def validate_att_property(att_property):
    att_property = att_property.lower()

    if att_property != "read" and att_property != "write":
        raise InvalidATTProperty(att_property)
    return att_property


def validate_gatt_property(gatt_property):
    gatt_property = gatt_property.lower()
    valid_properties = ['broadcast', 'read', 'write', 'notify', 'indicate',
                        'authenticated signed writes', 'extended properties',
                        'write without response']
    if gatt_property not in valid_properties:
        raise InvalidGATTProperty(gatt_property)
    return gatt_property


def validate_ltk(ltk):
    ltk = ltk.lower()
    try:
        unhexlify(ltk)
    except TypeError:
        raise InvalidSMLTK(ltk)
    return ltk


def validate_irk(irk):
    if irk is None:
        irk = "00" * 16
    irk = irk.lower()
    try:
        unhexlify(irk)
    except TypeError:
        raise InvalidSMIRK(irk)
    return irk


def validate_csrk(csrk):
    if csrk is None:
        csrk = "00" * 16
    csrk = csrk.lower()
    try:
        unhexlify(csrk)
    except TypeError:
        raise InvalidSMCSRK(csrk)
    return csrk


def validate_rand(rand):
    rand = rand.lower()
    try:
        unhexlify(rand)
    except TypeError:
        raise InvalidSMRandom(rand)
    return rand


