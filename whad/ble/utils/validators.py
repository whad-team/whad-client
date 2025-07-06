"""Bluetooth Low Energy validators (mostly crypto-related)
"""
import re
import argparse

from whad.ble.profile.attribute import UUID, InvalidUUIDException as AttrInvalidUUIDException


class InvalidUUIDException(Exception):
    """Base class for Invalid HandleException -- The attribute handle given was
    not valid on this server."""

    def __init__(self, uuid):
        self.code = 0x01
        self.name = "Invalid UUID"
        self.description = (
            f"The supplied UUID ({uuid}) is not a valid 16-bit or 128-bit UUID. "
            "(ex: 2a1b or 000AA000-0BB0-10C0-80A0-00805F9B34FB"
        )
        

# Validators for various BLESuite input parameters supplied by the user. The use
# of these validators is mostly limited to import/export and CLI features.


class InvalidBDADDRException(Exception):
    """Invalid Bluetooth Device address.
    """

    def __init__(self, address):
        self.code = 0x02
        self.name = "Invalid BD_ADDR"
        self.description = (
            f"The supplied BD_ADDR ({address}) is not valid. Use format 00:11:22:33:44:55"
        )


class InvalidAddressTypeByName(Exception):
    """Invalid Bluetooth address type.

    Bluetooth device address is defined by the combination of TxAdd/RxAdd,
    and must match one of these two types: random or public.
    """

    def __init__(self, address_type):
        self.code = 0x02
        self.name = "Invalid address type name"
        self.description = (
            f"The supplied address type name ({address_type}) is not valid. "
            f"Options: ['public', 'random']"
        )


class InvalidATTHandle(Exception):
    """Invalid ATT protocol handle.
    """

    def __init__(self, handle):
        self.code = 0x03
        self.name = "Invalid ATT handle"
        self.description = (
            f"The supplied attribute handle ({handle}) is not valid. "
            f"The integer value must be >= 1 and <= 0xffff"
        )


class InvalidATTSecurityMode(Exception):
    """Invalid security mode.
    """

    def __init__(self, mode, level):
        self.code = 0x04
        self.name = "Invalid ATT security mode"
        self.description = (
            f"The supplied attribute security mode ({mode}, {level}) is not valid. "
            "Options: (Security Mode, Security Level) [(0,0) -- No Access, (1,1) -- "
            "Open, (1,2) -- Requires encryption and does not require authenticated pairing,"
            " (1,3) -- Requires encryption and requires authenticated pairing, (1,4)"
            " -- Requires encryption with Secure Connections pairing, (2,1)"
            " -- Data signing and does not require authenticated pairing, (2,2)"
            " -- Data signing and requires authenticated pairing]"
        )


class InvalidATTProperty(Exception):
    """Invalid attribute property.
    """

    def __init__(self, att_property):
        self.code = 0x05
        self.name = "Invalid ATT property"
        self.description = (
            f"The supplied attribute property ({att_property}) is not valid. "
            "Options: ['read', 'write']"
        )


class InvalidGATTProperty(Exception):
    """Invalid GATT property.
    """

    def __init__(self, gatt_property):
        self.code = 0x06
        self.name = "Invalid GATT property"
        self.description = (
            f"The supplied GATT property ({gatt_property}) is not valid. "
            "Options: ['broadcast', 'read', 'write', 'notify', 'indicate', "
            "'authenticated signed writes', 'extended properties']"
        )


class InvalidSMLTK(Exception):
    """Invalid Long-term key (LTK).
    """

    def __init__(self, ltk):
        self.code = 0x07
        self.name = "Invalid SM LTK"
        self.description = (
            f"The supplied SM LTK ({ltk}) is not valid. Expects hex string (ie 'AB7F2A...')"
        )


class InvalidSMRandom(Exception):
    """Invalid Random.
    """

    def __init__(self, rand):
        self.code = 0x08
        self.name = "Invalid SM Random"
        self.description = (
            f"The supplied SM Random ({rand}) is not valid. Expects hex string (ie 'AB7F2A...')"
        )


class InvalidSMIRK(Exception):
    """Invalid IRK.
    """

    def __init__(self, irk):
        self.code = 0x09
        self.name = "Invalid SM IRK"
        self.description = (
            f"The supplied SM IRK ({irk}) is not valid. Expects hex string (ie 'AB7F2A...')"
        )


class InvalidSMCSRK(Exception):
    """Invalid CSRK.
    """

    def __init__(self, csrk):
        self.code = 0x0a
        self.name = "Invalid SM CSRK"
        self.description = (
            f"The supplied SM CSRK ({csrk}) is not valid. Expects hex string (ie 'AB7F2A...')"
        )


def validate_bluetooth_address_cli(address):
    """
    Validates BT address string

    :param address: BT Address
    :type: str
    :return: address
    :raises: ArgumentTypeError
    """
    if address is not None:
        match = re.search(("^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
                           ":[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$"), address)
        if match is not None and match.group(0) is not None:
            return address

    raise argparse.ArgumentTypeError(f"{address} is an invalid Bluetooth address (BD_ADDR)")


def validate_bluetooth_address(address):
    """
    Validates BT address string

    :param address: BT Address
    :type: str
    :return: address
    :raises: InvalidBDADDRException
    """
    if address is not None:
        match = re.search(("^[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}"
                           ":[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}:[0-9A-Fa-f]{2}$"),
                          address)
        if match is not None and match.group(0) is not None:
            return address

    raise InvalidBDADDRException(address)


def validate_attribute_uuid(uuid):
    """Validate attribute UUID.

    :param uuid: Attribute UUID
    :type uuid: UUID
    :return: Validated UUID
    :raises: InvalidUUIDException
    """
    if uuid is None:
        raise InvalidUUIDException(uuid)
    # When attribute UUID is read from JSON, it can be encoded as unicode,
    # which will break the UUID class
    try:
        UUID(uuid)
    except AttrInvalidUUIDException as uuid_err:
        raise InvalidUUIDException(uuid) from uuid_err
    except TypeError as type_err:
        raise InvalidUUIDException(uuid) from type_err
    return uuid


def validate_address_type_name(address_type_name: str) -> str:
    """Validate address_type_name (must be 'random' or 'public').

    :param address_type_name: Address type name
    :type address_type_name: str
    :return: Validated address type name
    :rtype: str
    :raises: InvalidAddressTypeByName
    """
    if address_type_name is None:
        return InvalidAddressTypeByName(address_type_name)
    address_type_name = address_type_name.lower()
    if address_type_name in ("public", "random"):
        return address_type_name

    raise InvalidAddressTypeByName(address_type_name)


def validate_int_att_handle(handle: int) -> int:
    """Validate ATT handle value.

    :param handle: Attribute handle to validate
    :type handle: int
    :return: Validated attribute handle
    :rtype: int
    :raises: InvalidATTHandle
    """
    if handle is None or handle < 0x01 or handle > 0xffff:
        raise InvalidATTHandle
    return handle


def validate_att_security_mode(mode: int, level: int) -> tuple[int, int]:
    """Validate ATT security mode.

    :param mode: Security mode to validate
    :type mode: int
    :param level: Security level to validate
    :type level: int
    :return: Validated security mode and level
    :rtype: tuple
    :raises: InvalidATTSecurityMode
    """
    supported_modes = [
        (0, 0), (1, 1), (1, 2), (1, 3), (1, 4), (2, 1), (2, 2)
    ]

    if (mode, level) not in supported_modes:
        raise InvalidATTSecurityMode(mode, level)
    return mode, level


def validate_att_property(prop: str) -> str:
    """Validate ATT property.

    :param prop: Attribute property to validate
    :type prop: str
    :return: Validated property
    :rtype: str
    :raises: InvalidATTProperty
    """
    if prop.lower() not in ("read", "write"):
        raise InvalidATTProperty(prop)
    return prop


def validate_gatt_property(prop: str) -> str:
    """Validate GATT attribute property.

    :param prop: GATT property
    :type prop: str
    :return: Validated GATT property
    :rtype: str
    :raises: InvalidGATTProperty
    """
    prop = prop.lower()
    valid_properties = ['broadcast', 'read', 'write', 'notify', 'indicate',
                        'authenticated signed writes', 'extended properties',
                        'write without response']
    if prop not in valid_properties:
        raise InvalidGATTProperty(prop)
    return prop


def validate_ltk(ltk: str) -> str:
    """Validate LTK

    :param ltk: Long-term key in hex
    :type ltk: str
    :return: Validated LTK
    :rtype: str
    :raises: InvalidSMLTK
    """
    ltk = ltk.lower()
    try:
        bytes.fromhex(ltk)
    except ValueError as err_type:
        raise InvalidSMLTK(ltk) from err_type
    return ltk


def validate_irk(irk: str) -> str:
    """Validate IRK

    :param irk: IRK to validate (in hex)
    :type irk: str
    :return: Validated IRK
    :rtype: str
    :raises: InvalidSMIRK
    """
    if irk is None:
        irk = "00" * 16
    irk = irk.lower()
    try:
        bytes.fromhex(irk)
    except ValueError as err_type:
        raise InvalidSMIRK(irk) from err_type
    return irk


def validate_csrk(csrk: str) -> str:
    """Validate CSRK

    :param csrk: CSRK to validate (in hex)
    :type csrk: str
    :return: Validated CSRK
    :rtype: str
    :raises: InvalidSMCSRK
    """
    if csrk is None:
        csrk = "00" * 16
    csrk = csrk.lower()
    try:
        bytes.fromhex(csrk)
    except ValueError as err_type:
        raise InvalidSMCSRK(csrk) from err_type
    return csrk


def validate_rand(rand):
    """Validate Rand value

    :param ramd: Rand value to validate (in hex)
    :type rand: str
    :return: Validated Rand
    :rtype: str
    :raises: InvalidSMRandom
    """
    rand = rand.lower()
    try:
        bytes.fromhex(rand)
    except ValueError as err_type:
        raise InvalidSMRandom(rand) from err_type
    return rand
