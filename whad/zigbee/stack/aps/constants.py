from enum import IntEnum
"""
Constants implemented as Enum for Zigbee APS layer.
"""

class APSSourceAddressMode(IntEnum):
    """
    Enum representing the different APS source address modes supported by Zigbee.
    """
    SHORT_ADDRESS_SRC_ENDPOINT_PRESENT = 0x02
    EXTENDED_ADDRESS_SRC_ENDPOINT_PRESENT = 0x03
    EXTENDED_ADDRESS_SRC_ENDPOINT_NOT_PRESENT = 0x04


class APSDestinationAddressMode(IntEnum):
    """
    Enum representing the different APS destination address modes supported by Zigbee.
    """
    DST_ADDRESS_AND_DST_ENDPOINT_NOT_PRESENT = 0x00
    SHORT_GROUP_ADDRESS_DST_ENDPOINT_NOT_PRESENT = 0x01
    SHORT_ADDRESS_DST_ENDPOINT_PRESENT = 0x02
    EXTENDED_ADDRESS_DST_ENDPOINT_PRESENT = 0x03
    EXTENDED_ADDRESS_DST_ENDPOINT_NOT_PRESENT = 0x04


class APSKeyAttribute(IntEnum):
    """
    Enum storing the different possible values for the APS key attribute.
    """
    PROVISIONAL_KEY = 0
    UNVERIFIED_KEY = 1
    VERIFIED_KEY = 2

class APSKeyType(IntEnum):
    """
    Enum storing the different possible values for the APS key type attribute.
    """
    STANDARD_NETWORK_KEY = 1
    APPLICATION_LINK_KEY = 3
    TRUST_CENTER_LINK_KEY = 4

class APSSecurityStatus(IntEnum):
    """
    Enum storing the different possible values for the APS security status.
    """
    UNSECURED = 0
    SECURED_NWK_KEY = 1
    SECURED_LINK_KEY = 2
