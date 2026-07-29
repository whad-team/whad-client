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

class APSFragmentationBlockType(IntEnum):
    """
    Enum storing the different possible values for the APS extended header
    fragmentation field.
    """
    NONE = 0
    FIRST_BLOCK = 1
    MIDDLE_BLOCK = 2

# Conservative default max size (in bytes) of an ASDU chunk carried per
# fragment, keeping on-air frames within the 802.15.4 127-byte PHY budget
# even with NWK security overhead.
APS_MAX_FRAME_SIZE = 80

# Zigbee spec's apscMaxFrameRetries constant (section 2.2.4.3): number of
# times an APSDE-DATA request with acknowledged_transmission=True is
# resent after not receiving a matching APS ack within apsAckWaitDuration.
APS_MAX_FRAME_RETRIES = 3
