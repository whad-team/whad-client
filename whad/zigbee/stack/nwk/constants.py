from enum import IntEnum
"""
Constants implemented as Enum for Zigbee NWK layer.
"""

class ZigbeeDeviceType(IntEnum):
    """
    Enum representing the different device types in a Zigbee network.
    """
    COORDINATOR = 0
    ROUTER = 1
    END_DEVICE = 2

class ZigbeeRelationship(IntEnum):
    """
    Enum representing the different relationship between ZigBee devices.
    """
    IS_PARENT = 0
    IS_CHILD = 1
    IS_SIBLING = 2
    NONE = 3
    PREVIOUS_CHILD = 4
    UNAUTHENTICATED_CHILD = 5


class NWKJoinMode(IntEnum):
    """
    Enum representing the different NWK join modes supported by 802.15.4.
    """
    NEW_JOIN = 0
    REJOIN = 1
    CHANGE_CHANNEL = 2

class NWKAddressMode(IntEnum):
    """
    Enum representing the different NWK address modes supported by 802.15.4.
    """
    MULTICAST = 1
    UNICAST = BROADCAST = 2

BROADCAST_ADDRESSES = {
    0xFFFF : "All devices in PAN",
    0xFFFD : "macRxOnWhenIdle=True",
    0xFFFC : "All routers and coordinators",
    0xFFFB : "Low power routers only"
}
