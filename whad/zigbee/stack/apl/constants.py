from enum import IntEnum
"""
Constants implemented as Enum for Zigbee APL layer.
"""

class LogicalDeviceType(IntEnum):
    """
    Represents the logical device type of a node.
    """
    COORDINATOR = 0
    ROUTER = 1
    END_DEVICE = 2
