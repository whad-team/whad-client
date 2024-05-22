from enum import IntEnum


class ZCLClusterType(IntEnum):
    """
    Type of Zigbee Cluster Library cluster.
    """
    CLIENT = 0
    SERVER = 1
