from enum import IntEnum

class MACAddressMode(IntEnum):
    """
    Enum representing the different MAC address modes supported by 802.15.4.
    """
    NONE = 0
    SHORT = 1
    EXTENDED = 2

class MACDeviceType(IntEnum):
    """
    Enum representing the different MAC device types supported by 802.15.4.
    """
    RFD = 0
    FFD = 1

class MACPowerSource(IntEnum):
    """
    Enum representing the different MAC power source supported by 802.15.4.
    """
    BATTERY_SOURCE = 0
    ALTERNATING_CURRENT_SOURCE = 1

class MACScanType(IntEnum):
    """
    Enum representing MAC scan types supported by 802.15.4.
    """
    ENERGY_DETECTION = 0
    ACTIVE = 1
    PASSIVE = 2
    ORPHAN = 3
    ENHANCED_ACTIVE_SCAN = 4
    RIT_PASSIVE = 5

class MACNetworkType(IntEnum):
    """
    Enum representing the different network type supported by 802.15.4.
    """
    BEACON_ENABLED = 0
    NON_BEACON_ENABLED = 1


class MACBeaconType(IntEnum):
    """
    Enum representing the different beacon type supported by 802.15.4.
    """
    BEACON = 0
    ENHANCED_BEACON = 1


class MACConstants:
    """
    Constants used by 802.15.4 MAC layer.
    """
    A_BASE_SLOT_DURATION = 60
    A_NUM_SUPERFRAME_SLOTS = 16
    A_GTS_DESC_PERSISTENCE_TIME = 4
    A_MAX_LOST_BEACONS = 4
    A_MAX_SIFTS_FRAME_SIZE = 18
    A_MIN_CAP_LENGTH = 440
    A_BASE_SUPERFRAME_DURATION = 960
    A_UNIT_BACKOFF_PERIOD = None
    A_RCCN_BASE_SLOT_DURATION = 60
