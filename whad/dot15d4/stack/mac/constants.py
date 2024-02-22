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

class MACAssociationStatus(IntEnum):
    """
    Enum representing the different association status supported by 802.15.4.
    """
    ASSOCIATION_SUCCESSFUL = 0
    PAN_AT_CAPACITY = 1
    PAN_ACCESS_DENIED = 2
    HOPPING_SEQUENCE_OFFSET_DUPLICATION = 3
    FAST_ASSOCIATION_SUCCESSFUL = 0x80

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

PANID_COMPRESSION_TABLE = {
    # (Dest. Addr, Src Addr, Dest. PAN ID, Src PAN ID) : pan_id_compress bit
    (MACAddressMode.NONE, MACAddressMode.NONE, False, False) : 0,

    (MACAddressMode.NONE, MACAddressMode.NONE, True, False) : 1,

    (MACAddressMode.SHORT, MACAddressMode.NONE, True, False) : 0,
    (MACAddressMode.EXTENDED, MACAddressMode.NONE, True, False) : 0,

    (MACAddressMode.SHORT, MACAddressMode.NONE, False, False) : 1,
    (MACAddressMode.EXTENDED, MACAddressMode.NONE, False, False) : 1,

    (MACAddressMode.NONE, MACAddressMode.SHORT, False, True) : 0,
    (MACAddressMode.NONE, MACAddressMode.EXTENDED, False, True) : 0,

    (MACAddressMode.NONE, MACAddressMode.SHORT, False, False) : 1,
    (MACAddressMode.NONE, MACAddressMode.EXTENDED, False, False) : 1,

    (MACAddressMode.EXTENDED, MACAddressMode.EXTENDED, True, False) : 0,

    (MACAddressMode.EXTENDED, MACAddressMode.EXTENDED, False, False) : 1,

    (MACAddressMode.SHORT, MACAddressMode.SHORT, True, True) : 0,
    (MACAddressMode.SHORT, MACAddressMode.EXTENDED, True, True) : 0,
    (MACAddressMode.EXTENDED, MACAddressMode.SHORT, True, True) : 0,

    (MACAddressMode.SHORT, MACAddressMode.EXTENDED, True, False) : 1,
    (MACAddressMode.EXTENDED, MACAddressMode.SHORT, True, False) : 1,
    (MACAddressMode.SHORT, MACAddressMode.SHORT, True, False) : 1,

}
