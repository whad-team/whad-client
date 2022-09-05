from enum import IntEnum

class MACAddressMode(IntEnum):
    """
    Enum representing the different MAC address modes supported by 802.15.4.
    """
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

class EDMeasurement:
    """
    Maximum measurement of an energy detection scan.
    """
    def __init__(self, samples, channel_page, channel):
        self.max_sample = max(samples)
        self.channel_number = channel
        self.channel_page = channel_page

    def __repr__(self):
        return ("EDMeasurement("+
                "max_sample=" + str(self.max_sample) +", "
                "channel_page=" + str(self.channel_page)+", "
                "channel_number=" + str(self.channel_number) +
            ")"
        )

class Dot15d4PANNetwork:
    """
    Represents a 802.15.4 PAN network.
    """
    def __init__(self, beacon, channel_page, channel):
        self.coord_addr_mode = MACAddressMode(beacon.fcf_srcaddrmode)
        self.coord_pan_id = beacon.src_panid
        self.coord_addr = beacon.src_addr
        self.channel = channel
        self.channel_page = channel_page
        self.beacon_order = beacon.sf_beaconorder
        self.superframe_order = beacon.sf_sforder
        self.final_capslot = beacon.sf_finalcapslot
        self.batt_life_extend = beacon.sf_battlifeextend
        self.pan_coord = beacon.sf_pancoord
        self.assoc_permit = beacon.sf_assocpermit
        self.gts_permit = beacon.gts_spec_permit

    def __eq__(self, other):
        return self.coord_addr == other.coord_addr and self.coord_pan_id == other.coord_pan_id

    def __repr__(self):
        return ("Dot15d4PANNetwork("+
                "pan_id=" + hex(self.coord_pan_id)+", "
                "pan_coord=" + (hex(self.coord_addr) if isinstance(self.coord_addr,int) else self.coord_addr) + ", "
                "channel_page=" + str(self.channel_page)+", "
                "channel=" + str(self.channel)+", "
                "association=" + ("permitted" if self.assoc_permit else "forbidden") +
            ")"
        )

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
