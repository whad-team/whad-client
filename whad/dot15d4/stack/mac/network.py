from whad.dot15d4.stack.mac.constants import MACAddressMode, MACNetworkType

class Dot15d4PANNetwork:
    """
    Represents a 802.15.4 PAN network.
    """
    def __init__(self, beacon, channel_page, channel):
        try:
            self.coord_addr_mode = MACAddressMode(beacon.fcf_srcaddrmode)
        except:
            self.coord_addr_mode = None
        self.coord_pan_id = beacon.src_panid
        self.coord_addr = beacon.src_addr
        self.channel = channel
        self.channel_page = channel_page
        self.link_quality = beacon.metadata.lqi if hasattr(beacon, "metadata") and hasattr(beacon.metadata, "lqi") else 255
        self.beacon_order = beacon.sf_beaconorder
        self.superframe_order = beacon.sf_sforder
        self.final_capslot = beacon.sf_finalcapslot
        self.batt_life_extend = beacon.sf_battlifeextend
        self.pan_coord = beacon.sf_pancoord
        self.assoc_permit = beacon.sf_assocpermit
        self.gts_permit = beacon.gts_spec_permit
        self.network_type = MACNetworkType.BEACON_ENABLED if self.beacon_order < 15 else MACNetworkType.NON_BEACON_ENABLED

    def __eq__(self, other):
        return self.coord_addr == other.coord_addr and self.coord_pan_id == other.coord_pan_id

    def __repr__(self):
        return (
                "Dot15d4PANNetwork("+
                "pan_id=" + hex(self.coord_pan_id)+", "
                "pan_coord=" + hex(self.coord_addr)+ ", "
                "channel_page=" + str(self.channel_page)+", "
                "channel=" + str(self.channel)+", "
                "link_quality=" + str(self.link_quality)+", "
                "network_type=" + (
                                    "beacon_enabled ({})".format(self.beacon_order) if
                                    self.network_type == MACNetworkType.BEACON_ENABLED else
                                    "non_beacon_enabled"
                )+", "
                "association=" + ("permitted" if self.assoc_permit else "forbidden") +
            ")"
        )
