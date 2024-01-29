
class ZigbeeNetwork:
    def __init__(self, beacon):
        self.dot15d4_pan_network = beacon.pan_descriptor
        self.extended_pan_id = beacon.extended_pan_id
        self.channel = self.dot15d4_pan_network.channel
        self.stack_profile = beacon.stack_profile
        self.zigbee_version = beacon.nwkc_protocol_version
        self.beacon_order = self.dot15d4_pan_network.beacon_order
        self.superframe_order = self.dot15d4_pan_network.superframe_order
        self.joining_permit = self.dot15d4_pan_network.assoc_permit
        self.router_capacity = bool(beacon.router_capacity)
        self.end_device_capacity = bool(beacon.end_device_capacity)

    def __eq__(self, other):
        return self.extended_pan_id == other.extended_pan_id

    def __repr__(self):
        return ("ZigbeeNetwork("+
                "pan_id=" + hex(self.dot15d4_pan_network.coord_pan_id)+", "
                "extended_pan_id=" + hex(self.extended_pan_id)+", "
                "pan_coord=" + (hex(self.dot15d4_pan_network.coord_addr) if isinstance(self.dot15d4_pan_network.coord_addr,int) else self.dot15d4_pan_network.coord_addr) + ", "
                "channel=" + str(self.channel)+", "
                "joining=" + ("permitted" if self.joining_permit else "forbidden") +", " +
                "router_capacity=" + ("yes" if self.router_capacity else "no") +", " +
                "end_device_capacity=" + ("yes" if self.end_device_capacity else "no") +
            ")"
        )
