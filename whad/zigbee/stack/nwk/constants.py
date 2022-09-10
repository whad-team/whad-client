from enum import IntEnum
from whad.zigbee.stack.nwk.exceptions import NWKInvalidKey

class NetworkSecurityMaterial:
    KEY_COUNTER = 0
    def __init__(self, key, key_sequence_number=None, outgoing_frame_counter=0):
        if isinstance(key,str):
            try:
                self.key = bytes.fromhex(key.replace(":",""))
            except ValueError:
                raise NWKInvalidKey()
        elif isinstance(key,bytes):
            self.key = key

        if len(self.key) != 16:
            raise NWKInvalidKey()

        if key_sequence_number is not None:
            self.key_sequence_number = key_sequence_number
        else:
            self.key_sequence_number = NetworkSecurityMaterial.KEY_COUNTER
            NetworkSecurityMaterial.KEY_COUNTER+=1

        self.outgoing_frame_counter = outgoing_frame_counter
        self.incoming_frame_counters = {}

    def add_incoming_frame_counter(self, device_address, frame_counter):
        self.incoming_frame_counters[device_address] = frame_counter

    def __repr__(self):
        printable_key = ":".join(["{:02X}".format(i) for i in self.key])
        return "NetworkSecurityMaterial(Key #{}, '{}')".format(self.key_sequence_number, printable_key)

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
