from enum import IntEnum
from whad.zigbee.stack.nwk.exceptions import NWKInvalidKey
from time import time

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

class ZigbeeNode:
    """
    Class representing a Zigbee device.
    """
    def __init__(self, address, device_type, extended_address=None,rx_on_when_idle=False, end_device_configuration=0, timeout_counter=None, device_timeout=None, transmit_failure=0, lqi=None, outgoing_cost=0, age=0,  keepalive_received=False, extended_pan_id=None, logical_channel=None, depth=None, beacon_order=None, permit_joining=None, potential_parent=None, update_id=None, pan_id=None):
        self.address = address
        self.device_type = device_type
        self.extended_address = extended_address
        self.rx_on_when_idle = rx_on_when_idle
        self.end_device_configuration = end_device_configuration
        self.timeout_counter = timeout_counter
        self.device_timeout = device_timeout
        self.transmit_failure = transmit_failure
        self.lqi = lqi
        self.outgoing_cost = outgoing_cost
        self.age = age
        self.update_id=update_id
        self.keepalive_received = keepalive_received
        self.extended_pan_id = extended_pan_id
        self.logical_channel = logical_channel
        self.depth = depth
        self.beacon_order = beacon_order
        self.permit_joining = permit_joining
        self.potential_parent = potential_parent
        self.pan_id = pan_id
        self.lqis = [lqi] if lqi is not None else []
        self.last_update = time()

    def link_cost(self):
        pl = sum(self.lqis) / len(self.lqis)
        result = min(7,round(1/(pl ** 4)))
        self.__dict__["outgoing_cost"] = result
        return link_cost

    def __setattr__(self, name, value):
        if hasattr(self, "last_update"):
            if name == "lqi":
                self.__dict__["lqis"].append(value)
                if len(self.__dict__["lqis"]) > 20:
                    self.__dict__["lqis"] = self.__dict__["lqis"][1:]
                    self.link_cost()
            self.__dict__["last_update"] = time()

        self.__dict__[name] = value

    def __repr__(self):
        if self.device_type == ZigbeeDeviceType.END_DEVICE:
            role = "ZigbeeEndDevice"
        elif self.device_type == ZigbeeDeviceType.COORDINATOR:
            role = "ZigbeeCoordinator"
        elif self.device_type == ZigbeeDeviceType.ROUTER:
            role = "ZigbeeRouter"

        return "{}(address={:04x}, extended_pan_id={:04x} - last update {} seconds ago)".format(role, self.address, self.extended_pan_id, round(time() - self.last_update, 2))

class ZigbeeEndDevice(ZigbeeNode):
    def __init__(self, address, extended_address=None, rx_on_when_idle=False, end_device_configuration=0, timeout_counter=None, device_timeout=None, transmit_failure=0, lqi=0, outgoing_cost=0, age=0,  keepalive_received=False, extended_pan_id=None, logical_channel=None, depth=None, beacon_order=None, permit_joining=None, potential_parent=None, update_id=None, pan_id=None):
        super().__init__(address, device_type=ZigbeeDeviceType.END_DEVICE,extended_address=extended_address, rx_on_when_idle=rx_on_when_idle, end_device_configuration=end_device_configuration, timeout_counter=timeout_counter, device_timeout=device_timeout, transmit_failure=transmit_failure, lqi=lqi, outgoing_cost=outgoing_cost, age=age,  keepalive_received=keepalive_received, extended_pan_id=extended_pan_id, logical_channel=logical_channel, depth=depth, beacon_order=beacon_order, permit_joining=permit_joining, potential_parent=potential_parent, update_id=update_id, pan_id=pan_id)

class ZigbeeCoordinator(ZigbeeNode):
    def __init__(self, address, extended_address=None, rx_on_when_idle=False, end_device_configuration=0, timeout_counter=None, device_timeout=None, transmit_failure=0, lqi=0, outgoing_cost=0, age=0,  keepalive_received=False, extended_pan_id=None, logical_channel=None, depth=None, beacon_order=None, permit_joining=None, potential_parent=None, update_id=None, pan_id=None):
        super().__init__(address, device_type=ZigbeeDeviceType.COORDINATOR, extended_address=extended_address,rx_on_when_idle=rx_on_when_idle, end_device_configuration=end_device_configuration, timeout_counter=timeout_counter, device_timeout=device_timeout, transmit_failure=transmit_failure, lqi=lqi, outgoing_cost=outgoing_cost, age=age,  keepalive_received=keepalive_received, extended_pan_id=extended_pan_id, logical_channel=logical_channel, depth=depth, beacon_order=beacon_order, permit_joining=permit_joining, potential_parent=potential_parent, update_id=update_id, pan_id=pan_id)

class ZigbeeRouter(ZigbeeNode):
    def __init__(self, address, extended_address=None, rx_on_when_idle=False, end_device_configuration=0, timeout_counter=None, device_timeout=None, transmit_failure=0, lqi=0, outgoing_cost=0, age=0,  keepalive_received=False, extended_pan_id=None, logical_channel=None, depth=None, beacon_order=None, permit_joining=None, potential_parent=None, update_id=None, pan_id=None):
        super().__init__(address, device_type=ZigbeeDeviceType.ROUTER, extended_address=extended_address,rx_on_when_idle=rx_on_when_idle, end_device_configuration=end_device_configuration, timeout_counter=timeout_counter, device_timeout=device_timeout, transmit_failure=transmit_failure, lqi=lqi, outgoing_cost=outgoing_cost, age=age,  keepalive_received=keepalive_received, extended_pan_id=extended_pan_id, logical_channel=logical_channel, depth=depth, beacon_order=beacon_order, permit_joining=permit_joining, potential_parent=potential_parent, update_id=update_id, pan_id=pan_id)

class NWKNeighborTable:
    """
    Structure representing a NWK neighbor table, to store the characteristics of surrounding devices.
    """
    def __init__(self):
        self.table = {}

    def update(self, address, **kwargs):
        if address in self.table:
            device = self.table[address]
            for name, value in kwargs.items():
                if hasattr(device, name):
                    setattr(device, name, value)
            return True
        else:
            if "device_type" not in kwargs:
                return False
            if kwargs["device_type"] == ZigbeeDeviceType.END_DEVICE:
                del kwargs["device_type"]
                self.table[address] = ZigbeeEndDevice(address, **kwargs)
            elif kwargs["device_type"] == ZigbeeDeviceType.COORDINATOR:
                del kwargs["device_type"]
                self.table[address] = ZigbeeCoordinator(address, **kwargs)
            elif kwargs["device_type"] == ZigbeeDeviceType.ROUTER:
                del kwargs["device_type"]
                self.table[address] = ZigbeeRouter(address, **kwargs)
            else:
                return False
            return True

    def select_suitable_parent(self, extended_pan_id, nwk_update_id):
        selected_devices = []
        for address, device in self.table.items():
            if (
                device.extended_pan_id == extended_pan_id and #the device belongs to the right network
                device.permit_joining and  # the device allows joining
                device.outgoing_cost <= 3 and # the total cost is under 3
                device.potential_parent and # it is a potential parent
                device.update_id >= nwk_update_id
            ):
                selected_devices.append(device)
        return selected_devices

    def delete(self, address):
        del self.table[address]

    def show(self):
        for _, device in self.table.items():
            print(device)

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
