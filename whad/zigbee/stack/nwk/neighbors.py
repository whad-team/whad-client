from whad.zigbee.stack.nwk.nodes import ZigbeeEndDevice, ZigbeeCoordinator, ZigbeeRouter
from whad.zigbee.stack.nwk.constants import ZigbeeDeviceType, ZigbeeRelationship

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

    def select_by_extended_address(self, extended_address):
        for address, node in self.table.items():
            if node.extended_address == extended_address:
                return node
        return None

    def select_routers_by_pan_id(self, pan_id):
        routers = []
        for address, device in self.table.items():
            if device.device_type == ZigbeeDeviceType.ROUTER and device.pan_id == pan_id:
                routers.append(device)
        return routers

    def select_end_devices_by_pan_id(self, pan_id):
        end_devices = []
        for address, device in self.table.items():
            if device.device_type == ZigbeeDeviceType.END_DEVICE and device.pan_id == pan_id:
                end_devices.append(device)
        return end_devices

    def select_suitable_parent(self, extended_pan_id, nwk_update_id, no_permit_check=False):
        selected_devices = []
        for address, device in self.table.items():
            if (
                device.extended_pan_id == extended_pan_id and #the device belongs to the right network
                (device.permit_joining or no_permit_check) and  # the device allows joining
                device.outgoing_cost <= 3 and # the total cost is under 3
                device.potential_parent and # it is a potential parent
                device.update_id >= nwk_update_id
            ):
                selected_devices.append(device)
        return selected_devices

    def get_parent(self):
        for device in self.table.values():
            if device.relationship == ZigbeeRelationship.IS_PARENT:
                return device
        return None

    def delete(self, address):
        del self.table[address]

    def show(self):
        for _, device in self.table.items():
            print(device)
