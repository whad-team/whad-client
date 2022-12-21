from whad.zigbee.stack.nwk.constants import ZigbeeDeviceType
from whad.zigbee.profile.endpoint import Endpoint
class Device:
    def __init__(self,device_type, address, extended_address=None, network=None):
        self.__device_type = device_type
        self.__address = address
        self.__extended_address = extended_address
        self.__node_descriptor = None
        self.__active_endpoints = None
        self.__network = network

    def discover(self):
        for endpoint in self.endpoints:
            _ = endpoint.descriptor
        return (self.endpoints, self.descriptor)

    @property
    def descriptor(self):
        if self.__node_descriptor is None and self.__network.is_associated() and self.__network.is_authorized():
            self.__node_descriptor = self.stack.apl.get_application_by_name("zdo").device_and_service_discovery.get_node_descriptor(self.__address)
        return self.__node_descriptor

    @property
    def endpoints(self):
        if self.__active_endpoints is None and self.__network.is_associated() and self.__network.is_authorized():
            self.__active_endpoints = []
            for endpoint in self.stack.apl.get_application_by_name("zdo").device_and_service_discovery.get_active_endpoints(self.__address):
                self.__active_endpoints.append(Endpoint(endpoint, self))
        return self.__active_endpoints

    @property
    def address(self):
        return self.__address

    @property
    def extended_address(self):
        return self.__extended_address

    @address.setter
    def address(self, address):
        self.__address = address


    @extended_address.setter
    def extended_address(self, extended_address):
        self.__extended_address = extended_address

    @property
    def network(self):
        return self.__network

    @property
    def stack(self):
        return self.__network.stack

    def __eq__(self, other):
        return self.address == other.address

class Coordinator(Device):
    def __init__(self, address, extended_address=None, network=None):
        super().__init__(ZigbeeDeviceType.COORDINATOR, address, extended_address=extended_address, network=network)

    def __repr__(self):
        return (
            "Coordinator(" +
                "address="+hex(self.address) + ", " +
                "extended_address="+(hex(self.extended_address) if self.extended_address is not None else "<unknown>") + ", " +
                "network="+hex(self.network.extended_pan_id) +
            ")"
        )
class Router(Device):
    def __init__(self, address, extended_address=None, network=None):
        super().__init__(ZigbeeDeviceType.ROUTER, address, extended_address=extended_address, network=network)

    def __repr__(self):
        return (
            "Router(" +
                "address="+hex(self.address) + ", " +
                "extended_address="+(hex(self.extended_address) if self.extended_address is not None else "<unknown>") + ", " +
                "network="+hex(self.network.extended_pan_id) +
            ")"
        )

class EndDevice(Device):
    def __init__(self, address, extended_address=None, network=None):
        super().__init__(ZigbeeDeviceType.END_DEVICE, address, extended_address=extended_address, network=network)

    def __repr__(self):
        return (
            "EndDevice(" +
                "address="+hex(self.address) + ", " +
                "extended_address="+(hex(self.extended_address) if self.extended_address is not None else "<unknown>") + ", " +
                "network="+hex(self.network.extended_pan_id) +
            ")"
        )
