from whad.zigbee.stack.nwk.constants import ZigbeeDeviceType
from whad.zigbee.profile.endpoint import Endpoint

class EndpointsDiscoveryException(Exception):
    """
    Default exception raised when an error occured during Endpoints discovery.
    """
    def __init__(self):
        super().__init__()


class Node:
    """
    Class representing a Zigbee Node.
    """
    def __init__(
                    self,
                    device_type,
                    address,
                    extended_address=None,
                    descriptor=None,
                    network=None
    ):
        self.__device_type = device_type
        self.__address = address
        self.__extended_address = extended_address
        self.__node_descriptor = descriptor
        self.__active_endpoints = None
        self.__network = network

    def discover(self):
        """
        Discover the endpoints and the node descriptor exposed by this node.
        """
        for endpoint in self.endpoints:
            _ = endpoint.descriptor
        return (self.endpoints, self.descriptor)

    @property
    def descriptor(self):
        """
        Returns the node descriptor.
        """
        if (
            self.__node_descriptor is None and
            self.__network.is_associated() and
            self.__network.is_authorized()
        ):
            self.__node_descriptor = self.stack.get_layer('apl').get_application_by_name("zdo").device_and_service_discovery.get_node_descriptor(self.__address)
        return self.__node_descriptor

    @property
    def endpoints(self):
        """
        Returns the list of active endpoints.
        """
        if (
            self.__active_endpoints is None and
            self.__network.is_associated() and
            self.__network.is_authorized()
        ):
            self.__active_endpoints = []
            endpoints = self.stack.get_layer('apl').get_application_by_name("zdo").device_and_service_discovery.get_active_endpoints(self.__address)
            if endpoints is None:
                self.__active_endpoints = None
                raise EndpointsDiscoveryException()

            for endpoint in endpoints:
                self.__active_endpoints.append(Endpoint(endpoint, self))

        return self.__active_endpoints

    @property
    def address(self):
        """
        Returns the node short address.
        """
        return self.__address

    @property
    def extended_address(self):
        """
        Returns the node extended address.
        """
        return self.__extended_address

    @address.setter
    def address(self, address):
        """
        Sets the node short address.
        """
        self.__address = address


    @extended_address.setter
    def extended_address(self, extended_address):
        """
        Sets the node extended address.
        """
        self.__extended_address = extended_address

    @property
    def network(self):
        """
        Returns the network where the node is associated.
        """
        return self.__network

    @property
    def stack(self):
        """
        Returns the stack instance linked to the node.
        """
        return self.__network.stack

    def __eq__(self, other):
        """
        Checks if two nodes are equals (according to their short address).
        """
        return self.address == other.address

    def __repr__(self):
        return (
            self.__class__.__name__ + "(" +
                "address="+hex(self.address) + ", " +
                "extended_address="+(hex(self.extended_address) if self.extended_address is not None else "<unknown>") + ", " +
                "network="+hex(self.network.extended_pan_id) +
            ")"
        )
class CoordinatorNode(Node):
    """
    Represents a ZigBee Coordinator node.
    """
    def __init__(
                    self,
                    address,
                    extended_address=None,
                    descriptor=None,
                    network=None
    ):
        super().__init__(
                            ZigbeeDeviceType.COORDINATOR,
                            address,
                            extended_address=extended_address,
                            descriptor=descriptor,
                            network=network
        )
class RouterNode(Node):
    """
    Represents a ZigBee Router node.
    """
    def __init__(
                    self,
                    address,
                    extended_address=None,
                    descriptor=None,
                    network=None
    ):
        super().__init__(
                            ZigbeeDeviceType.ROUTER,
                            address,
                            extended_address=extended_address,
                            descriptor=descriptor,
                            network=network
        )

class EndDeviceNode(Node):
    """
    Represents a ZigBee End Device node.
    """
    def __init__(
                    self,
                    address,
                    extended_address=None,
                    descriptor=None,
                    network=None
    ):
        super().__init__(
                            ZigbeeDeviceType.END_DEVICE,
                            address,
                            extended_address=extended_address,
                            descriptor=descriptor,
                            network=network
        )
