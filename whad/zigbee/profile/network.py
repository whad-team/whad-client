from whad.zigbee.stack.nwk.constants import ZigbeeDeviceType
from whad.zigbee.profile.nodes import CoordinatorNode, EndDeviceNode, RouterNode
from whad.dot15d4.address import Dot15d4Address
from random import randint
from time import sleep

class JoiningForbidden(Exception):
    """
    Exception raised when joining is forbidden on the network.
    """
    pass

class NotAssociated(Exception):
    """
    Exception raised when we are not associated in this network.
    """
    pass

class NotAuthorized(Exception):
    """
    Exception raised when we are not authorized in this network.
    """
    pass

class Network:
    """
    Class representing a ZigBee network.
    """
    def __init__(self, nwkObject=None, stack = None):
        # reference to the corresponding network representation
        # in the stack, we are defining an helper class here.
        self.__nwk_object = nwkObject

        # reference to the stack
        self.__stack = stack

        # only one coordinator, but possibly multiple routers & end devices
        self.coordinator = None
        self.routers = []
        self.end_devices = []


    @property
    def nodes(self):
        """
        Returns all the nodes present in this network.
        """
        return (
            [self.coordinator] if self.coordinator is not None else []
        ) + self.routers + self.end_devices

    @property
    def stack(self):
        """
        Returns the associated instance of the stack.
        """
        return self.__stack

    @property
    def pan_id(self):
        """
        Returns the network Pan ID.
        """
        return self.__nwk_object.dot15d4_pan_network.coord_pan_id

    @property
    def extended_pan_id(self):
        """
        Returns the network extended Pan ID.
        """
        return self.__nwk_object.extended_pan_id

    @property
    def channel(self):
        """
        Returns the channel used by the network.
        """
        return self.__nwk_object.channel

    def discover(self):
        """
        Discover all the nodes present in the network.
        """
        if not self.is_associated():
            raise NotAssociated
        if not self.is_authorized():
            raise NotAuthorized
        devices = self.stack.get_layer('apl').get_application_by_name("zdo").device_and_service_discovery.discover_nodes()
        return self.nodes

    def join(self):
        """
        Join the network (if permitted).

        This method is blocking and wait until we are both associated AND authorized on the network.
        """
        if self.is_joining_permitted():
            join_success = self.stack.get_layer('apl').get_application_by_name("zdo").network_manager.join(self)
            if join_success:
                while not self.is_authorized():
                    sleep(0.1)
                return True
            return False
        else:
            raise JoiningForbidden

    def rejoin(self, address=None):
        """
        Rejoin the network (if permitted).

        This method is blocking and wait until we are both associated AND authorized on the network.
        """
        if address is None:
            address = randint(0x0001, 0xFFF0)
        print("rejoining...")
        self.stack.get_layer('apl').get_application_by_name("zdo").network_manager.configure_short_address(address)
        rejoin_success = self.stack.get_layer('apl').get_application_by_name("zdo").network_manager.rejoin(self)

        if rejoin_success:
            while not self.is_authorized():
                sleep(0.1)
            return True
        return False

    def is_joining_permitted(self):
        """
        Indicates if joining the network is permitted.
        """
        return self.__nwk_object.joining_permit

    def is_associated(self):
        """
        Indicates if we are associated with the network.
        """
        return self.stack.get_layer('nwk').database.get("nwkExtendedPANID") == self.extended_pan_id

    def is_authorized(self):
        """
        Indicates if we are authorized on the network.
        """
        return self.stack.get_layer('apl').get_application_by_name("zdo").network_manager.authorized

    @property
    def network_key(self):
        """
        Returns the network key associated with this network (if any).
        """
        nwk_material = self.stack.get_layer('nwk').database.get("nwkSecurityMaterialSet")
        if len(nwk_material) > 0:
            return nwk_material[0].key
        else:
            return None

    @network_key.setter
    def network_key(self, value):
        """
        Configure the network key associated with this network.
        """
        self.stack.get_layer('apl').get_application_by_name("zdo").security_manager.provision_network_key(value)

    def leave(self):
        """
        Initiates a leave operation on this network.
        """
        return self.stack.get_layer('apl').get_application_by_name("zdo").network_manager.leave()

    def __eq__(self, other):
        return self.extended_pan_id == other.extended_pan_id

    def __repr__(self):
        return (
            "Network(" +
            "pan_id=" + hex(self.pan_id) + ", " +
            "extended_pan_id=" + str(self.extended_pan_id) + ", " +
            "channel="+str(self.channel) + ", " +
            "joining="+ ("allowed" if self.is_joining_permitted() else "forbidden") + ", " +
            "associated="+ ("yes" if self.is_associated() else "no") + ", "
            "authorized="+ ("yes" if self.is_authorized() else "no") +

            ")"
        )
