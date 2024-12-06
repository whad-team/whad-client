"""
Bluetooth Mesh Base Profile

Supports only the Configuration Server Model on the primary element
"""

from whad.btmesh.models import Element
from whad.btmesh.models.configuration import ConfigurationModelServer
from whad.btmesh.models.health import HealthModelServer
from whad.btmesh.models.generic_on_off import GenericOnOffServer

from threading import Lock


def lock(f):
    """
    Decorator to lock the seq_number

    :param f: [TODO:description]
    :type f: [TODO:type]
    """

    def _wrapper(self, *args, **kwargs):
        self.lock_seq()
        result = f(self, *args, **kwargs)
        self.unlock_seq()
        return result

    return _wrapper


class BaseMeshProfile(object):
    """
    Base class for Blutooth Mesh Profile.
    Should be inherited by BaseMeshProvisioneeProfile and BaseMeshProvisionerProfile

    All nodes should have the ConfigurationModelServer and HealthModelServer on the primary element (stack does not function without it)
    """

    def __init__(self):
        # Elements of the node. Ordered.
        self.__elements = []

        # address of primary element, used as an offset for the others
        # set after the provisioning
        self.primary_element_addr = 0

        # Set after the provisioning
        self.iv_index = b"\x00\x00\x00\x00"

        # Sequence number of the device for the iv_index
        # used by basically every layer ...
        self.__seq_number = 0

        # the forwarding number for "legitimate" PATH_REQUEST packets from our primary unicast addr
        self.__forwarding_number = 0

        # lock to access the seq_number
        self.__seq_lock = Lock()

        # address of primary element, used as an offset for the others
        self.primary_element_addr = 0

        self.iv_index = b"\x00\x00\x00\x00"

        # Sequence number of the device for the iv_index
        # used by basically every layer ...
        self.__seq_number = 0

        # the forwarding number for "legitimate" PATH_REQUEST packets from our primary unicast addr
        self.__forwarding_number = 0

        # lock to access the seq_number
        self.__seq_lock = Lock()

        # Create and register primary element
        self.register_element(is_primary=True)

        # dict of the subnets of the node. Key is net_key_index, value is a Subnet
        self.__subnets = {}

        self.__populate_base_models()

        primary_element = self.get_element(0)

        # Configure and add HealthModelServer
        health_server = HealthModelServer()
        primary_element.register_model(health_server)

        # Configuration Model Server mandatory (should be LAST to be created)
        conf_model = ConfigurationModelServer(profile=self)
        primary_element.register_model(conf_model)

    def __populate_base_models(self):
        """
        Populate elements and models for the node (except the ConfigurationModelServer and primary element creation, by default)
        """
        primary_element = self.get_element(0)
        primary_element.register_model(GenericOnOffServer())

    def lock_seq(self):
        self.__seq_lock.acquire()

    def unlock_seq(self):
        self.__seq_lock.release()

    @property
    def seqnum(self):
        return self.__seq_number

    def set_primary_element_addr(self, primary_element_addr):
        """
        Sets the primary unicast addr of the node (after provisioning). Used as an offset for the other elements based on their index

        :param primary_element_addr: Primary unicast addr
        :type primary_element_addr: int
        """
        self.primary_element_addr = primary_element_addr

    def is_unicast_addr_ours(self, addr):
        """
        Verifies if a unicast addr is ours (in the range of our addresses)
        Use after provisioning only ...

        :param addr: Unicast addr to check
        :type addr: int
        """
        max_addr = len(self.get_all_elements()) + self.primary_element_addr - 1

        if addr >= self.primary_element_addr and addr <= max_addr:
            return True
        return False

    @lock
    def get_next_seq_number(self, inc=1):
        """
        Reserves a number of seq num.
        If inc > 1, used for multiple fragment packet

        :param inc: [TODO:description], defaults to 1
        :type inc: [TODO:type], optional
        """
        seq = self.__seq_number
        self.__seq_number += inc
        return seq

    @lock
    def set_seq_number(self, seq):
        """
        Sets the seq number to a particular value (will still increment starting from that)

        :param seq: The new seq number of the node
        :type seq: int
        """
        self.__seq_number = seq

    def get_next_forwarding_number(self):
        """
        Get the legitimate (for our "real" addr range) forwardigng number to send a PATH_REQUEST
        and increments it
        """
        fwn = self.__forwarding_number
        self.__forwarding_number = (self.__forwarding_number + 1) % 256
        return fwn

    def provision(
        self, primary_net_key, dev_key, iv_index, flags, unicast_addr, app_key=None
    ):
        """
        When provisioning is done (auto or not), store the information received and keys

        :param primary_net_key: Primary net key object
        :type primary_net_key: NetworkLayerCryptoManager
        :param dev_key: Device key of the node
        :type dev_key: UpperTransportLayerDevKeyCryptoManager
        :param iv_index: The IV index
        :type iv_index: Bytes
        :param flags: Flags of features
        :type flags: int
        :param unicast_addr: The unicast addr of the node
        :type unicast_addr: bytes
        :param app_key: App key to add when auto provisioning, defaults to None
        :type app_key: UpperTransportLayerAppKeyCryptoManager, optional
        """
        configuration_server_model = self.get_configuration_server_model()
        configuration_server_model.get_state("net_key_list").set_value(
            field_name=primary_net_key.key_index, value=primary_net_key
        )
        configuration_server_model.get_state("app_key_list").set_value(
            field_name=-1, value=dev_key
        )
        self.iv_index = iv_index
        self.primary_element_addr = int.from_bytes(unicast_addr, "big")

        # Add an app ley if specified in arguments
        if app_key is not None:
            configuration_server_model.get_state("app_key_list").set_value(
                field_name=app_key.key_index, value=app_key
            )

    def bind_all(self, app_key_index):
        """
        Used when auto provisioning. Bind all the models of the node to app_key with index in argument

        :param app_key_index: Index of the app key
        :type app_key_index: int
        """
        for element in self.__elements:
            for model in element.models:
                # check if model is not configuration model
                if model.model_id != 0:
                    self.get_configuration_server_model().get_state(
                        "model_to_app_key_list"
                    ).set_value(field_name=model.model_id, value=[0])

    def get_element(self, index):
        """
        Returns the nth element of the profile. Index 0 for primary element

        :param index: Index of the element in the list
        :type index: int
        """
        try:
            return self.__elements[index]
        except IndexError:
            return None

    def get_all_elements(self):
        """
        Retrieves all the elements of the node
        """
        return self.__elements

    def remove_elements(self, index):
        """
        Used to remove an element (cannot be the primary one)

        :param index: Index of the element to remove
        :type index: int
        :returns: True if successfull, False otherwise
        """
        if len(self.__elements) < index:
            return False
        self.__elements.pop(index)
        return True

    def register_element(self, is_primary=False):
        """
        Add an element to a profile

        :param is_primary: Is the element the primary element of the node, defaults to False
        :type is_primary: Bool, optional
        """
        self.__elements.append(
            Element(is_primary=is_primary, index=len(self.__elements))
        )
        return len(self.__elements) - 1

    def get_configuration_server_model(self):
        """
        Returns the ConfigurationModelServer associated with the Node
        :returns: The ConfigurationModelServer object of the node
        :rtype: ConfigurationModelServer
        """
        return self.get_element(0).get_model_by_id(0)

    def get_subnet(self, index):
        """
        Returns the subnet with given net_key_index

        :param index: Index of net key associated with the subnet
        :type index: int
        :returns: The Subnet associated with the index if it exists, None otherwise
        :rtype: Subnet | None
        """
        try:
            return self.__subnets[index]
        except IndexError:
            return None

    def get_all_subnets(self):
        """
        Returns all the subnets objects of the node
        """
        return self.__subnets

    def add_subnet(self, subnet):
        """
        Adds a subnet into the disctionary. If it already exists, doesnt do anything.

        :param subnet: The subnet to add (with netkey intialized)
        :type subnet: Subnet
        """
        if subnet.net_key.key_index in self.__subnets.keys():
            return
        self.__subnets[subnet.net_key.key_index] = subnet

    def remove_subnet(self, index):
        """
        Removes a subnet with the given net_key_index.
        Returns the removed subnet if found, None otherwise

        :param index: Index of the NetKey associated with the subnet
        :type index: int
        :returns: The removed subnet
        :rtype: Subnet | None
        """
        return self.__subnets.pop(index, default=None)
