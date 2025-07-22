"""
Bluetooth Mesh Base Profile

Supports only the Configuration Server Model on the primary element
Used for basic node directly is ok.
"""

from whad.btmesh.models import Element
from whad.btmesh.models.configuration import ConfigurationModelServer
from whad.btmesh.models.health import HealthModelServer
from whad.btmesh.models.generic_on_off import GenericOnOffServer
from whad.btmesh.stack.constants import (
    GROUP_ADDR_TYPE,
    UNICAST_ADDR_TYPE,
    VIRTUAL_ADDR_TYPE,
    UNASSIGNED_ADDR_TYPE,
)
from whad.btmesh.stack.utils import Subnet, MeshMessageContext, Node
from whad.btmesh.crypto import (
    NetworkLayerCryptoManager,
    UpperTransportLayerAppKeyCryptoManager,
    UpperTransportLayerDevKeyCryptoManager,
)
from whad.scapy.layers.btmesh import (
    BTMesh_Model_Config_Net_Key_Add,
    BTMesh_Model_Config_Net_Key_Delete,
    BTMesh_Model_Config_App_Key_Add,
    BTMesh_Model_Config_App_Key_Update,
    BTMesh_Model_Config_App_Key_Delete,
)

from threading import Lock
from copy import copy


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

    Manages the local data of the node and allows interaction from user code or shell to manage the device (no interaction with network)

    All nodes should have the ConfigurationModelServer and HealthModelServer on the primary element (stack does not function without it)
    """

    def __init__(
        self,
        auto_prov_net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
        # auto_prov_net_key=bytes.fromhex("efb2255e6422d330088e09bb015ed707"),
        auto_prov_dev_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        auto_prov_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        auto_prov_unicast_addr=0x0002,
    ):
        """
        Init of the BTMesh generic profile.

        :param auto_prov_net_key: Primary net key of the node (index 0) if auto_provisioned, defaults to bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00")
        :type auto_prov_net_key: bytes, optional
        :param auto_prov_dev_key: Dev key of the node if auto_provisioned , defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type auto_prov_dev_key: bytes, optional
        :param auto_prov_app_key: App key of the node (index 0, binded to net_key at index 0) if auto_provisioned, defaults to bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        :type auto_prov_app_key: bytes, optional
        :param auto_prov_unicast_addr: Primary unicast_addr if auto_provisioned, defaults to 0x0002
        :type auto_prov_unicast_addr: int, optional
        """

        # Is the node provisioned ? (should be True on start if Provisioner)
        self.is_provisioned = False

        # Elements of the node. Ordered.
        self.__elements = []

        # NOT USED, KEPT FOR REFRACTORING
        self.primary_element_addr = 0

        # Set after the provisioning
        self.iv_index = b"\x00\x00\x00\x00"

        # Sequence number of the device for the iv_index
        # used by basically every layer ..XŒ
        self.__seq_number = 0

        # the forwarding number for "legitimate" PATH_REQUEST packets from our primary unicast addr
        self.__forwarding_number = 0

        # lock to access the seq_number
        self.__seq_lock = Lock()

        # Sequence number of the device for the iv_index
        # used by basically every layer ...
        self.__seq_number = 0

        # the forwarding number for "legitimate" PATH_REQUEST packets from our primary unicast addr
        self.__forwarding_number = 0

        # dict of the subnets the node belongs to. (Subnet objects)
        self.__subnets = []

        # Dev keys of other nodes AND ours
        # Key is primary address of the node
        self.__dev_keys = {}

        # Represents our own Node (unprovisioned for now, arbitrary address)
        self.__local_node = Node(address=0x0001)

        # List of Nodes object reprensenting the nodes within the network.
        # Key is primary address of node. Automatically filled by provisioners when provisioning other nodes
        self.__distant_nodes = {}

        # Create and register primary element
        self.register_element(is_primary=True)

        self._populate_elements_and_models()

        primary_element = self.get_element(0)

        # Configure and add HealthModelServer
        health_server = HealthModelServer()
        primary_element.register_model(health_server)

        # Configuration Model Server mandatory (should be LAST to be created)
        conf_model = ConfigurationModelServer(profile=self)
        primary_element.register_model(conf_model)

        # Default values used when auto_provisioning
        self._auto_prov_net_key = auto_prov_net_key
        self._auto_prov_dev_key = auto_prov_dev_key
        self._auto_prov_app_key = auto_prov_app_key
        self._auto_prov_unicast_addr = auto_prov_unicast_addr

    def _populate_elements_and_models(self):
        """
        Populate elements and models for the node (except the ConfigurationModelServer, HealthModelServer and primary element creation, by default)
        """
        primary_element = self.get_element(0)
        primary_element.register_model(GenericOnOffServer())

    def lock_seq(self):
        self.__seq_lock.acquire()

    def unlock_seq(self):
        self.__seq_lock.release()

    def get_primary_element_addr(self):
        """
        Returns the primary unicast address of this node

        :returns: The primary element address of this node
        :rtype: int
        """
        return self.__local_node.address

    def set_primary_element_addr(self, primary_element_addr):
        """
        Sets the primary unicast addr of the node (after provisioning). Used as an offset for the other elements based on their index

        :param primary_element_addr: Primary unicast addr
        :type primary_element_addr: int
        """
        self.__local_node.address = primary_element_addr

    def is_unicast_addr_ours(self, addr):
        """
        Verifies if a unicast addr is ours (in the range of our addresses)
        Use after provisioning only ...
        If addr is 0x7E00 or 0x7FFF, considered ours (for attacks)

        :param addr: Unicast addr to check
        :type addr: int
        """
        max_addr = self.__local_node.address + self.__local_node.addr_range - 1

        if addr >= self.__local_node.address and addr <= max_addr:
            return True
        return False

    def is_addr_ours(self, addr, addr_type):
        """
        Checks if an address (unicast, group or virtual) is a target of us (should we process it after the network layer ?)

        :param addr: Address to check
        :type addr: int
        :param addr_type: Addr type
        :type addr_type: int
        :returns: True if we are a target, False otherwise
        :rtype: boolean
        """
        if addr_type == UNASSIGNED_ADDR_TYPE:
            return False

        if addr_type == UNICAST_ADDR_TYPE:
            res = self.is_unicast_addr_ours(addr) or (
                addr == 0x7E00 or addr == 0x7E01 or addr == 0x7FFF
            )
            return res

        if (
            addr_type == GROUP_ADDR_TYPE
        ):  # for now, only broadcast addr (all nodes and all directed forwarding) are considered
            if addr == 0xFFFF or addr == 0xFFFB:
                return True
            return False

        if addr_type == VIRTUAL_ADDR_TYPE:
            return False

    @property
    @lock
    def seqnum(self):
        return self.__seq_number

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
        :type unicast_addr: int
        :param app_key: App key to add when auto provisioning, defaults to None
        :type app_key: UpperTransportLayerAppKeyCryptoManager, optional
        """
        configuration_server_model = self.get_configuration_server_model()
        configuration_server_model.get_state("net_key_list").set_value(
            field_name=primary_net_key.key_index, value=primary_net_key
        )
        self.iv_index = iv_index
        # self.__dev_keys[unicast_addr] = dev_key
        # self.primary_element_addr = int.from_bytes(unicast_addr, "big")

        self.__local_node.address = unicast_addr
        self.__local_node.dev_key = dev_key
        self.__local_node.addr_range = len(self.__elements)

        # Add an app key if specified in arguments
        if app_key is not None:
            configuration_server_model.get_state("app_key_list").set_value(
                field_name=app_key.key_index, value=app_key
            )

        # Create subnet from the provisioning data
        subnet = Subnet(primary_net_key.key_index)
        self.add_subnet(subnet)

        self.is_provisioned = True

    def auto_provision(
        self,
    ):
        """
        Auto provisioning with data given in constructor of the profile or set with the setters
        Will automatically bind all the non config models of the node to the primary app key (index 0)

        :returns: True if successfull, False otherwise
        :rtype: bool
        """
        primary_net_key = NetworkLayerCryptoManager(
            key_index=0, net_key=self._auto_prov_net_key
        )
        dev_key = UpperTransportLayerDevKeyCryptoManager(
            device_key=self._auto_prov_dev_key
        )
        primary_app_key = UpperTransportLayerAppKeyCryptoManager(
            app_key=self._auto_prov_app_key
        )
        self.provision(
            primary_net_key,
            dev_key,
            b"\x00\x00\x00\x00",
            0,
            self._auto_prov_unicast_addr,
            primary_app_key,
        )
        # create app key and bind it to all models
        self.bind_all(primary_app_key.key_index)

        return True

    def bind_all(self, app_key_index):
        """
        Used when auto provisioning. Bind all the models of the node to app_key with index in argument

        :param app_key_index: Index of the app key
        :type app_key_index: int
        """
        for element in self.__elements:
            for model in element.models:
                # check if model is not configuration model (for now we allow use of app key because easier to manage for examples)
                # if model.model_id != 0:
                self.get_configuration_server_model().get_state(
                    "model_to_app_key_list"
                ).set_value(field_name=model.model_id, value=[0])

    def get_dev_key(self, address=None):
        """
        Retrieves the dev_key of the address in argument. If address is None, returns the dev key of this node.
        Returns None is no dev_key stored for the adress in argument

        :param address: Primary Address of the node we want the dev_key of, defaults to None
        :type address: int, optional
        :returns: The dev_key asked, None if not found
        :rtype: UpperTransportLayerDevKeyCryptoManager | None
        """
        if address is None or self.__local_node.address == address:
            return self.__local_node.dev_key

        elif address in self.__distant_nodes.keys():
            return self.__distant_nodes[address]

        else:
            return None

    def get_all_nodes(self):
        """
        Returns a dict of all the nodes that we know of (distant and local)
        Key is primary unicast address of the node.

        :return: A disctionary of Node objects we have (local and distant) (copies)
        :rtype: Dict[int, Node]
        """
        nodes = dict(self.__distant_nodes)
        nodes[self.__local_node.address] = copy(self.__local_node)
        return nodes

    def get_all_dev_keys(self):
        """
        Returns a dict of all the devkeys this node stores (at least it has its own)

        :returns: The dev_keys this node stores (dict, key is primary_element_addr of the node in question)
        :rtype: dict
        """
        return self.__dev_keys

    def update_dev_key(self, address, dev_key):
        """
        Update or add a dev_key associated witht the given address
        If the Node does not exist, we add it to the distant Nodes object.

        Returns True if success, False otherwise

        :param address: Address to bind to the dev_key
        :type address: int
        :param dev_key: The dev key to add
        :type dev_key: UpperTransportLayerDevKeyCryptoManager
        :returns: True is success, False otherwise
        :rtype: Bool
        """
        dev_key = UpperTransportLayerDevKeyCryptoManager(device_key=dev_key)

        if address == self.__local_node.address:
            self.__local_node.dev_key = dev_key

        elif address in self.__distant_nodes.keys():
            self.__distant_nodes[address].dev_key = dev_key
        else:
            self.__distant_nodes[address] = Node(
                address=address, addr_range=0, dev_key=dev_key
            )

        return True

    def remove_dev_key(self, address):
        """
        Removes a dev_key from the list we have
        Address cannot be the current primary adress of this node
        Returns True if success, False if fail


        :param address: Address to remove the dev_key of
        :type address: int
        """
        if address in self.__distant_nodes.keys():
            self.__distant_nodes.pop(address)
            return True

        return False

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

    def get_net_key(self, index):
        """
        Returns the NetworkLayerCryptoManager object associated with net_key_index. (the actual key object, not Subnet object)
        None if not exist

        :param index: net_key_index
        :type index: int
        """
        return (
            self.get_configuration_server_model()
            .get_state("net_key_list")
            .get_value(index)
        )

    def update_net_key(self, net_key_index, key):
        """
        Updates the net_key at index if it exists, or creates it alongisde the corresponding Subnet object
        For update, does not follow the proper Key refresh procedure (simply replaces the value --force)

        Returns False if problem, True if successfull

        :param net_key_index: The net_key_index
        :type net_key_index: int
        :param key: The key value to add/update
        :type key: Bytes
        """

        # If net_key already exist, update by hand and not via ConfigurationModelServer since procedure is different (key refresh)
        if self.get_subnet(net_key_index) is not None:
            self.get_configuration_server_model().get_state("net_key_list").set_value(
                field_name=net_key_index,
                value=NetworkLayerCryptoManager(net_key_index, key),
            )
            return True
        else:
            message = BTMesh_Model_Config_Net_Key_Add(
                net_key_index=net_key_index, net_key=key
            )
            response = self.get_configuration_server_model().on_net_key_add((
                message,
                MeshMessageContext(),
            ))
            if response.status != 0:
                return False

            self.add_subnet(Subnet(net_key_index))
            return True

    def remove_net_key(self, index):
        """
        Launches the Net Key delete procedure. The handler of the ConfigurationModelServer manages everything.
        Return True if ok, False if fail

        :param index: NetKey index of the key to remove
        :type index: int
        :returns: True if ok, False if fail
        :rtype: bool
        """
        message = BTMesh_Model_Config_Net_Key_Delete(net_key_index=index)
        response = self.get_configuration_server_model().on_net_key_delete((
            message,
            MeshMessageContext(),
        ))
        return response.status == 0

    def get_subnet(self, index):
        """
        Returns the subnet with given net_key_index

        :param index: Index of net key associated with the subnet
        :type index: int
        :returns: The Subnet associated with the index if it exists, None otherwise
        :rtype: Subnet | None
        """
        for subnet in self.__subnets:
            if subnet.net_key_index == index:
                return subnet

        return None

    def get_all_subnets(self):
        """
        Returns all the subnets objects of the node (List)
        """
        return self.__subnets

    def add_subnet(self, subnet):
        """
        Adds a subnet into the disctionary. If it already exists, doesnt do anything.

        :param subnet: The subnet to add (with netkey intialized)
        :type subnet: Subnet
        """
        if self.get_subnet(subnet.net_key_index) is None:
            self.__subnets.append(subnet)

    def remove_subnet(self, index):
        """
        Removes a subnet with the given net_key_index
        Returns the removed subnet if found, None otherwise (or if a single subnet is present)

        :param index: Index of the NetKey associated with the subnet
        :type index: int
        :returns: True if success, False if fail
        :rtype: bool
        """

        for i, subnet in enumerate(self.__subnets):
            if subnet.net_key_index == index:
                self.__subnets.pop(i)
                return True

        return False

    def get_app_key(self, index):
        """
        Returns the UpperTransportLayerAppKeyCryptoManager/UpperTransportLayerDevKeyCryptoManager object associated with app_key_index.
        None if not exist

        :param index: app_key_index
        :type index: int
        :returns: The AppKey for the index from the app_key_list state in ConfigurationModelServer, None if not found
        :rtype: UpperTransportLayerAppKeyCryptoManager | None
        """
        return (
            self.get_configuration_server_model()
            .get_state("app_key_list")
            .get_value(index)
        )

    def get_all_app_keys(self):
        """
        Returns a List of the App keys/Dev keys of UpperTransportLayerAppKeyCryptoManager
        From the app_key_list state in ConfigurationModelServer

        :returns: The list if UpperTransportLayerAppKeyCryptoManager of the node
        :rtype: List(UpperTransportLayerAppKeyCryptoManager)
        """
        return (
            self.get_configuration_server_model()
            .get_state("app_key_list")
            .get_all_values()
        )

    def update_app_key(self, app_key_index, net_key_index, value):
        """
        Updates the app_key at index if it exists, or creates it alongisde the corresponding Subnet object
        For update, does not follow the proper Key refresh procedure (simply replaces the value --force)

        Returns False if problem, True if successfull.

        :param app_key_index: The app_key_index
        :type app_key_index: int
        :param: net_key_index: the net_key_index the key is bounded to
        ;type net_key_index: int
        :param key: The key value to add/update
        :type key: Bytes
        """

        if self.get_app_key(app_key_index) is not None:
            message = BTMesh_Model_Config_App_Key_Update(
                app_key_index=app_key_index, net_key_index=net_key_index, app_key=value
            )
            response = self.get_configuration_server_model().on_app_key_update((
                message,
                MeshMessageContext(),
            ))
        else:
            message = BTMesh_Model_Config_App_Key_Add(
                app_key_index=app_key_index, net_key_index=net_key_index, app_key=value
            )
            response = self.get_configuration_server_model().on_app_key_add((
                message,
                MeshMessageContext(),
            ))

        return response.status == 0

    def remove_app_key(self, app_key_index, net_key_index):
        """
        Removes an app_key with the given app_key_index and net_key_index from the app_key_list in the ConfigurationModelServer
        Returns the removed app_key if found, None otherwise (or if only one app_key is present)

        :param index: Index of the AppKey
        :type index: int
        :returns: True if success, False if fail
        :rtype: bool
        """
        message = BTMesh_Model_Config_App_Key_Delete(
            app_key_index=app_key_index, net_key_index=net_key_index
        )
        response = self.get_configuration_server_model().on_app_key_delete((
            message,
            MeshMessageContext(),
        ))
        return response.status == 0

    def set_auto_prov_unicast_addr(self, unicast_addr):
        """
        Sets the value to use for the unicast_addr of the node if auto_provision used

        :param unicast_addr: Unicast address to set
        :type unicast_addr: int
        """
        self._auto_prov_unicast_addr = int

    def set_auto_prov_net_key(self, net_key):
        """
        Sets the value to use for the primary_net_key of the node if auto_provision used

        :param net_key: net key value
        :type  net_key: bytes
        """
        self._auto_prov_net_key = net_key

    def set_auto_prov_app_key(self, app_key):
        """
        Sets the value to use for the app_key at index 0 if auto_provision used

        :param app_key: App key value
        :type app_key: bytes
        """
        self._auto_prov_app_key = app_key

    def set_auto_prov_dev_key(self, dev_key):
        """
        Sets the value to use for the dev_key of the node if auto_provision used

        :param dev_key: Dev key value
        :type dev_key: bytes
        """
        self._auto_prov_dev_key = dev_key
