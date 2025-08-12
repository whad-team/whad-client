"""
Bluetooth Mesh Base Profile

Supports only the Configuration Server Model on the primary element
Used for basic node directly is ok.
"""

from whad.btmesh.models import Element
from whad.btmesh.models.configuration import (
    ConfigurationModelServer,
    ConfigurationModelClient,
)
from whad.btmesh.models.health import HealthModelServer
from whad.btmesh.models.generic_on_off import GenericOnOffServer, GenericOnOffClient
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

    When creating a new profile, the only function that the subclass should overwrite is the _populate_elements_and_models function
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

        # Is the local node provisioned ? (should be True on start if Provisioner)
        self.is_provisioned = False

        # Set after the provisioning
        self.iv_index = b"\x00\x00\x00\x00"

        # Sequence number of the local node for the iv_index
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

        # list of the subnets the local node belongs to. (Subnet objects)
        self.__subnets = []

        # Represents our own Node (unprovisioned for now, arbitrary address)
        self.__local_node = Node(address=0x0001)

        # List of Nodes object reprensenting the nodes within the network.
        # Key is primary address of node. Automatically filled by provisioners when provisioning other nodes
        self.__distant_nodes = {}

        # Create and register primary element
        primary_element = self.__local_node.add_element(index=0, is_primary=True) 

        self._populate_elements_and_models()

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

        # Provisioning Capabilities of the Device, set via shell or configuration.
        self.capabilities = dict(
            algorithms=0b11,  # default support 2 algs
            public_key_type=0x00,  # default no OOB public key support
            oob_type=0b00,  # no static OOB supported
            output_oob_size=0x00,
            output_oob_action=0b00000,  # default no output OOB action available, for tests, 0b11000
            input_oob_size=0x00,
            input_oob_action=0b0000,  # default no input OOB a available. For test, 0b1100
        )

    def _populate_elements_and_models(self):
        """
        Populate elements and models for the node (except the ConfigurationModelServer, HealthModelServer and primary element creation, by default)
        """

        new_element = self.__local_node.add_element()
        new_element.register_model(GenericOnOffServer())

        primary_element = self.__local_node.get_element(0)
        primary_element.register_model(GenericOnOffServer())
        primary_element.register_model(GenericOnOffClient())
        # for convenience, we add a ConfigurationModelClient to all nodes for testing.
        primary_element.register_model(ConfigurationModelClient())

    def lock_seq(self):
        self.__seq_lock.acquire()

    def unlock_seq(self):
        self.__seq_lock.release()

    @property
    def local_node(self):
        return self.__local_node

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

        self.__local_node.address = unicast_addr
        self.__local_node.dev_key = dev_key
        self.__local_node.addr_range = len(self.__local_node.get_all_elements())

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
        Used when auto provisioning. Bind all the models of the local node to app_key with index in argument

        :param app_key_index: Index of the app key
        :type app_key_index: int
        """
        for element in self.__local_node.get_all_elements():
            for model in element.models:
                # check if model is not configuration model (for now we allow use of app key because easier to manage for examples)
                # if model.model_id != 0:
                self.get_configuration_server_model().get_state(
                    "model_to_app_key_list"
                ).set_value(field_name=model.model_id, value=[0])

    def get_dev_key(self, address=None):
        """
        Retrieves the dev_key of the address in argument. If address is None, returns the dev key of the node.
        Returns None is no dev_key stored for the adress in argument

        :param address: Primary Address of the node we want the dev_key of, defaults to None
        :type address: int, optional
        :returns: The dev_key asked, None if not found
        :rtype: UpperTransportLayerDevKeyCryptoManager | None
        """
        if address is None or self.__local_node.address == address:
            return self.__local_node.dev_key

        elif address in self.__distant_nodes.keys():
            return self.__distant_nodes[address].dev_key

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

    def add_distant_node(self, node):
        """
        Adds a new distant node to our dictionnary

        :param node: The new node object to add
        :type node: Node
        """
        self.__distant_nodes[node.address] = node
        return True

    def get_distant_node(self, address):
        """
        Returns a Node object that has the specified primary address if we have one.
        None if it doesnt exist.

        :param address: Primary unicast address of the node
        :type address: int
        :return: The node that has the address, None if not found
        :rtype: Node | None
        """
        try:
            return self.__distant_nodes[address]
        except KeyError:
            return None

    def remove_distant_node(self, address):
        """
        Removes the distant node that has the given primary unicast address from our dictionnary
        Local change only

        :param address: The primary uniast address of the node we want to remove from our database
        :type address: int
        :returns: The removed node if successfull, None otherwise
        :rtype: Node | None
        """
        try:
            return self.__distant_nodes.pop(address)
        except KeyError:
            return None

    def update_dev_key(self, address=None, dev_key=None):
        """
        Update or add a dev_key associated witht the given address (or local node if no address given)
        If the Node does not exist, we add it to the distant Nodes object.

        Returns True if success, False otherwise

        :param address: Address to bind to the dev_key, defaults to None
        :type address: int, optional
        :param dev_key: The dev key to add
        :type dev_key: UpperTransportLayerDevKeyCryptoManager
        :returns: True is success, False otherwise
        :rtype: Bool
        """
        dev_key = UpperTransportLayerDevKeyCryptoManager(device_key=dev_key)

        if address is None:
            self.__local_node.dev_key = dev_key

        elif address in self.__distant_nodes.keys():
            self.__distant_nodes[address].dev_key = dev_key
        else:
            self.__distant_nodes[address] = Node(
                address=address, addr_range=0, dev_key=dev_key
            )

        return True

    def update_distant_node_elements(self, address, composition_packet):
        """
        Updates the list of elements/models of the node with primary address specified based on a received Composition page.

        :param composition_packet: A Composition page (sent by node or generated ?)
        :type composition_packet: BTMesh_Model_Config_Composition_Data_Status
        """

    def get_configuration_server_model(self):
        """
        Returns the ConfigurationModelServer associated with the local Node (speficic model needed in the stack)
        :returns: The ConfigurationModelServer object of the node
        :rtype: ConfigurationModelServer
        """
        return self.local_node.get_element(0).get_model_by_id(0)

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
            response = self.get_configuration_server_model().on_net_key_add(
                (
                    message,
                    MeshMessageContext(),
                )
            )
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
        response = self.get_configuration_server_model().on_net_key_delete(
            (
                message,
                MeshMessageContext(),
            )
        )
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
            response = self.get_configuration_server_model().on_app_key_update(
                (
                    message,
                    MeshMessageContext(),
                )
            )
        else:
            message = BTMesh_Model_Config_App_Key_Add(
                app_key_index=app_key_index, net_key_index=net_key_index, app_key=value
            )
            response = self.get_configuration_server_model().on_app_key_add(
                (
                    message,
                    MeshMessageContext(),
                )
            )

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
        response = self.get_configuration_server_model().on_app_key_delete(
            (
                message,
                MeshMessageContext(),
            )
        )
        return response.status == 0

    def set_auto_prov_unicast_addr(self, unicast_addr):
        """
        Sets the value to use for the unicast_addr of the node if auto_provision used

        :param unicast_addr: Unicast address to set
        :type unicast_addr: int
        """
        self._auto_prov_unicast_addr = unicast_addr

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
