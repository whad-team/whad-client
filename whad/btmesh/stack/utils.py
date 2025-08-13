"""
Classes used between layers to manage a message.
"""

from whad.btmesh.stack.constants import (
    VIRTUAL_ADDR_TYPE,
    GROUP_ADDR_TYPE,
    UNICAST_ADDR_TYPE,
    UNASSIGNED_ADDR_TYPE,
    MANAGED_FLOODING_CREDS,
)
from whad.btmesh.models import StatesManager, Element, Model
from whad.btmesh.models.states import (
    NodeIdentityState,
    PrivateNodeIdentityState,
    DirectedControlCompositeState,
    PathMetricCompositeState,
    ForwardingTableCompositeState,
    WantedLanesState,
    UnicastEchoIntervalState,
    MulticastEchoIntervalState,
    DiscoveryTableCapabitlitiesCompositeState,
    KeyRefreshPhaseState,
    TwoWayPathState,
)
from whad.btmesh.stack.constants import (
    OUTPUT_NUMERIC_AUTH,
    OUTPUT_ALPHANUM_AUTH,
    INPUT_ALPHANUM_AUTH,
    INPUT_NUMERIC_AUTH,
)
from random import randrange, choices
from string import ascii_letters, digits
from struct import unpack
from whad.btmesh.crypto import UpperTransportLayerDevKeyCryptoManager


class MeshMessageContext:
    """
    Context of a BTMesh message (Rx and Tx)
    Is passed from layers to layers alongside the scapy packets.
    """

    def __init__(self):
        self.src_addr: int = None
        self.dest_addr: int = 0xFFFF

        # Credentials used at the network layer (managed flooding or directed forwarding) (frienship creds not supported)
        self.creds: int = MANAGED_FLOODING_CREDS

        # Should be equal to the sequence number of the PDU
        self.seq_number: int = None

        # if segmentention used in Lower transport layer, set to the segment number
        self.segment_number: int = None

        # AID of the app_key if app_key used, -1 if device_key used
        self.aid: int = None

        # Index of the app key if not device_key used, -1 if device key used
        self.application_key_index: int = 0

        # Address of the node we use the DevKey of to decrypt/encrypt the message (should be dst or src addr...)
        self.dev_key_address: int = None

        # Net key id used
        self.net_key_id: int = 0

        # lower transport value (size of mic)
        self.aszmic: int = 0

        # If src_addr is Virtual Addr
        self.uuid: bytes = None

        # Either received TTL or sending TTL
        self.ttl: int = None  # int

        # True if Upper Transport Control Message/Ack messgae (network_ctl field to 1), false otherwise
        self.is_ctl: bool = False

        # Seq auth value set by the Upper Transport Layer when encrypting the access pdu
        self.seq_auth: int = None

        # Set by model layer, if the message is too small to be segmented but still want acknowlegment on network layer
        self.force_segment: bool = False

        # Received RSSI of a packet (sending RSSI when feature available for Adv mode)
        self.rssi: float = 0

    def print(self):
        for attribute, value in self.__dict__.items():
            print(attribute, "=", value)


class Subnet(StatesManager):
    """
    Represents a subnet associated with one NetKey.
    The states bound to a subnet are accessible from this object.
    """

    def __init__(self, net_key_index):
        """
        Initializes the subnet with its netkey

        :param net_key: The index of the netkey associated with the subnet
        :type net_key: int
        """
        super().__init__()
        self.net_key_index = net_key_index

    def __init_states(self):
        """
        Initializes the states bound to a subnet (called in StatesManager __init__)
        """
        self.add_state(NodeIdentityState())
        self.add_state(PrivateNodeIdentityState())
        self.add_state(DirectedControlCompositeState())
        self.add_state(PathMetricCompositeState())
        self.add_state(ForwardingTableCompositeState())
        self.add_state(WantedLanesState())
        self.add_state(UnicastEchoIntervalState())
        self.add_state(MulticastEchoIntervalState())
        self.add_state(DiscoveryTableCapabitlitiesCompositeState())
        self.add_state(KeyRefreshPhaseState())
        self.add_state(TwoWayPathState())


class Node:
    """
    Represents a node within the network and stores data related to it.
    Also used to represent our node.

    Automatically filed when provisioner node provisions a node. Otherwise needs to be filled by hand.
    """

    def __init__(
        self,
        address,
        addr_range=0,
        dev_key=UpperTransportLayerDevKeyCryptoManager(
            device_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48")
        ),
    ):
        """
        Creates a node object.

        :param address: Primary unicast Address of the node
        :type address: int
        :param addr_range: Number of addresses in the range. If 0 or 1, one address. If greater than 2, range. defaults to 0
        :type addr_range: int, optional
        :param dev_key: Dev key of the node, defaults to UpperTransportLayerDevKeyCryptoManager(bytes.fromhex("63964771734fbd76e3b40519d1d94a48"))
        :type dev_key: UpperTransportLayerDevKeyCryptoManager, optional
        """

        self.__address = address & 0xFFFF
        self.__addr_range = 0 if addr_range in (0, 1) else addr_range & 0xFFFF
        self.__dev_key = dev_key
        self.__elements = {}

        # Features
        self.__is_relay = False
        self.__is_proxy = False
        self.__is_friend = False
        self.__is_lpn = False

    @property
    def address(self):
        return self.__address

    @address.setter
    def address(self, value):
        self.__address = value & 0xFFFF

    @property
    def addr_range(self):
        return self.__addr_range

    @addr_range.setter
    def addr_range(self, value):
        self.__addr_range = 0 if value in (0, 1) else value & 0xFFFF

    @property
    def dev_key(self):
        return self.__dev_key

    @dev_key.setter
    def dev_key(self, value):
        self.__dev_key = value

    @property
    def is_relay(self):
        return self.__is_relay

    @is_relay.setter
    def is_relay(self, value):
        self.__is_relay = value

    @property
    def is_proxy(self):
        return self.__is_proxy

    @is_proxy.setter
    def is_proxy(self, value):
        self.__is_proxy = value

    @property
    def is_friend(self):
        return self.__is_friend

    @is_friend.setter
    def is_friend(self, value):
        self.__is_friend = value

    @property
    def is_lpn(self):
        return self.__is_lpn

    @is_lpn.setter
    def is_lpn(self, value):
        self.__is_lpn = value

    def add_element(self, index=None, is_primary=False):
        """
        Adds an element to the list of elements of the node at index given.
        Ideally, no index should be passed (can raise error if not subsequent, elements added in order, index + 1 each time)

        :param index: index of the element to add (should not be used ideally), defaults to None
        :type element: int, optional
        :param is_primary: Is the element the primary index ?
        :return: The Element created (object contains index as well)
        :rtype: Element
        """
        if index is None:
            index = len(self.__elements)

        self.__elements[index] = Element(is_primary=is_primary, index=index)
        return self.__elements[index]

    def get_element(self, index):
        """
        Returns the nth element of the node. Index 0 for primary element
        Returns None if not found

        :param index: Index of the element in the list
        :type index: int
        :returns: The element at index given, None if doesnt exist
        :rtype: Element | None
        """
        try:
            return self.__elements[index]
        except KeyError:
            return None

    def get_all_elements(self):
        """
        Retrieves all the elements of the node (list of elements, sorted by index)
        """
        return dict(sorted(self.__elements.items())).values()

    def remove_element(self, index):
        """
        Used to remove an element (cannot be the primary one)

        :param index: Index of the element to remove
        :type index: int
        :returns: True if successfull, False otherwise
        """
        try:
            self.__elements.pop(index)
            return True
        except KeyError:
            return False

    def dissect_composition_data(self, page_0):
        """
        Interprets the pages of Composition data to fill the elements list with Elements and associated Models
        (Only from page0, no relashionship information)
        The Models are only placeholders and do not allow sending/receving.
        Used to get information about distant nodes

        :param page_0: Page 0 of the CompositionData
        :type page_0: BTMesh_Model_Config_Composition_Data_Status
        """
        data = page_0.data

        self.is_relay = bool(data.features & 0b1000)
        self.is_proxy = bool(data.features & 0b100)
        self.is_friend = bool(data.features & 0b10)
        self.is_lpn = bool(data.features & 0b1)

        for element in data.elements:
            new_element = self.add_element()
            for model_id in element.sig_models:
                new_element.register_model(Model(model_id=model_id))
            for model_id in element.vendor_models:
                new_element.register_model(
                    Model(model_id=model_id), is_vendor_model=True
                )


class ProvisioningData:
    """
    Message sent by Provisioning Layer through the provisioning stack in ordrer to send it to the connector with the provisioning data
    """

    def __init__(
        self,
        net_key=None,
        key_index=None,
        flags=None,
        iv_index=None,
        unicast_addr=None,
        addr_range=None,
        provisioning_crypto_manager=None,
    ):
        """
        Init the Data with the received provisioning data
        Also the provisioning_crypto_manager is sent to comptute the device_key
        Or we use the dev_key value in arg. ONE OR THE OTHER ARGUMENT IS PRESENT (not both)

        :param net_key: The value of the netkey
        :type net_key: Bytes
        :param key_index: The net key index
        :type key_index: int
        :param flags: Flags (unused for now)
        :type flags: Any
        :param iv_index: The iv_index
        :type iv_index: Bytes
        :param unicast_addr: Unicast addr of the device
        :type unicast_addr: int
        :param addr_range: Range of unicast_addr of the node
        :type addr_range: int
        :param provisioning_crypto_manager: The provisionning_crypto_manager used during provisioning
        :type provisioning_crypto_manager: ProvisioningBearerAdvCryptoManagerProvisionee
        """
        self.net_key = net_key
        self.key_index = key_index
        self.flags = flags
        self.iv_index = iv_index
        self.unicast_addr = unicast_addr
        self.provisioning_crypto_manager = provisioning_crypto_manager
        self.addr_range = addr_range

    def get_data_string(self):
        """
        Returns the byte object to send in a Provisioning_Data packet
        """
        return (
            self.net_key
            + self.key_index.to_bytes(2, "big")
            + self.flags
            + self.iv_index
            + self.unicast_addr.to_bytes(2, "big")
        )


class ProvisioningAuthenticationData:
    """
    Message sent/received by the Provisioning layer and the connector in order to manage authentication (input, output)
    Allows to notify the connector (hence the user) that an authentication value is needed.

    Constants for methods and actions in btmesh/provisioning/constants.py
    """

    def __init__(self, auth_method, auth_action, size, value=None):
        """
        Inits the ProvisioningAuthenticationData object with the type needed and the value if relevant

        :param auth_method: The auth_method (INPUT, OUTUT or STATIC OOB)
        :type auth_method: int
        :param: auth_action: The auth_action (numeric, alphanum, beep ....)
        :type auth_action: int
        :param size: The size of the auth value
        :type size: int
        :param value: Auth value
        :type value: str | int
        """
        self.auth_method = auth_method
        self.auth_action = auth_action
        self.size = size
        self.value = value

    def generate_value(self):
        """
        Based on the parameters of the object, generate a random auth value
        For now supports numeric or alphanum only
        """
        if (
            self.auth_action == INPUT_NUMERIC_AUTH
            or self.auth_method == OUTPUT_NUMERIC_AUTH
        ):
            lower_bound = 10 ** (self.size - 1)
            upper_bound = 10**self.size
            self.value = randrange(lower_bound, upper_bound)

        elif (
            self.auth_action == INPUT_ALPHANUM_AUTH
            or self.auth_action == OUTPUT_ALPHANUM_AUTH
        ):
            self.value = "".join(choices(ascii_letters + digits, k=self.size))


def get_address_type(address):
    """
    Utils function returning the type of the address in argument (virtual, group or unicast)

    :param address: The address to check
    :type address: int
    :returns: The type of the address (constant values in whad.btmesh.stack.constants)
    :rtype: int
    """

    if address == 0:
        return UNASSIGNED_ADDR_TYPE
    elif (address & 0b1000000000000000) == 0:
        return UNICAST_ADDR_TYPE
    elif (address & 0b0100000000000000) == 0:
        return VIRTUAL_ADDR_TYPE
    else:
        return GROUP_ADDR_TYPE


def key_indexes_to_packet_encoding(key_indexes):
    """
    Encodes a list of key indexes according to Mesh PRT Spec Section 4.3.1.1
    (if not handled in Scapy, for unbound list of indexes)

    :param key_indexes: List of key indexes
    :type key_indexes: List[int]
    """
    ints = key_indexes
    if ints is None or ints == []:
        return []
    byte_array = bytearray()

    for i in range(0, len(ints), 2):
        if i + 1 < len(ints):
            first_int = ints[i]
            second_int = ints[i + 1]

            # Ensure both integers are within 12 bits
            if (
                first_int < 0
                or first_int >= 4096
                or second_int < 0
                or second_int >= 4096
            ):
                raise ValueError("Integers must be in the range 0 to 4095 (12 bits).")

            # 2 keys in 3 bytes, little endian
            packed = (first_int << 12) | second_int
            byte_array.append(packed & 0xFF)
            byte_array.append((packed >> 8) & 0xFF)
            byte_array.append((packed >> 16) & 0xFF)
        else:
            # handle the last integer if the count is odd
            last_int = ints[i]

            if last_int < 0 or last_int >= 4096:
                raise ValueError("Integer must be in the range 0 to 4095 (12 bits).")

            packed = last_int << 4
            byte_array.append(packed & 0xFF)
            byte_array.append(
                (packed >> 8) & 0xFF
            )  # Most significant byte (only needed if last_int is >= 256)

    return bytes(byte_array)


def packet_encoding_to_key_indexes(packed_keys):
    """
    Unpacks a list of key indexes according to Mesh PRT Spec Section 4.3.1.1
    (if not handled in Scapy, for unbound list of indexes)

    :param packed_keys: Field in the packed of the indexes
    :type key_indexes: Bytes
    """

    ints = []
    if packed_keys is None or packed_keys == []:
        return []

    packed_bytes = packed_keys

    for i in range(0, len(packed_bytes) - 2, 3):
        byte1 = packed_bytes[i]
        byte2 = packed_bytes[i + 1]
        byte3 = packed_bytes[i + 2]

        # Combine the bytes into two integers
        packed = (byte3 << 16) | (byte2 << 8) | byte1

        # Extract the keys
        first_int = (packed >> 12) & 0xFFF
        second_int = packed & 0xFFF

        ints.append(first_int)
        ints.append(second_int)

    # Handle the last 2 bytes if the total number of bytes is odd
    if len(packed_bytes) % 3 == 2:
        # Read the last 2 bytes
        byte1 = packed_bytes[-2]
        byte2 = packed_bytes[-1]

        packed = (byte2 << 8) | byte1  # Combine into a single 16-bit integer

        last_int = (packed >> 4) & 0xFFF
        ints.append(last_int)

    return ints


def calculate_seq_auth(iv_index: bytes, seq: int, seq_zero: int) -> int:
    """
    Computes the SeqAuth value for a PDU received in the Lower Transport Layer

    :param iv_index: The iv_index used
    :type iv_index: Bytes
    :param seq: The sequence number (network layer) of the segment PDU
    :type seq: int
    :param seq_zero: The seq_zero value (lower transport layer)
    ;param seq_zero: int
    :return: The seq_auth value
    :rtype: int
    """
    iv_index_int = int.from_bytes(iv_index, byteorder="big")

    TRANSPORT_SAR_SEQZERO_MASK = 0x1FFF
    masked_seqnum = seq & TRANSPORT_SAR_SEQZERO_MASK
    if masked_seqnum < seq_zero:
        adjusted_seq = (
            seq - (masked_seqnum - seq_zero) - (TRANSPORT_SAR_SEQZERO_MASK + 1)
        )
    else:
        adjusted_seq = seq - (masked_seqnum - seq_zero)

    seq_auth = (iv_index_int << 24) | adjusted_seq

    return seq_auth
