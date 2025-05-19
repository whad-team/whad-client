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
from whad.btmesh.models import StatesManager
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


class MeshMessageContext:
    """
    Context of a BTMesh message (Rx and Tx)
    Is passed from layers to layers alongside the scapy packets.
    """

    def __init__(self):
        self.src_addr: bytes = None
        self.dest_addr: bytes = None

        # Credentials used at the network layer (managed flooding or directed forwarding) (frienship creds not supported)
        self.creds: int = MANAGED_FLOODING_CREDS

        # Should be equal to the sequence number of the PDU
        self.seq_number: int = None

        # if segmentention used in Lower transport layer, set to the segment number
        self.segment_number: int = None

        # AID of the app_key if app_key used, -1 if device_key used
        self.aid: int = None

        # Index of the app key if not device_key used, -1 if device key used
        self.application_key_index: int = None

        # Address of the node we use the DevKey of to decrypt/encrypt the message (should be dst or src addr)
        self.dev_key_address: bytes = None

        # Net key id used
        self.net_key_id: int = None

        # lower transport value (size of mic)
        self.aszmic: int = 0

        # If src_addr is Virtual Addr
        self.uuid: bytes = None

        # Either received TTL or sending TTL
        self.ttl: int = None  # int

        # True if Upper Transport Control Message/Ack messgae (network_ctl field to 1), false otherwise
        self.is_ctl: bool = False

        # Seq auth value set by the Upper Transport Layer when encrypting the access pdu
        # Set by the Network layer on Rx messages
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


class ProvisioningCompleteData:
    """
    Message sent by Provisioning Layer through the provisioning stack in ordrer to send it to the connector with the provisioning data
    """

    def __init__(
        self,
        net_key,
        key_index,
        flags,
        iv_index,
        unicast_addr,
        provisionning_crypto_manager,
    ):
        """
        Init the Data with the received provisioning data
        Also the provisionning_crypto_manager is sent to comptute the device_key
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
        :type unicast_addr: Bytes
        :param provisionning_crypto_manager: The provisionning_crypto_manager used during provisioning
        :type provisioning: ProvisioningBearerAdvCryptoManagerProvisionee
        """
        self.net_key = net_key
        self.key_index = key_index
        self.flags = flags
        self.iv_index = iv_index
        self.unicast_addr = unicast_addr
        self.provisionning_crypto_manager = provisionning_crypto_manager


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
    :type address: Bytes
    :returns: The type of the address (constant values in whad.btmesh.stack.constants)
    :rtype: int
    """

    if address == 0:
        return UNASSIGNED_ADDR_TYPE
    if (address[0] >> 6) & 0b10 == 0x00:
        return UNICAST_ADDR_TYPE
    if (address[0] >> 6) == 0b10:
        return VIRTUAL_ADDR_TYPE

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
    # Initialize an empty bytearray to hold the result
    byte_array = bytearray()

    # Process pairs of integers
    for i in range(0, len(ints), 2):
        if i + 1 < len(ints):
            # Pack two integers
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

            # Pack them into 3 bytes (little-endian)
            packed = (
                first_int << 12
            ) | second_int  # Combine into a single 24-bit integer
            byte_array.append(packed & 0xFF)  # Least significant byte
            byte_array.append((packed >> 8) & 0xFF)  # Middle byte
            byte_array.append((packed >> 16) & 0xFF)  # Most significant byte
        else:
            # Handle the last integer if the count is odd
            last_int = ints[i]

            # Ensure the integer is within 12 bits
            if last_int < 0 or last_int >= 4096:
                raise ValueError("Integer must be in the range 0 to 4095 (12 bits).")

            # Pack the last integer into 2 bytes with 4 bits of padding
            packed = last_int << 4  # Shift left by 4 bits for padding
            byte_array.append(packed & 0xFF)  # Least significant byte
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

    # Initialize an empty list to hold the unpacked integers
    ints = []
    if packed_keys is None or packed_keys == []:
        return []

    packed_bytes = packed_keys
    # Process the packed bytes in chunks of 3
    for i in range(0, len(packed_bytes) - 2, 3):
        # Read 3 bytes
        byte1 = packed_bytes[i]
        byte2 = packed_bytes[i + 1]
        byte3 = packed_bytes[i + 2]

        # Combine the bytes into two integers
        packed = (
            (byte3 << 16) | (byte2 << 8) | byte1
        )  # Combine into a single 24-bit integer

        # Extract the two integers
        first_int = (packed >> 12) & 0xFFF  # Get the first 12 bits
        second_int = packed & 0xFFF  # Get the last 12 bits

        # Append the integers to the list
        ints.append(first_int)
        ints.append(second_int)

    # Handle the last 2 bytes if the total number of bytes is odd
    if len(packed_bytes) % 3 == 2:
        # Read the last 2 bytes
        byte1 = packed_bytes[-2]
        byte2 = packed_bytes[-1]

        # Combine the bytes into the last integer
        packed = (byte2 << 8) | byte1  # Combine into a single 16-bit integer

        # Extract the last integer (with 4 bits of padding)
        last_int = (packed >> 4) & 0xFFF  # Get the 12 bits of the last integer
        ints.append(last_int)  # Append the last integer

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
