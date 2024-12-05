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


class MeshMessageContext:
    def __init__(self):
        self.src_addr = None
        self.dest_addr = None

        # Credentials used at the network layer (managed flooding or directed forwarding) (frienship creds not supported)
        self.creds = MANAGED_FLOODING_CREDS

        # Should be equal to the sequence number of the PDU
        self.seq_number = None

        # if segmentention used in Lower transport layer, set to the segment number
        self.segment_number = None

        # AID of the app_key if app_key used, -1 if device_key used
        self.aid = None

        # Index of the app key if not device_key used
        self.application_key_index = None

        # Net key id used
        self.net_key_id = None

        # lower transport value (size of mic)
        self.azsmic = 0

        # If src_addr is Virtual Addr
        self.uuid = None

        # Either received TTL or sending TTL
        self.ttl = None

        # True if Upper Transport Control Message/Ack messgae (network_ctl field to 1), false otherwise
        self.is_ctl = None

        # Seq auth value set by the Upper Transport Layer when encrypting the access pdu
        # Set by the Network layer on Rx messages
        # int !
        self.seq_auth = None

        # Set by model layer, if the message is too small to be segmented but still want acknowlegment on network layer
        self.force_segment = False

        # Received RSSI of a packet (sending RSSI when feature available for Adv mode)
        self.rssi = None

    def print(self):
        for attribute, value in self.__dict__.items():
            print(attribute, "=", value)


class Subnet(StatesManager):
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
    if (address[0] >> 6) & 0x10 == 0x00:
        return UNICAST_ADDR_TYPE
    if (address[0] >> 6 & 0x11) == 0b10:
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

    """
    # Compute the 14-bit and 13-bit masks
    seq_mask_14 = (1 << 14) - 1
    seq_mask_13 = (1 << 13) - 1

    # Compute the sequence adjustment from seq_zero
    seq_diff = ((seq & seq_mask_14) - seq_zero) & seq_mask_13

    adjusted_seq = seq - seq_diff
    """

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
