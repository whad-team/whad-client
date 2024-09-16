"""
Classes used between layers to manage a message.
"""

from whad.bt_mesh.stack.constants import (
    VIRTUAL_ADDR_TYPE,
    GROUP_ADDR_TYPE,
    UNICAST_ADDR_TYPE,
    UNASSIGNED_ADDR_TYPE,
)


class MeshMessageContext:
    def __init__(self):
        self.src_addr = None
        self.dest_addr = None

        # Should be equal to the segment segment number before the Upper Transport Layer.
        # After that should be equal to the segment number of segment 0 (if segmented message)
        self.seq_number = None

        # 1 if app_key used, 0 if devic key
        self.application_key_flag = None

        # AID of the app_key if app_key used, 0 id device_key used
        self.application_key_id = None

        # If src_addr is Virtual Addr
        self.uuid = None

        # Either received TTL or sending TTL
        self.ttl = None

        # Either received RSSI or sending RSSI
        self.rssi = None


def get_address_type(address):
    """
    Utils function returning the type of the address in argument (virtual, group or unicast)

    :param address: The address to check
    :type address: Bytes
    :returns: The type of the address (constant values in whad.bt_mesh.stack.constants)
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
