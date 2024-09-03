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
