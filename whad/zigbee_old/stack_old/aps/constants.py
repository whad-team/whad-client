from enum import IntEnum

class APSSourceAddressMode(IntEnum):
    """
    Enum representing the different APS source address modes supported by Zigbee.
    """
    SHORT_ADDRESS_SRC_ENDPOINT_PRESENT = 0x02
    EXTENDED_ADDRESS_SRC_ENDPOINT_PRESENT = 0x03
    EXTENDED_ADDRESS_SRC_ENDPOINT_NOT_PRESENT = 0x04


class APSDestinationAddressMode(IntEnum):
    """
    Enum representing the different APS destination address modes supported by Zigbee.
    """
    DST_ADDRESS_AND_DST_ENDPOINT_NOT_PRESENT = 0x00
    SHORT_GROUP_ADDRESS_DST_ENDPOINT_NOT_PRESENT = 0x01
    SHORT_ADDRESS_DST_ENDPOINT_PRESENT = 0x02
    EXTENDED_ADDRESS_DST_ENDPOINT_PRESENT = 0x03
    EXTENDED_ADDRESS_DST_ENDPOINT_NOT_PRESENT = 0x04


class APSKeyAttribute(IntEnum):
    """
    This enum stores the different possible values for the APS key attribute.
    """
    PROVISIONAL_KEY = 0
    UNVERIFIED_KEY = 1
    VERIFIED_KEY = 2

class APSSecurityStatus(IntEnum):
    """
    This enum stores the different possible values for the APS security status.
    """
    UNSECURED = 0
    SECURED_NWK_KEY = 1
    SECURED_LINK_KEY = 2

class APSTransportKeyData:
    """
    This class allows to transport security material from the APS to the ZDO layer.
    """
    def __init__(self, key):
        self.key = key

class APSTrustCenterLinkKeyData(APSTransportKeyData):
    """
    Specializes APSTransportKeyData class to store a Trust Center Link Key and its related data.
    """
    pass

class APSNetworkKeyData(APSTransportKeyData):
    """
    Specializes APSTransportKeyData class to store a Network Key and its related data.
    """
    def __init__(self, key, key_sequence_number, use_parent, parent_address=None):
        super().__init__(key)
        self.key_sequence_number = key_sequence_number
        self.use_parent = use_parent
        self.parent_address = parent_address

class APSApplicationLinkKeyData(APSTransportKeyData):
    """
    Specializes APSTransportKeyData class to store an Applicatino Key and its related data.
    """
    def __init__(self, key, partner_address):
        super().__init__(key)
        self.partner_address = partner_address

class APSKeyPair:
    """
    Implements a Key-Pair descriptor, needed to implement APS security features.
    """
    def __init__(self, device_address, key, key_attributes=APSKeyAttribute.PROVISIONAL_KEY, outgoing_frame_counter=0, incoming_frame_counter=0, global_link_key=False):
        self.device_address = device_address
        self.key = key
        self.key_attributes = key_attributes
        self.outgoing_frame_counter = outgoing_frame_counter
        self.incoming_frame_counter = incoming_frame_counter
        self.global_link_key = global_link_key

    def __repr__(self):
        if self.device_address is not None:
            return "APSKeyPair(device={:016x}, key={})".format(self.device_address, self.key)
        else:
            return "APSKeyPair(pre-installed, key={})".format(self.key)

class APSKeyPairSet:
    """
    Implement a set of APSKeyPair, providing an easy-to-use API to manipulate it.
    """
    def __init__(self, preinstalled_keys=[b"ZigBeeAlliance09"]):
        self.key_pair_set = []
        for preinstalled_key in preinstalled_keys:
            self.key_pair_set.append(
                APSKeyPair(
                    None,
                    preinstalled_key,
                    key_attributes=APSKeyAttribute.PROVISIONAL_KEY,
                    outgoing_frame_counter=0,
                    incoming_frame_counter=0,
                    global_link_key=True
                )
            )

    def select(self, address, unverified=True):
        matching_key_pairs = []
        preinstalled_keys = []
        for key_pair in self.key_pair_set:
            if unverified or not unverified and key_pair.key_attributes in (APSKeyAttribute.PROVISIONAL_KEY, APSKeyAttribute.VERIFIED_KEY):
                if key_pair.device_address == address:
                    matching_key_pairs.append(key_pair)
                elif key_pair.device_address is None:
                    preinstalled_keys.append(key_pair)

        if len(matching_key_pairs) == 0:
            matching_key_pairs += preinstalled_keys

        return matching_key_pairs
