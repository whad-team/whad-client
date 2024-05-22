from whad.dot15d4.stack.mac.constants import MACAddressMode

class ZCLClusterConfiguration:
    """
    This class defines the current configuration for a Zigbee Cluster Library cluster.
    """
    def __init__(   self,
                    destination_address_mode = None,
                    destination_address = None,
                    destination_endpoint = None,
                    transaction = None,
                    alias_address=None,
                    alias_sequence_number=0,
                    radius=30,
                    security_enabled_transmission=False,
                    use_network_key=True,
                    acknowledged_transmission=False,
                    fragmentation_permitted=False,
                    include_extended_nonce=False,
                    disable_default_response=False,
                    interpan=False,
                    asdu_handle=0,
                    source_address_mode=MACAddressMode.EXTENDED,
                    destination_pan_id=0xFFFF
    ):
        self.destination_address_mode = destination_address_mode
        self.destination_address = destination_address
        self.destination_endpoint = destination_endpoint
        self.transaction = transaction
        self.alias_address = alias_address
        self.alias_sequence_number = alias_sequence_number
        self.radius = radius
        self.security_enabled_transmission = security_enabled_transmission
        self.use_network_key = use_network_key
        self.acknowledged_transmission = acknowledged_transmission
        self.fragmentation_permitted = fragmentation_permitted
        self.include_extended_nonce = include_extended_nonce
        self.disable_default_response = disable_default_response
        self.interpan = interpan
        self.asdu_handle=asdu_handle
        self.source_address_mode=source_address_mode
        self.destination_pan_id=destination_pan_id
