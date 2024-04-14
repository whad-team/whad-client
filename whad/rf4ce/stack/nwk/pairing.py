from enum import IntEnum


class PairingEntryStatus(IntEnum):
    """
    List of possible status for a pairing entry.
    """
    PROVISIONAL = 1
    ACTIVE = 2

class PairingEntry:
    """
    Defines a pairing table entry.
    """
    def __init__(self, source_network_address, channel, destination_ieee_address, destination_pan_id, destination_network_address, capabilities, frame_counter, link_key):
        self.source_network_address = source_network_address
        self.channel = channel
        self.destination_ieee_address= destination_ieee_address
        self.destination_network_address = destination_network_address
        self.destination_pan_id = destination_pan_id
        self.capabilities = capabilities
        self.frame_counter = frame_counter
        self.link_key = link_key
        self.status = PairingEntryStatus.PROVISIONAL


    def is_active(self):
        """
        Returns a boolean indicating if entry is active.
        """
        return self.status == PairingEntryStatus.ACTIVE
        
    def mark_as_active(self):
        """
        Mark this entry as active.
        """
        self.status = PairingEntryStatus.ACTIVE
