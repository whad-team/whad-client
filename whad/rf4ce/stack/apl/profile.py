from whad.dot15d4.stack.service import Dot15d4Service
from whad.rf4ce.stack.apl.exceptions import APLTimeoutException

class APLProfile(Dot15d4Service):
    """
    This class represents a APL profile, exposing a standardized API.
    """
    def __init__(self, name=None, profile_id=None):
        self.profile_id = profile_id
        super().__init__(
            manager=None,
            name=name,
            timeout_exception_class=APLTimeoutException
        )

    def attach(self, manager):
        """
        Attach this profile to the manager.
        """
        self.manager = manager

    def init(self):
        """
        Initialize the APL profile.
        """
        pass

    def on_data(self, npdu, pairing_reference, vendor_id, link_quality, rx_flags):
        """
        Callback processing incoming data for the profile.
        """
        pass

    def on_discovery(self, status, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, requested_device_type, link_quality):
        """
        Callback processing incoming discovery request for the profile.
        """
        pass

    def on_pair(self, status, source_pan_id, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, key_exchange_transfer_count, pairing_reference):
        """
        Callback processing incoming pairing request for the profile.
        """
        pass
