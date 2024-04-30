from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.rf4ce.stack.apl.database import APLIB
from whad.common.stack import Layer, alias, source, state

import logging

logger = logging.getLogger(__name__)

@state(APLIB)
@alias('apl')
class APLManager(Dot15d4Manager):
    """
    This class implements the RF4CE Application manager (APL).
    It handles application-level operations and provide an high level API for network features.

    It exposes several services (e.g. "RF4CE profiles") providing a more specialized API.
    """
    def init(self):
        """
        Initialize the APL manager.

        The APL manager is associated to one or several profiles, that specialize its API
        to manipulate the lowest layers.
        """
        self.profiles = {}

    def add_profile(self, profile):
        """
        Add a profile to the APL manager.
        """
        # print("[i] Adding profile (",profile.profile_id ,profile.name ,")")
        self.profiles[profile.profile_id] = profile
        self.add_service(profile.name, profile)
        profile.attach(self)
        profile.init()

    def get_profile_by_name(self, profile_name):
        """
        Returns a profile associated to the APL manager by its name.
        """
        return self.get_service(profile_name)

    def get_profile_by_profile_id(self, profile_id):
        """
        Returns a profile associated to the APL manager by its profile ID.
        """
        if profile_id in self.profiles.keys():
            return self.profiles[profile_id]
        else:
            return None

    @source('nwk', 'NLDE-DATA')
    def on_nlde_data(self, npdu, pairing_reference, profile_id, vendor_id, link_quality, rx_flags):
        '''
        print("[i] Incoming data at APL layer", repr(npdu))
        print("    | -> pairing_reference", pairing_reference)
        print("    | -> profile_id", hex(profile_id))
        print("    | -> vendor_id", hex(vendor_id))
        print("    | -> link_quality", link_quality)
        print("    | -> rx_flags", rx_flags)
        '''
        profile = self.get_profile_by_profile_id(npdu.profile_id)
        if profile is not None:
            #print("[i] Forwarding to profile ", profile.name)
            profile.on_data(npdu, pairing_reference, vendor_id, link_quality, rx_flags)
        else:
            pass
            #print("[i] No profile found, dropping.")

    @source('nwk', 'NLME-DISCOVERY')
    def on_nlme_discovery(self, status, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, requested_device_type, link_quality):
        '''
        print("[i] Incoming discovery -> status  = ", status)
        print("    | -> source_address", hex(source_address))
        print("    | -> node_capability", node_capability)
        print("    | -> vendor_identifier", hex(vendor_identifier))
        print("    | -> vendor_string", vendor_string)
        print("    | -> application_capability", application_capability)
        print("    | -> user_string", user_string)
        print("    | -> device_type_list", device_type_list)
        print("    | -> profile_identifier_list", profile_identifier_list)
        print("    | -> requested_device_type", requested_device_type)
        print("    | -> link_quality", link_quality)
        '''
        for profile_id in profile_identifier_list:
            profile = self.get_profile_by_profile_id(profile_id)
            if profile is not None:
                #print("[i] Forwarding to profile ", profile.name)
                profile.on_discovery(status, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, requested_device_type, link_quality)
            else:
                pass
                #print("[i] No profile found, dropping.")

    @source('nwk', 'NLME-PAIR')
    def on_nlme_pair(self, status, source_pan_id, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, key_exchange_transfer_count, pairing_reference):
        '''
        print("[i] Incoming pairing -> status  = ", status)
        print("    | -> source_address", hex(source_address))
        print("    | -> node_capability", node_capability)
        print("    | -> vendor_identifier", hex(vendor_identifier))
        print("    | -> vendor_string", vendor_string)
        print("    | -> application_capability", application_capability)
        print("    | -> user_string", user_string)
        print("    | -> device_type_list", device_type_list)
        print("    | -> profile_identifier_list", profile_identifier_list)
        print("    | -> key_exchange_transfer_count", key_exchange_transfer_count)
        print("    | -> pairing_reference", pairing_reference)
        '''
        for profile_id in profile_identifier_list:
            profile = self.get_profile_by_profile_id(profile_id)
            if profile is not None:
                #print("[i] Forwarding to profile ", profile.name)
                profile.on_pair(status, source_pan_id, source_address, node_capability, vendor_identifier, vendor_string, application_capability, user_string, device_type_list, profile_identifier_list, key_exchange_transfer_count, pairing_reference)
            else:
                pass
                #print("[i] No profile found, dropping.")


    @source('nwk', 'NLME-COMM-STATUS')
    def on_nlme_comm_status(self, status, pairing_reference, pan_id, destination_address_mode, destination_address):
        '''
        print("[i] Incoming communication status -> status = ", status)
        print("    | -> pairing_reference", pairing_reference)
        print("    | -> pan_id", hex(pan_id))
        print("    | -> destination_address_mode", destination_address_mode)
        print("    | -> destination_address", hex(destination_address))
        '''
        pass
