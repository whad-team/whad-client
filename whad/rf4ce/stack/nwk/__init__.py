from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.dot15d4.stack.mac.constants import MACAddressMode
from whad.rf4ce.stack.nwk.exceptions import NWKTimeoutException
from whad.rf4ce.stack.nwk.database import NWKIB
from whad.scapy.layers.rf4ce import RF4CE_Command_Hdr, RF4CE_Cmd_Discovery_Request, \
    RF4CE_Cmd_Discovery_Response, RF4CE_Hdr
from whad.common.stack import Layer, alias, source, state

from time import time

import logging

logger = logging.getLogger(__name__)

class NWKService(Dot15d4Service):
    """
    This class represents a NWK service, exposing a standardized API.
    """
    def __init__(self, manager, name=None):
        super().__init__(
            manager,
            name=name,
            timeout_exception_class=NWKTimeoutException
        )

class NWKDataService(NWKService):
    """
    NWK service forwarding data packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="nwk_data")


    def on_data_npdu(self, npdu, link_quality=255):
        """
        Callback processing NPDU from NWK manager.

        It forwards the NPDU to indicate_data method.
        """
        npdu.show()
        self.indicate_data(npdu, link_quality=link_quality)

    @Dot15d4Service.indication("NLDE-DATA")
    def indicate_data(self, npdu, link_quality=255):
        """
        Indication transmitting NPDU to upper layer.
        """
        pass


class NWKManagementService(NWKService):
    """
    NWK service forwarding management packets.
    """
    def __init__(self, manager):
        super().__init__(manager, name="nwk_management")


    @Dot15d4Service.request("NLME-AUTO-DISCOVERY")
    def auto_discovery(self, user_string_specificied=False, list_of_device_types=[1], list_of_profiles=[192], duration=15*50000*(10**6)): # ~ 15s
        """
        Request allowing NWK layer to auto respond to discovery requests.
        """
        duration_us = duration * self.manager.get_layer('phy').symbol_duration

        start = (time()*(10**6))
        match = 0
        while (time()*(10**6)) - start < duration_us:
            try:
                device_type_found = False
                profile_id_found = False

                discovery = self.wait_for_packet(lambda pkt:RF4CE_Cmd_Discovery_Request in pkt, timeout=0.01)
                discovery.show()
                for device_type in discovery.device_type_list:
                    if device_type in list_of_device_types:
                        device_type_found = True
                        break
                for profile_id in discovery.profile_identifier_list:
                    if profile_id in list_of_profiles:
                        profile_id_found = True
                        break

                if device_type_found and profile_id_found:
                    match += 1
                else:
                    match = 0

                if match == 2:
                    # Build a discovery response
                    discovery_response = (
                        RF4CE_Hdr(security_enabled = 0) /
                        RF4CE_Command_Hdr() /
                        RF4CE_Cmd_Discovery_Response(
                            status = 0,
                            channel_normalization_capable = 1,
                            security_capable = 1,
                            power_source = "battery_source",
                            node_type = "target",
                            vendor_identifier = self.database.get("nwkVendorIdentifier"),
                            vendor_string = self.database.get("nwkVendorString"),
                            number_of_supported_profiles = len(list_of_profiles),
                            profile_identifier_list = list_of_profiles,
                            number_of_supported_device_types = len(list_of_device_types),
                            device_type_list = list_of_device_types,
                            user_string_specificied = int(self.database.get("nwkUserString") is not None),
                            user_string = self.database.get("nwkUserString"),
                            discovery_req_lqi = discovery.link_quality
                        )
                    )
                    self.manager.get_layer('mac').get_service("data").data(
                        discovery_response,
                        destination_address_mode=MACAddressMode.EXTENDED,
                        source_address_mode=MACAddressMode.EXTENDED,
                        destination_pan_id=0xFFFF,
                        destination_address=discovery.source_address,
                        wait_for_ack=True
                    )
                    discovery_response.show()
            except NWKTimeoutException:
                pass
        print("end")

    def on_command_npdu(self, pdu, source_address, link_quality=255):
        pdu.link_quality = link_quality
        pdu.source_address = source_address
        self.add_packet_to_queue(pdu)


@state(NWKIB)
@alias('nwk')
class NWKManager(Dot15d4Manager):
    """
    This class implements the RF4CE Network manager (NWK).
    It handles network-level operations, such as discovery, association or network initiation.

    It exposes two services providing the appropriate API.
    """
    def init(self):
        self.add_service("data", NWKDataService(self))
        self.add_service("management", NWKManagementService(self))



    @source('mac', 'MCPS-DATA')
    def on_mcps_data(self, pdu, destination_pan_id, destination_address, source_pan_id, source_address, link_quality):
        """
        Callback processing MAC MCPS Data indication.
        """
        if pdu.frame_type == 1:
            self.get_service('data').on_data_npdu(pdu, link_quality)
        elif pdu.frame_type == 2:
            self.get_service('management').on_command_npdu(pdu, source_address, link_quality)

#NWKManager.add(APSManager)
