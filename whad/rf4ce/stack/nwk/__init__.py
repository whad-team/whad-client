from whad.dot15d4.stack.manager import Dot15d4Manager
from whad.dot15d4.stack.service import Dot15d4Service
from whad.zigbee.stack.nwk.exceptions import NWKTimeoutException
from whad.zigbee.stack.nwk.database import NWKIB
from whad.common.stack import Layer, alias, source, state
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
    def auto_discovery(self, user_string_specificied=False, list_of_device_types=[], list_of_profiles=[]):
        """
        Request allowing NWK layer to auto respond to discovery requests.
        """
        pass

    def on_command_npdu(self, pdu, link_quality=255):
        print("CMD PDU")
        pdu.show()

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
            self.get_service('management').on_command_npdu(pdu, link_quality)

#NWKManager.add(APSManager)
