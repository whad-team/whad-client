from whad.zigbee.stack.apl.zdo.discovery import ZDODeviceAndServiceDiscovery
from whad.zigbee.stack.apl.zdo.discovery.clusters import ZDODeviceAnnce, ZDONodeDescReq, \
    ZDONodeDescRsp, ZDONWKAddrReq, ZDONWKAddrRsp, ZDOIEEEAddrReq, ZDOIEEEAddrRsp, \
    ZDOActiveEPReq, ZDOActiveEPRsp, ZDOSimpleDescReq, ZDOSimpleDescRsp

from whad.zigbee.stack.apl.zdo.network import ZDONetworkManager
from whad.zigbee.stack.apl.zdo.security import ZDOSecurityManager
from whad.zigbee.stack.apl.zdo.database import ConfigurationDatabase
from whad.zigbee.stack.apl.application import ApplicationObject

import logging

logger = logging.getLogger(__name__)

class ZigbeeDeviceObjects(ApplicationObject):
    """
    Application object representing Zigbee Device Objects.

    This app is the main entry point for managing the stack. It handles:
     - a specific database, storing the current configuration
     - the ZDO Network Manager, handling the network operations
     - the ZDO Security Manager, handling the security related operations
     - the ZDO Devices and Discovery Manager, handling the identification of
       surrounding devices and the discovery process of their apps & services.
    """
    def __init__(self):
        # Initialize the configuration database
        self.configuration = ConfigurationDatabase()

        # Initializes the managers
        self.security_manager = ZDOSecurityManager(self)
        self.network_manager = ZDONetworkManager(self)
        self.device_and_service_discovery = ZDODeviceAndServiceDiscovery(self)

        # Initialize ZDP clusters
        self.setup_clusters()

        # Configure application parameters
        super().__init__(
            "zdo",  # name
            0x0000, # profile ID
            0x0000, # device ID
            device_version=0,
            input_clusters=[
                self.clusters["node_desc_req"],
                self.clusters["node_desc_rsp"],
                self.clusters["ieee_addr_req"],
                self.clusters["nwk_addr_rsp"],
                self.clusters["ieee_addr_rsp"],
                self.clusters["active_ep_req"],
                self.clusters["active_ep_rsp"],
                self.clusters["simple_desc_req"],
                self.clusters["simple_desc_rsp"],
            ],
            output_clusters=[
                self.clusters["nwk_addr_req"],
                self.clusters["active_ep_req"],
                self.clusters["active_ep_rsp"],
                self.clusters["ieee_addr_req"],
                self.clusters["device_annce"],
                self.clusters["node_desc_req"],
                self.clusters["node_desc_rsp"],
                self.clusters["simple_desc_req"],
                self.clusters["simple_desc_rsp"],
            ]
        )


    def setup_clusters(self):
        self.clusters = {
            "device_annce"      : ZDODeviceAnnce(self.device_and_service_discovery),
            "node_desc_req"     : ZDONodeDescReq(self.device_and_service_discovery),
            "node_desc_rsp"     : ZDONodeDescRsp(self.device_and_service_discovery),
            "nwk_addr_req"      : ZDONWKAddrReq(self.device_and_service_discovery),
            "nwk_addr_rsp"      : ZDONWKAddrRsp(self.device_and_service_discovery),
            "ieee_addr_req"     : ZDOIEEEAddrReq(self.device_and_service_discovery),
            "ieee_addr_rsp"     : ZDOIEEEAddrRsp(self.device_and_service_discovery),
            "active_ep_req"     : ZDOActiveEPReq(self.device_and_service_discovery),
            "active_ep_rsp"     : ZDOActiveEPRsp(self.device_and_service_discovery),
            "simple_desc_req"   : ZDOSimpleDescReq(self.device_and_service_discovery),
            "simple_desc_rsp"   : ZDOSimpleDescRsp(self.device_and_service_discovery),
        }

    def initialize(self):
        """
        Initializes the ZDO managers.
        """
        self.network_manager.initialize()

    def start(self):
        """
        Starts the ZDO managers.
        """
        self.network_manager.startup()

    def configure(self, attribute_name, attribute_value):
        """
        Configures the value of a specific attribute in the database.
        """
        return self.configuration.set(attribute_name, attribute_value)

    def on_join(
                            self,
                            network_address,
                            extended_address,
                            capability_information,
                            rejoin=False,
                            secure_rejoin=False
    ):
        """
        Forwards new device join notification.
        """
        self.security_manager.send_transport_key(
            network_address
        )

    def on_transport_key(
                            self,
                            source_address,
                            standard_key_type,
                            transport_key_data
    ):
        """
        Forwards the transport key to the security manager.
        """
        self.security_manager.on_transport_key(
            source_address,
            standard_key_type,
            transport_key_data
        )

    # Helpers
    @property
    def nwk_management(self):
        """
        Shortcut for accessing the NWK management service.
        """
        return self.manager.get_layer('nwk').get_service('management')

    @property
    def aps_management(self):
        """
        Shortcut for accessing the APS management service.
        """
        return self.manager.get_layer('aps').get_service('management')
