from whad.zigbee.stack.apl.zdo.discovery import ZDODeviceAndServiceDiscovery
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

        # Configure application parameters
        super().__init__(
            "zdo",  # name
            0x0000, # profile ID
            0x0000, # device ID
            device_version=0,
            input_clusters = [

            ],
            output_clusters = [

            ]
        )

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
