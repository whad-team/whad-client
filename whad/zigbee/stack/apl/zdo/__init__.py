from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.zdo.discovery_manager import ZDODeviceAndServiceDiscovery
from whad.zigbee.stack.apl.zdo.network_manager import ZDONetworkManager
from whad.zigbee.stack.apl.zdo.security_manager import ZDOSecurityManager
from whad.zigbee.stack.apl.zdo.descriptors import NodeDescriptor
from whad.zigbee.stack.database import Dot15d4Database
from time import sleep
import logging

logger = logging.getLogger(__name__)


class ConfigurationDatabase(Dot15d4Database):
    def reset(self):
        self.configNodeDescriptor = NodeDescriptor()
        self.configNWKScanAttempts = 5
        self.configNWKTimeBetweenScans = 0xc35

class ZigbeeDeviceObjects(ApplicationObject):

    def setup_clusters(self):
        self.clusters = {
            "zdo_device_annce": ZDODeviceAndServiceDiscovery.ZDODeviceAnnce(),
            "zdo_node_desc_req": ZDODeviceAndServiceDiscovery.ZDONodeDescReq(),
            "zdo_node_desc_rsp": ZDODeviceAndServiceDiscovery.ZDONodeDescRsp(),
            "zdo_nwk_addr_req":ZDODeviceAndServiceDiscovery.ZDONWKAddrReq(),
            "zdo_ieee_addr_req":ZDODeviceAndServiceDiscovery.ZDOIEEEAddrReq()
        }

    def __init__(self):
        self.setup_clusters()
        super().__init__(
            "zdo",
            0x0000,
            0x0000,
            device_version=0,
            input_clusters=[
                            self.clusters["zdo_node_desc_req"]
            ],
            output_clusters=[
                            self.clusters["zdo_nwk_addr_req"],
                            self.clusters["zdo_ieee_addr_req"],
                            self.clusters["zdo_device_annce"],
                            self.clusters["zdo_node_desc_rsp"],

            ]
        )
        self.configuration = ConfigurationDatabase()
        self.security_manager = ZDOSecurityManager(self)
        self.network_manager = ZDONetworkManager(self)
        self.device_and_service_discovery = ZDODeviceAndServiceDiscovery(self)


    def configure(self, attribute_name, attribute_value):
        return self.configuration.set(attribute_name, attribute_value)

    def initialize(self):
        self.network_manager.initialize()

    def start(self):
        self.network_manager.startup()

    @property
    def nwk_management(self):
        return self.manager.nwk.get_service("management")

    @property
    def aps_management(self):
        return self.manager.aps.get_service("management")

    def on_transport_key(self, source_address, standard_key_type, transport_key_data):
        self.security_manager.on_transport_key(source_address, standard_key_type, transport_key_data)
