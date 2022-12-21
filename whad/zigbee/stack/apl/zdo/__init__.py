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
            "zdo_device_annce": ZDODeviceAndServiceDiscovery.ZDODeviceAnnce(self.device_and_service_discovery),
            "zdo_node_desc_req": ZDODeviceAndServiceDiscovery.ZDONodeDescReq(self.device_and_service_discovery),
            "zdo_node_desc_rsp": ZDODeviceAndServiceDiscovery.ZDONodeDescRsp(self.device_and_service_discovery),
            "zdo_nwk_addr_req":ZDODeviceAndServiceDiscovery.ZDONWKAddrReq(self.device_and_service_discovery),
            "zdo_ieee_addr_req":ZDODeviceAndServiceDiscovery.ZDOIEEEAddrReq(self.device_and_service_discovery),
            "zdo_ieee_addr_rsp":ZDODeviceAndServiceDiscovery.ZDOIEEEAddrRsp(self.device_and_service_discovery),
            "zdo_active_ep_req":ZDODeviceAndServiceDiscovery.ZDOActiveEPReq(self.device_and_service_discovery),
            "zdo_active_ep_rsp":ZDODeviceAndServiceDiscovery.ZDOActiveEPRsp(self.device_and_service_discovery),
            "zdo_simple_desc_req":ZDODeviceAndServiceDiscovery.ZDOSimpleDescReq(self.device_and_service_discovery),
            "zdo_simple_desc_rsp":ZDODeviceAndServiceDiscovery.ZDOSimpleDescRsp(self.device_and_service_discovery),
        }

    def __init__(self):

        self.configuration = ConfigurationDatabase()
        self.security_manager = ZDOSecurityManager(self)
        self.network_manager = ZDONetworkManager(self)
        self.device_and_service_discovery = ZDODeviceAndServiceDiscovery(self)

        self.setup_clusters()
        super().__init__(
            "zdo",
            0x0000,
            0x0000,
            device_version=0,
            input_clusters=[
                            self.clusters["zdo_node_desc_req"],
                            self.clusters["zdo_ieee_addr_rsp"],
                            self.clusters["zdo_node_desc_rsp"],
                            self.clusters["zdo_active_ep_rsp"],
                            self.clusters["zdo_simple_desc_rsp"],

            ],
            output_clusters=[
                            self.clusters["zdo_nwk_addr_req"],
                            self.clusters["zdo_active_ep_req"],
                            self.clusters["zdo_ieee_addr_req"],
                            self.clusters["zdo_device_annce"],
                            self.clusters["zdo_node_desc_rsp"],
                            self.clusters["zdo_simple_desc_req"],
            ]
        )


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
