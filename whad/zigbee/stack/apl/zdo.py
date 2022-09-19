from whad.zigbee.stack.apl.application import ApplicationObject
from whad.zigbee.stack.apl.cluster import Cluster
from whad.zigbee.stack.database import Dot15d4Database
from whad.zigbee.stack.nwk.constants import NWKJoinMode, NetworkSecurityMaterial
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.mac.constants import MACDeviceType, MACPowerSource
from whad.zigbee.stack.constants import SYMBOL_DURATION, Dot15d4Phy
from scapy.layers.zigbee import  ZigbeeDeviceProfile
from whad.scapy.layers.zdp import ZDPDeviceAnnce, ZDPNodeDescReq, ZDPNodeDescRsp
from .constants import LogicalDeviceType
from time import sleep
import logging

logger = logging.getLogger(__name__)

class NodeDescriptor:
    def __init__(self):
        self.logical_type = LogicalDeviceType.END_DEVICE
        self.complex_descriptor_available = False
        self.user_descriptor_available = False
        self.aps_flags = 0
        self.support_868_mhz = False
        self.support_902_mhz = False
        self.support_2400_mhz = True
        self.alternate_pan_coordinator = False
        self.device_type = MACDeviceType.FFD
        self.power_source = MACPowerSource.ALTERNATING_CURRENT_SOURCE
        self.receiver_on_when_idle = True
        self.security_capability = True
        self.allocate_address = False
        self.manufacturer_code = 0x1234
        self.max_buffer_size = 128
        self.max_incoming_transfer_size = 128
        self.server_primary_trust_center = False
        self.server_backup_trust_center = False
        self.server_primary_binding_table_cache = False
        self.server_backup_binding_table_cache = False
        self.server_primary_discovery_cache = False
        self.server_backup_discovery_cache = False
        self.network_manager = False
        self.stack_compliance_revision = 21
        self.max_outgoing_transfer_size = 128
        self.extended_active_endpoint_list_available = False
        self.extended_simple_descriptors_list_available = False

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
            "zdo_node_desc_rsp": ZDODeviceAndServiceDiscovery.ZDONodeDescRsp()

        }

    def __init__(self):
        self.setup_clusters()
        super().__init__(
            "zdo",
            0x0000,
            0x0000,
            application_device_version=0,
            input_clusters=[
                            self.clusters["zdo_node_desc_req"]
            ],
            output_clusters=[
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

class ZDOObject:
    def __init__(self, zdo):
        self.zdo = zdo

class ZDODeviceAndServiceDiscovery(ZDOObject):

    def device_annce(self, transaction=0):
        self.zdo.clusters["zdo_device_annce"].generate(transaction)

    class ZDODeviceAnnce(Cluster):
        def __init__(self):
            super().__init__(cluster_id=0x0013)

        def generate(self, transaction=0):
            node_descriptor = self.application.configuration.get("configNodeDescriptor")
            command =  ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPDeviceAnnce(
                nwk_addr = self.application.manager.nwk.database.get("nwkNetworkAddress"),
                ieee_addr = self.application.manager.nwk.database.get("nwkIeeeAddress"),
                allocate_address = int(node_descriptor.allocate_address),
                security_capability = int(node_descriptor.security_capability),
                receiver_on_when_idle = int(node_descriptor.receiver_on_when_idle),
                power_source = int(node_descriptor.power_source),
                device_type = int(node_descriptor.logical_type),
                alternate_pan_coordinator = int(node_descriptor.alternate_pan_coordinator)
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=0xfffd, use_network_key=True, destination_endpoint=0)

    def node_desc_req(self, address, transaction=0):
        self.zdo.clusters["zdo_node_desc_req"].generate(address, transaction)

    class ZDONodeDescReq(Cluster):
        def __init__(self):
            super().__init__(cluster_id=0x0002)

        def generate(self, address, transaction=0):
            command =  ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPNodeDescReq(
                nwk_addr = address
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=address, use_network_key=True, destination_endpoint=0)

        def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
            self.application.clusters["zdo_node_desc_rsp"].generate(source_address, asdu.trans_seqnum)


    def node_desc_rsp(self, address, transaction=0):
        self.zdo.clusters["zdo_node_desc_rsp"].generate(address, transaction)

    class ZDONodeDescRsp(Cluster):
        def __init__(self):
            super().__init__(cluster_id=0x8002)

        def generate(self, address, transaction=0):
            node_descriptor = self.application.configuration.get("configNodeDescriptor")

            command =  ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPNodeDescRsp(
                status = 0,
                nwk_addr = self.application.manager.nwk.database.get("nwkNetworkAddress"),
                logical_type = int(node_descriptor.logical_type),
                complex_descriptor_available = int(node_descriptor.complex_descriptor_available),
                user_descriptor_available = int(node_descriptor.user_descriptor_available),
                aps_flags = int(node_descriptor.aps_flags),
                support_868_mhz=int(node_descriptor.support_868_mhz),
                support_902_mhz=int(node_descriptor.support_902_mhz),
                support_2400_mhz=int(node_descriptor.support_2400_mhz),
                allocate_address = int(node_descriptor.allocate_address),
                security_capability = int(node_descriptor.security_capability),
                receiver_on_when_idle = int(node_descriptor.receiver_on_when_idle),
                power_source = int(node_descriptor.power_source),
                device_type = int(node_descriptor.device_type),
                alternate_pan_coordinator = int(node_descriptor.alternate_pan_coordinator),
                manufacturer_code = node_descriptor.manufacturer_code,
                max_buffer_size = node_descriptor.max_buffer_size,
                max_incoming_transfer_size = node_descriptor.max_incoming_transfer_size,
                server_primary_trust_center = int(node_descriptor.server_primary_trust_center),
                server_backup_trust_center = int(node_descriptor.server_backup_trust_center),
                server_primary_binding_table_cache = int(node_descriptor.server_primary_binding_table_cache),
                server_backup_binding_table_cache = int(node_descriptor.server_backup_binding_table_cache),
                server_primary_discovery_cache = int(node_descriptor.server_primary_discovery_cache),
                server_backup_discovery_cache = int(node_descriptor.server_backup_discovery_cache),
                network_manager = int(node_descriptor.network_manager),
                stack_compliance_revision = node_descriptor.stack_compliance_revision,
                max_outgoing_transfer_size = node_descriptor.max_outgoing_transfer_size,
                extended_active_endpoint_list_available = int(node_descriptor.extended_active_endpoint_list_available),
                extended_simple_descriptors_list_available = int(node_descriptor.extended_simple_descriptors_list_available)
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=address, use_network_key=True, destination_endpoint=0)

class ZDONetworkManager(ZDOObject):

    def initialize(self):
        if self.zdo.configuration.get("configNodeDescriptor").logical_type == LogicalDeviceType.END_DEVICE:
            self.zdo.manager.nwk.database.set("nwkExtendedPANID", 0x0000000000000000)
            self.zdo.manager.aps.database.set("apsDesignatedCoordinator", False)
            self.zdo.manager.aps.database.set("apsChannelMask", 0x7fff800)
            self.zdo.manager.aps.database.set("apsUseExtendedPANID", 0x0000000000000000)
            self.zdo.manager.aps.database.set("apsUseInsecureJoin", True)

    def on_authorization(self):
        self.zdo.device_and_service_discovery.device_annce()

    def startup(self):
        self.initialize()
        nwkExtendedPANID = self.zdo.nwk_management.get("nwkExtendedPANID")
        apsDesignatedCoordinator = self.zdo.aps_management.get("apsDesignatedCoordinator")
        apsUseExtendedPANID = self.zdo.aps_management.get("apsUseExtendedPANID")
        apsUseInsecureJoin = self.zdo.aps_management.get("apsUseInsecureJoin")
        apsChannelMask = self.zdo.aps_management.get("apsChannelMask")
        if nwkExtendedPANID != 0:
            # we are already connected :) don't do anything
            return True

        if apsDesignatedCoordinator:
            # We are a coordinator not connected, start NLME-NETWORK-FORMATION
            raise RequiredImplementation("ZigbeeNetworkFormation")

        else:
            # We are a router or an end device, attempt to join or rejoin a network
            if apsUseExtendedPANID != 0:
                rejoin_success = self.zdo.nwk_management.join(
                    apsUseExtendedPANID,
                    association_type=NWKJoinMode.REJOIN,
                    scan_channels=apsChannelMask
                )
                if rejoin_success:
                    return True

                # We failed to rejoin, try to join
                selected_zigbee_network = None
                for attempt in range(self.zdo.configuration.get("configNWKScanAttempts")):
                    zigbee_networks = self.zdo.nwk_management.network_discovery(scan_channels=apsChannelMask)
                    for zigbee_network in zigbee_networks:
                        if zigbee_network.extended_pan_id == apsUseExtendedPANID:
                            selected_zigbee_network = zigbee_network
                    if selected_zigbee_network is not None:
                        break
                    else:
                        sleep(self.zdo.configuration.get("configNWKTimeBetweenScans") * SYMBOL_DURATION[Dot15d4Phy.OQPSK] * 2)
                if selected_zigbee_network is None:
                    logger.info("[zdo_network_manager] target network not found, exiting.")
                    return False

                join_success = self.zdo.nwk_management.join(
                    apsUseExtendedPANID,
                    association_type=NWKJoinMode.NEW_JOIN,
                    scan_channels=apsChannelMask
                )
                if not join_success:
                    logger.info("[zdo_network_manager] failure during network join, exiting.")

                return join_success

            else:
                # join the best available network
                selected_zigbee_network = None
                for attempt in range(self.zdo.configuration.get("configNWKScanAttempts")):
                    zigbee_networks = self.zdo.nwk_management.network_discovery(scan_channels=apsChannelMask)
                    for zigbee_network in zigbee_networks:
                        if zigbee_network.joining_permit:
                            selected_zigbee_network = zigbee_network
                    if selected_zigbee_network is not None:
                        break
                    else:
                        sleep(self.zdo.configuration.get("configNWKTimeBetweenScans") * SYMBOL_DURATION[Dot15d4Phy.OQPSK] * 2)

                if selected_zigbee_network is None:
                    logger.info("[zdo_network_manager] no target network found, exiting.")
                    return False

                join_success = self.zdo.nwk_management.join(
                    selected_zigbee_network.extended_pan_id,
                    association_type=NWKJoinMode.NEW_JOIN,
                    scan_channels=apsChannelMask
                )
                if not join_success:
                    logger.info("[zdo_network_manager] failure during network join, exiting.")

                return join_success

class ZDOSecurityManager(ZDOObject):
    def on_transport_key(self, source_address, standard_key_type, transport_key_data):
        if standard_key_type == 1: # process network key
            nwkSecurityMaterialSet = self.zdo.nwk_management.get("nwkSecurityMaterialSet")
            nwkSecurityMaterialSet.append(
                NetworkSecurityMaterial(
                    transport_key_data.key,
                    transport_key_data.key_sequence_number
                )
            )
            self.zdo.nwk_management.set("nwkSecurityMaterialSet", nwkSecurityMaterialSet)
            logger.info("[zdo_security_manager] new network key provisioned.")
            self.zdo.nwk_management.set("nwkSecurityLevel", 5)

            self.zdo.aps_management.set("apsTrustCenterAddress", source_address)
            logger.info("[zdo_security_manager] new trust center address set.")
            while self.zdo.manager.nwk.database.get("nwkNetworkAddress") == 0xFFFF:
                pass
            self.zdo.network_manager.on_authorization()
