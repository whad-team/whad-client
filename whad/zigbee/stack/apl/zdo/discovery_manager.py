from whad.zigbee.stack.apl.zdo.object import ZDOObject
from scapy.layers.zigbee import  ZigbeeDeviceProfile
from whad.scapy.layers.zdp import ZDPDeviceAnnce, ZDPNodeDescReq, ZDPNodeDescRsp, ZDPNWKAddrReq, \
    ZDPIEEEAddrReq
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.apl.cluster import Cluster
import logging

logger = logging.getLogger(__name__)

class ZDODeviceAndServiceDiscovery(ZDOObject):

    class ZDONWKAddrReq(Cluster):
        def __init__(self):
            super().__init__(cluster_id=0x0000)

        def generate(self, address, request_type=1, start_index=0, transaction=0):
            command = ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPNWKAddrReq(
                ieee_addr=address,
                request_type=request_type,
                start_index=start_index
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=0xfffd, use_network_key=True, destination_endpoint=0)

    def nwk_addr_req(self, address, request_type=0, start_index=0, transaction=0):
        self.zdo.clusters["zdo_nwk_addr_req"].generate(address, request_type, start_index, transaction)

    class ZDOIEEEAddrReq(Cluster):
        def __init__(self):
            super().__init__(cluster_id=0x0001)

        def generate(self, address, request_type=1, start_index=0, transaction=0):
            command = ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPIEEEAddrReq(
                nwk_addr=address,
                request_type=request_type,
                start_index=start_index
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=address, use_network_key=True, destination_endpoint=0)

    def ieee_addr_req(self, address, request_type=1, start_index=0, transaction=0):
        self.zdo.clusters["zdo_ieee_addr_req"].generate(address, request_type, start_index, transaction)


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
        '''
        def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
            asdu.show()
        '''

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
