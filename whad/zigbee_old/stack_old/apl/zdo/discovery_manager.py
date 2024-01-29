from whad.zigbee.stack.apl.zdo.object import ZDOObject
from scapy.layers.zigbee import  ZigbeeDeviceProfile
from whad.scapy.layers.zdp import ZDPDeviceAnnce, ZDPNodeDescReq, ZDPNodeDescRsp, ZDPNWKAddrReq, \
    ZDPIEEEAddrReq, ZDPIEEEAddrRsp, ZDPActiveEPReq, ZDPActiveEPRsp, ZDPSimpleDescReq, ZDPSimpleDescRsp
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.apl.cluster import Cluster
from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.zigbee.stack.mac.constants import MACDeviceType, MACPowerSource
from whad.zigbee.stack.apl.zdo.descriptors import NodeDescriptor, SimpleDescriptor
from whad.zigbee.profile.device import Coordinator, EndDevice, Router
from queue import Queue, Empty
from time import time, sleep
import logging

logger = logging.getLogger(__name__)

class ZDODeviceAndServiceDiscoveryTimeoutException(Exception):
    pass

class ZDODeviceAndServiceDiscovery(ZDOObject):

    def __init__(self, zdo):
        self.transaction = 0
        super().__init__(zdo)
        self.input_queue = Queue()

    def can_transmit(self):
        # We are associated AND authorized
        return self.zdo.manager.nwk.database.get("nwkNetworkAddress") != 0xFFFF and self.zdo.network_manager.authorized


    def get_simple_descriptor(self, node_address, endpoint):
        logger.info("[zdo_device_and_service_discovery_manager] Discovering simple descriptor of endpoint #%s of device %s.",str(endpoint), hex(node_address))
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Simple descriptor discovery failure, no associated and authorized network.")
            return None

        transaction = self.transaction
        self.simple_desc_req(node_address, endpoint, transaction)
        self.transaction += 1
        try:
            response = self.wait_for_response(filter_function=lambda pkt:ZDPSimpleDescRsp in pkt and pkt.trans_seqnum == transaction)
            (asdu, source_address, source_address_mode, security_status, link_quality) = response

            if asdu.status == 0:
                return SimpleDescriptor(
                        endpoint=asdu.endpoint,
                        profile_identifier=asdu.profile_identifier,
                        device_identifier=asdu.device_identifier,
                        device_version=asdu.device_version,
                        input_clusters=asdu.input_clusters,
                        output_clusters=asdu.output_clusters
                )
            return None

        except ZDODeviceAndServiceDiscoveryTimeoutException:
            return None

    def get_active_endpoints(self, node_address):
        logger.info("[zdo_device_and_service_discovery_manager] Discovering active endpoints of device %s.", hex(node_address))
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Active endpoints discovery failure, no associated and authorized network.")
            return None

        transaction = self.transaction
        self.active_ep_req(node_address, transaction)
        self.transaction += 1
        try:
            response = self.wait_for_response(filter_function=lambda pkt:ZDPActiveEPRsp in pkt and pkt.trans_seqnum == transaction)
            (asdu, source_address, source_address_mode, security_status, link_quality) = response

            if asdu.status == 0:
                return asdu.active_endpoints
            return []

        except ZDODeviceAndServiceDiscoveryTimeoutException:
            return []

    def get_node_descriptor(self, node_address):
        logger.info("[zdo_device_and_service_discovery_manager] Discovering descriptor of device %s.", hex(node_address))
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Node Descriptor discovery failure, no associated and authorized network.")
            return None

        transaction = self.transaction
        self.node_desc_req(node_address, transaction)
        self.transaction += 1
        try:
            response = self.wait_for_response(filter_function=lambda pkt:ZDPNodeDescRsp in pkt and pkt.trans_seqnum == transaction)
            (asdu, source_address, source_address_mode, security_status, link_quality) = response
            if asdu.status == 0:
                return NodeDescriptor(
                    logical_type=LogicalDeviceType(asdu.logical_type),
                    complex_descriptor_available=bool(asdu.complex_descriptor_available),
                    user_descriptor_available=bool(asdu.user_descriptor_available),
                    aps_flags=asdu.aps_flags,
                    support_868_mhz=bool(asdu.support_868_mhz),
                    support_902_mhz=bool(asdu.support_902_mhz),
                    support_2400_mhz=bool(asdu.support_2400_mhz),
                    alternate_pan_coordinator=bool(asdu.alternate_pan_coordinator),
                    device_type=MACDeviceType(asdu.device_type),
                    power_source=MACPowerSource(asdu.power_source),
                    receiver_on_when_idle=bool(asdu.receiver_on_when_idle),
                    security_capability=bool(asdu.security_capability),
                    allocate_address=bool(asdu.allocate_address),
                    manufacturer_code=asdu.manufacturer_code,
                    max_buffer_size=asdu.max_buffer_size,
                    max_incoming_transfer_size=asdu.max_incoming_transfer_size,
                    server_primary_trust_center = bool(asdu.server_primary_trust_center),
                    server_backup_trust_center = bool(asdu.server_backup_trust_center),
                    server_primary_binding_table_cache = bool(asdu.server_primary_binding_table_cache),
                    server_backup_binding_table_cache = bool(asdu.server_backup_binding_table_cache),
                    server_primary_discovery_cache = bool(asdu.server_primary_discovery_cache),
                    server_backup_discovery_cache = bool(asdu.server_backup_discovery_cache),
                    network_manager = bool(asdu.network_manager),
                    stack_compliance_revision = asdu.stack_compliance_revision,
                    max_outgoing_transfer_size = asdu.max_outgoing_transfer_size,
                    extended_active_endpoint_list_available = bool(asdu.extended_active_endpoint_list_available),
                    extended_simple_descriptors_list_available = bool(asdu.extended_simple_descriptors_list_available)
                )
            return None

        except ZDODeviceAndServiceDiscoveryTimeoutException:
            return None

    def discover_devices(self):
        logger.info("[zdo_device_and_service_discovery_manager] Discovering devices.")
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Devices discovery failure, no associated network.")
            return []

        network = self.zdo.network_manager.network
        addresses = [device.address for device in network.devices]

        transaction = self.transaction
        self.ieee_addr_req(0xFFFF, request_type=1, transaction=transaction)
        self.transaction += 1

        try:
            while True:
                response = self.wait_for_response(filter_function=lambda pkt:ZDPIEEEAddrRsp in pkt and pkt.trans_seqnum == transaction)
                (asdu, source_address, source_address_mode, security_status, link_quality) = response
                if source_address not in addresses:
                    addresses.append(source_address)
        except ZDODeviceAndServiceDiscoveryTimeoutException:
            pass

        scanned_devices = []

        for address in addresses:
            new_device = None
            # Generate a request
            transaction = self.transaction
            self.ieee_addr_req(address, request_type=1, transaction=transaction)
            self.transaction += 1
            try:
                response = self.wait_for_response(filter_function=lambda pkt:ZDPIEEEAddrRsp in pkt and pkt.trans_seqnum == transaction)
                (asdu, source_address, source_address_mode, security_status, link_quality) = response

                descriptor = self.get_node_descriptor(address)
                if descriptor is not None:
                    if descriptor.logical_type == LogicalDeviceType.COORDINATOR:
                        new_device = Coordinator(
                            address,
                            extended_address=asdu.ieee_addr,
                            descriptor=descriptor,
                            network=network
                        )
                        network.coordinator = new_device
                    elif descriptor.logical_type == LogicalDeviceType.ROUTER:
                        new_device = Router(
                            address,
                            extended_address=asdu.ieee_addr,
                            descriptor=descriptor,
                            network=network
                        )
                        if new_device not in network.routers:
                            network.routers.append(new_device)
                    else:
                        new_device = EndDevice(
                            address,
                            extended_address=asdu.ieee_addr,
                            descriptor=descriptor,
                            network=network
                        )
                        if new_device not in network.end_devices:
                            network.end_devices.append(new_device)
                    scanned_devices.append(new_device)

            except ZDODeviceAndServiceDiscoveryTimeoutException:
                pass
        return scanned_devices


    # Synchronous response waiting function
    def wait_for_response(self, filter_function=lambda pkt:True, timeout=3):
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                (asdu, source_address, source_address_mode, security_status, link_quality) = self.input_queue.get(block=False,timeout=0.1)
                if filter_function(asdu):
                    return (asdu, source_address, source_address_mode, security_status, link_quality)
            except Empty:
                pass
        raise ZDODeviceAndServiceDiscoveryTimeoutException

    # Cluster generation helpers
    def nwk_addr_req(self, address, request_type=0, start_index=0, transaction=0):
        self.zdo.clusters["zdo_nwk_addr_req"].generate(address, request_type, start_index, transaction)

    def ieee_addr_req(self, address, request_type=0, start_index=0, transaction=0):
        self.zdo.clusters["zdo_ieee_addr_req"].generate(address, request_type, start_index, transaction)

    def device_annce(self, transaction=0):
        self.zdo.clusters["zdo_device_annce"].generate(transaction)

    def node_desc_req(self, address, transaction=0):
        self.zdo.clusters["zdo_node_desc_req"].generate(address, transaction)

    def node_desc_rsp(self, address, transaction=0):
        self.zdo.clusters["zdo_node_desc_rsp"].generate(address, transaction)

    def active_ep_req(self, address, transaction=0):
        self.zdo.clusters["zdo_active_ep_req"].generate(address, transaction)

    def simple_desc_req(self, address, endpoint, transaction=0):
        self.zdo.clusters["zdo_simple_desc_req"].generate(address, endpoint, transaction)


    # Cluster reception helpers
    def on_nwk_addr_rsp(self, asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put((asdu, source_address, source_address_mode, security_status, link_quality))

    def on_ieee_addr_rsp(self, asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put((asdu, source_address, source_address_mode, security_status, link_quality))

    def on_node_desc_rsp(self,  asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put((asdu, source_address, source_address_mode, security_status, link_quality))

    def on_active_ep_rsp(self, asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put((asdu, source_address, source_address_mode, security_status, link_quality))

    def on_simple_desc_rsp(self, asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put((asdu, source_address, source_address_mode, security_status, link_quality))

    # Cluster definitions
    class ZDONWKAddrReq(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x0000)
            self.zdo_object = zdo_object

        def generate(self, address, request_type=1, start_index=0, transaction=0):
            command = ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPNWKAddrReq(
                ieee_addr=address,
                request_type=request_type,
                start_index=start_index
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=0xfffd, use_network_key=True, destination_endpoint=0)

    class ZDONWKAddrRsp(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x8000)
            self.zdo_object = zdo_object

        def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
            asdu.show()
            print(hex(source_address))
            self.zdo_object.on_nwk_addr_rsp(asdu, source_address, source_address_mode, security_status, link_quality)


    class ZDOIEEEAddrReq(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x0001)
            self.zdo_object = zdo_object

        def generate(self, address, request_type=1, start_index=0, transaction=0):
            command = ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPIEEEAddrReq(
                nwk_addr=address,
                request_type=request_type,
                start_index=start_index
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=address, use_network_key=True, destination_endpoint=0)

    class ZDOIEEEAddrRsp(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x8001)
            self.zdo_object = zdo_object

        def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
            self.zdo_object.on_ieee_addr_rsp(asdu, source_address, source_address_mode, security_status, link_quality)

    class ZDODeviceAnnce(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x0013)
            self.zdo_object = zdo_object

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

    class ZDONodeDescReq(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x0002)
            self.zdo_object = zdo_object

        def generate(self, address, transaction=0):
            command =  ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPNodeDescReq(
                nwk_addr = address
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=address, use_network_key=True, destination_endpoint=0)

        def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
            self.application.clusters["zdo_node_desc_rsp"].generate(source_address, asdu.trans_seqnum)

    class ZDONodeDescRsp(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x8002)
            self.zdo_object = zdo_object

        def generate(address, transaction):
            node_descriptor = self.zdo_object.zdo.configuration.get("configNodeDescriptor")
            command =  ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPNodeDescRsp(
                logical_type=int(node_descriptor.logical_type),
                complex_descriptor_available=int(node_descriptor.complex_descriptor_available),
                user_descriptor_available=int(node_descriptor.user_descriptor_available),
                aps_flags=node_descriptor.aps_flags,
                support_868_mhz=int(node_descriptor.support_868_mhz),
                support_902_mhz=int(node_descriptor.support_902_mhz),
                support_2400_mhz=int(node_descriptor.support_2400_mhz),
                alternate_pan_coordinator=int(node_descriptor.alternate_pan_coordinator),
                device_type=int(node_descriptor.device_type),
                power_source=int(node_descriptor.power_source),
                receiver_on_when_idle=int(node_descriptor.receiver_on_when_idle),
                security_capability=int(node_descriptor.security_capability),
                allocate_address=int(node_descriptor.allocate_address),
                manufacturer_code=node_descriptor.manufacturer_code,
                max_buffer_size=node_descriptor.max_buffer_size,
                max_incoming_transfer_size=node_descriptor.max_incoming_transfer_size,
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

        def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
            self.zdo_object.on_node_desc_rsp(asdu, source_address, source_address_mode, security_status, link_quality)



    class ZDOActiveEPReq(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x0005)
            self.zdo_object = zdo_object

        def generate(self, address, transaction=0):
            command =  ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPActiveEPReq(
                nwk_addr = address
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=address, use_network_key=True, destination_endpoint=0)

    class ZDOActiveEPRsp(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x8005)
            self.zdo_object = zdo_object

        def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
            self.zdo_object.on_active_ep_rsp(asdu, source_address, source_address_mode, security_status, link_quality)

    class ZDOSimpleDescReq(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x0004)
            self.zdo_object = zdo_object

        def generate(self, address, endpoint, transaction=0):
            command =  ZigbeeDeviceProfile(trans_seqnum=transaction)/ZDPSimpleDescReq(
                nwk_addr = address,
                endpoint = endpoint
            )
            self.send_data(command, destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT, destination_address=address, use_network_key=True, destination_endpoint=0)

    class ZDOSimpleDescRsp(Cluster):
        def __init__(self, zdo_object):
            super().__init__(cluster_id=0x8004)
            self.zdo_object = zdo_object

        def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
            self.zdo_object.on_simple_desc_rsp(asdu, source_address, source_address_mode, security_status, link_quality)
