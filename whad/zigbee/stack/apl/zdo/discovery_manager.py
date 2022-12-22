from whad.zigbee.stack.apl.zdo.object import ZDOObject
from scapy.layers.zigbee import  ZigbeeDeviceProfile
from whad.scapy.layers.zdp import ZDPDeviceAnnce, ZDPNodeDescReq, ZDPNodeDescRsp, ZDPNWKAddrReq, \
    ZDPIEEEAddrReq, ZDPIEEEAddrRsp, ZDPActiveEPReq, ZDPActiveEPRsp, ZDPSimpleDescReq, ZDPSimpleDescRsp
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.apl.cluster import Cluster
from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.zigbee.stack.mac.constants import MACDeviceType, MACPowerSource
from whad.zigbee.stack.apl.zdo.descriptors import NodeDescriptor, SimpleDescriptor
from whad.zigbee.stack.nwk.constants import ZigbeeEndDevice
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
            if response.status == 0:
                return SimpleDescriptor(
                        endpoint=response.endpoint,
                        profile_identifier=response.profile_identifier,
                        device_identifier=response.device_identifier,
                        device_version=response.device_version,
                        input_clusters=response.input_clusters,
                        output_clusters=response.output_clusters
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
            if response.status == 0:
                return response.active_endpoints
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
            if response.status == 0:
                return NodeDescriptor(
                    logical_type=LogicalDeviceType(response.logical_type),
                    complex_descriptor_available=bool(response.complex_descriptor_available),
                    user_descriptor_available=bool(response.user_descriptor_available),
                    aps_flags=response.aps_flags,
                    support_868_mhz=bool(response.support_868_mhz),
                    support_902_mhz=bool(response.support_902_mhz),
                    support_2400_mhz=bool(response.support_2400_mhz),
                    alternate_pan_coordinator=bool(response.alternate_pan_coordinator),
                    device_type=MACDeviceType(response.device_type),
                    power_source=MACPowerSource(response.power_source),
                    receiver_on_when_idle=bool(response.receiver_on_when_idle),
                    security_capability=bool(response.security_capability),
                    allocate_address=bool(response.allocate_address),
                    manufacturer_code=response.manufacturer_code,
                    max_buffer_size=response.max_buffer_size,
                    max_incoming_transfer_size=response.max_incoming_transfer_size,
                    server_primary_trust_center = bool(response.server_primary_trust_center),
                    server_backup_trust_center = bool(response.server_backup_trust_center),
                    server_primary_binding_table_cache = bool(response.server_primary_binding_table_cache),
                    server_backup_binding_table_cache = bool(response.server_backup_binding_table_cache),
                    server_primary_discovery_cache = bool(response.server_primary_discovery_cache),
                    server_backup_discovery_cache = bool(response.server_backup_discovery_cache),
                    network_manager = bool(response.network_manager),
                    stack_compliance_revision = response.stack_compliance_revision,
                    max_outgoing_transfer_size = response.max_outgoing_transfer_size,
                    extended_active_endpoint_list_available = bool(response.extended_active_endpoint_list_available),
                    extended_simple_descriptors_list_available = bool(response.extended_simple_descriptors_list_available)
                )
            return None

        except ZDODeviceAndServiceDiscoveryTimeoutException:
            return None

    def discover_devices(self):
        logger.info("[zdo_device_and_service_discovery_manager] Discovering devices.")
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Devices discovery failure, no associated network.")
            return []

        devices = {}
        extended_pan_id = self.zdo.manager.nwk.database.get("nwkExtendedPANID")

        # Loop over identified neighbors matching the current network
        for device_address, device in self.zdo.manager.nwk.database.get("nwkNeighborTable").table.items():
            if device.extended_pan_id == extended_pan_id:
                devices[device_address] = device

        scanned_devices = []

        # For each router or coordinator, send an extended IEEE address request
        for device_addr, device in devices.items():
            # Add the device to the list
            scanned_devices.append(device)
            transaction = self.transaction
            self.ieee_addr_req(device.address, request_type=1, transaction=transaction)
            self.transaction += 1
            try:
                response = self.wait_for_response(filter_function=lambda pkt:ZDPIEEEAddrRsp in pkt and pkt.trans_seqnum == transaction)
                # If we receive a response, extract the relevant information
                # If we didn't know extended address, update the node
                if device.extended_address is None:
                    device.extended_address = response.ieee_addr

                # Iterate over the children
                for child_address in response.associated_devices:
                    # If we don't already know the child, send a request
                    if child_address not in devices:
                        try:
                            transaction = self.transaction
                            self.ieee_addr_req(child_address, request_type=1, transaction=transaction)
                            self.transaction += 1

                            response_end_device = self.wait_for_response(filter_function=lambda pkt:ZDPIEEEAddrRsp in pkt and pkt.trans_seqnum==transaction)
                            # If we receive a response, the node is associated AND active, so create a new end device
                            # and add it to the new devices list
                            end_device = ZigbeeEndDevice(
                                child_address,
                                extended_address=response.ieee_addr,
                                rx_on_when_idle=False,
                                extended_pan_id=device.extended_pan_id,
                                logical_channel=device.logical_channel,
                                depth=None,
                                beacon_order=None,
                                permit_joining=False,
                                potential_parent=False,
                                pan_id=device.pan_id
                            )
                            scanned_devices.append(end_device)

                        except ZDODeviceAndServiceDiscoveryTimeoutException:
                            pass
            except ZDODeviceAndServiceDiscoveryTimeoutException:
                pass

        return scanned_devices




    # Synchronous response waiting function
    def wait_for_response(self, filter_function=lambda pkt:True, timeout=3):
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                msg = self.input_queue.get(block=False,timeout=0.1)
                if filter_function(msg):
                    return msg
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
    def on_ieee_addr_rsp(self, asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put(asdu)

    def on_node_desc_rsp(self,  asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put(asdu)

    def on_active_ep_rsp(self, asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put(asdu)

    def on_simple_desc_rsp(self, asdu, source_address, source_address_mode, security_status, link_quality):
        self.input_queue.put(asdu)

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
