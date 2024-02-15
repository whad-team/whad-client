from whad.zigbee.stack.apl.zdo.object import ZDOObject
from whad.zigbee.stack.apl.zdo.descriptors import NodeDescriptor, SimpleDescriptor
from whad.zigbee.profile.nodes import CoordinatorNode, EndDeviceNode, RouterNode
from whad.dot15d4.stack.mac.constants import MACDeviceType, MACPowerSource
from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.zigbee.stack.apl.zdo.discovery.exceptions import ZDODeviceAndServiceDiscoveryTimeoutException
from whad.scapy.layers.zdp import ZDPSimpleDescRsp, ZDPActiveEPRsp, ZDPNodeDescRsp, ZDPIEEEAddrRsp
from queue import Queue, Empty
from time import time, sleep

import logging

logger = logging.getLogger(__name__)

class ZDODeviceAndServiceDiscovery(ZDOObject):
    """
    ZDO Device Object handling the discovery of Devices, Apps & Services.
    """

    def __init__(self, zdo):
        # Init transaction counter
        self.transaction = 0
        # Build input queue
        self.input_queue = Queue()

        super().__init__(zdo)


    def can_transmit(self):
        """
        Check if we are associated and authorized to transmit on the network
        """

        return (
            self.zdo.manager.get_layer("nwk").database.get("nwkNetworkAddress") != 0xFFFF and
            self.zdo.network_manager.authorized
        )



    def get_simple_descriptor(self, node_address, endpoint):
        """
        Discover the simple descriptor of a specific endpoint for a specific node.
        """
        logger.info("[zdo_device_and_service_discovery_manager] Discovering simple descriptor of endpoint #%s of node %s.",str(endpoint), hex(node_address))

        # If we are not allowed to transmit, trigger an error
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Simple descriptor discovery failure, no associated and authorized network.")
            return None

        # Send a Simple Descriptor Request
        self.zdo.clusters["simple_desc_req"].send_data(
            node_address,
            endpoint,
            self.transaction
        )
        self.transaction += 1

        # Get Simple Descriptor Response or trigger an error if timeout
        try:
            response = self.wait_for_response(filter_function=
                lambda pkt:ZDPSimpleDescRsp in pkt and pkt.trans_seqnum == self.transaction
            )
            (asdu, source_address, source_address_mode, security_status, link_quality) = response

            # If successful, return the associated simple descriptor
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
        """
        Discover the active endpoints exposed by a specific node.
        """
        logger.info("[zdo_device_and_service_discovery_manager] Discovering active endpoints of node %s.", hex(node_address))

        # If we are not allowed to transmit, trigger an error
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Active endpoints discovery failure, no associated and authorized network.")
            return None

        # Send an Active Endpoint Request
        self.zdo.clusters["active_ep_req"].send_data(
            node_address,
            self.transaction
        )
        self.transaction += 1

        # Get Active Endpoint Response or trigger an error if timeout
        try:
            response = self.wait_for_response(
                filter_function=lambda pkt:ZDPActiveEPRsp in pkt and pkt.trans_seqnum == self.transaction
            )
            (asdu, source_address, source_address_mode, security_status, link_quality) = response

            # If successful, return the list of active endpoints
            if asdu.status == 0:
                return asdu.active_endpoints
            return []

        except ZDODeviceAndServiceDiscoveryTimeoutException:
            return None


    def get_node_descriptor(self, node_address):
        """
        Discover node descriptor of a specific node.
        """
        logger.info("[zdo_device_and_service_discovery_manager] Discovering descriptor of node %s.", hex(node_address))

        # If we are not allowed to transmit, trigger an error
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Node Descriptor discovery failure, no associated and authorized network.")
            return None

        # Send a Node Descriptor Request
        self.zdo.clusters["node_desc_req"].send_data(
            node_address,
            self.transaction
        )
        self.transaction += 1

        # Get Node Descriptor Response or trigger an error if timeout
        try:
            response = self.wait_for_response(
                filter_function=lambda pkt:ZDPNodeDescRsp in pkt and pkt.trans_seqnum == self.transaction
            )
            (asdu, source_address, source_address_mode, security_status, link_quality) = response

            # If response indicates a successful statuts, return the Node Descriptor
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

    def device_annce(self, transaction=0):
        """
        Annonce the current node.
        """
        self.zdo.clusters["device_annce"].send_data(transaction)


    def discover_nodes(self):
        """
        Discover nodes present on the current network.
        """
        logger.info("[zdo_device_and_service_discovery_manager] Discovering nodes.")
        # If we are not allowed to transmit, trigger an error
        if not self.can_transmit():
            logger.info("[zdo_device_and_service_discovery_manager] Nodes discovery failure, no associated network.")
            return []

        # Build a list of nodes addresses in the network
        network = self.zdo.network_manager.network
        addresses = [device.address for device in network.nodes]

        # Send an IEEE Address Request in broadcast
        self.zdo.clusters["ieee_addr_req"].send_data(
            0xFFFF,
            request_type=1,
            transaction=self.transaction
        )
        self.transaction += 1

        # Wait for responses and populate addresses list if we find more nodes
        try:
            while True:
                response = self.wait_for_response(
                    filter_function=lambda pkt:ZDPIEEEAddrRsp in pkt and pkt.trans_seqnum == self.transaction
                )
                (asdu, source_address, source_address_mode, security_status, link_quality) = response

                if source_address not in addresses:
                    addresses.append(source_address)

        except ZDODeviceAndServiceDiscoveryTimeoutException:
            pass

        # Iterate over addresses in our list
        scanned_nodes = []
        for address in addresses:
            new_device = None
            # Send an IEEE Address Request

            self.zdo.clusters["ieee_addr_req"].send_data(
                address,
                request_type=1,
                transaction=self.transaction
            )
            self.transaction += 1
            try:
                response = self.wait_for_response(
                    filter_function=lambda pkt:ZDPIEEEAddrRsp in pkt and pkt.trans_seqnum == self.transaction
                )
                (asdu, source_address, source_address_mode, security_status, link_quality) = response

                # Get the node descriptor and generate an appropriate node wrapper
                descriptor = self.get_node_descriptor(address)
                if descriptor is not None:
                    if descriptor.logical_type == LogicalDeviceType.COORDINATOR:
                        new_device = CoordinatorNode(
                            address,
                            extended_address=asdu.ieee_addr,
                            descriptor=descriptor,
                            network=network
                        )
                        network.coordinator = new_device
                    elif descriptor.logical_type == LogicalDeviceType.ROUTER:
                        new_device = RouterNode(
                            address,
                            extended_address=asdu.ieee_addr,
                            descriptor=descriptor,
                            network=network
                        )
                        if new_device not in network.routers:
                            network.routers.append(new_device)
                    else:
                        new_device = EndDeviceNode(
                            address,
                            extended_address=asdu.ieee_addr,
                            descriptor=descriptor,
                            network=network
                        )
                        if new_device not in network.end_devices:
                            network.end_devices.append(new_device)

                    scanned_nodes.append(new_device)

            except ZDODeviceAndServiceDiscoveryTimeoutException:
                pass
        return scanned_nodes

    def on_cluster_data(
                        self,
                        asdu,
                        source_address,
                        source_address_mode,
                        security_status,
                        link_quality
    ):
        """
        Callback called when a cluster processes a PDU.
        """
        # Send to queue
        self.input_queue.put(
            (
                asdu,
                source_address,
                source_address_mode,
                security_status,
                link_quality
            )
        )

    def wait_for_response(self, filter_function=lambda pkt:True, timeout=3):
        """
        Synchronous blocking method for processing data from input ZDP clusters.
        """
        start_time = time()
        while (time() - start_time) < timeout:
            try:
                (
                    asdu,
                    source_address,
                    source_address_mode,
                    security_status,
                    link_quality
                ) = self.input_queue.get(block=False,timeout=0.1)
                if filter_function(asdu):
                    return (
                        asdu,
                        source_address,
                        source_address_mode,
                        security_status,
                        link_quality
                    )
            except Empty:
                pass

        raise ZDODeviceAndServiceDiscoveryTimeoutException
