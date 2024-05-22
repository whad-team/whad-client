from whad.zigbee.stack.apl.zdo.object import ZDOObject
from whad.zigbee.stack.apl.zdo.descriptors import NodeDescriptor, SimpleDescriptor
from whad.zigbee.profile.nodes import CoordinatorNode, EndDeviceNode, RouterNode
from whad.dot15d4.stack.mac.constants import MACDeviceType, MACPowerSource
from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.zigbee.stack.apl.zdo.discovery.exceptions import ZDODeviceAndServiceDiscoveryTimeoutException
from whad.scapy.layers.zdp import ZDPIEEEAddrReq, ZDPSimpleDescRsp, ZDPActiveEPReq, ZDPActiveEPRsp, \
    ZDPNodeDescRsp, ZDPIEEEAddrRsp, ZDPSimpleDescReq, ZDPNodeDescReq
from whad.zigbee.stack.nwk.constants import ZigbeeRelationship, ZigbeeDeviceType
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
                lambda pkt:ZDPSimpleDescRsp in pkt# and pkt.trans_seqnum == self.transaction
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
                filter_function=lambda pkt:ZDPActiveEPRsp in pkt# and pkt.trans_seqnum == self.transaction
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
                filter_function=lambda pkt:ZDPNodeDescRsp in pkt# and pkt.trans_seqnum == self.transaction
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
                    filter_function=lambda pkt:ZDPIEEEAddrRsp in pkt# and pkt.trans_seqnum == self.transaction
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
                    filter_function=lambda pkt:ZDPIEEEAddrRsp in pkt# and pkt.trans_seqnum == self.transaction
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

        if ZDPIEEEAddrReq in asdu:
            self.on_ieee_addr_req(asdu, source_address)
        elif ZDPActiveEPReq in asdu:
            self.on_active_ep_req(asdu, source_address)
        elif ZDPSimpleDescReq in asdu:
            self.on_simple_desc_req(asdu, source_address)
        elif ZDPNodeDescReq in asdu:
            self.on_node_desc_req(asdu, source_address)

    def on_node_desc_req(self, asdu, source_address):
        """
        Callback called when a Node Descriptor Request is received.
        """
        nwk_layer = self.zdo.manager.get_layer("nwk")
        own_network_address = nwk_layer.database.get("nwkNetworkAddress")

        apl_layer = self.zdo.manager.get_layer("apl")


        associated_devices_addresses = []
        for address, device in nwk_layer.database.get("nwkNeighborTable").table.items():
            if (
                device.relationship == ZigbeeRelationship.IS_CHILD and
                device.device_type == ZigbeeDeviceType.END_DEVICE
            ):
                associated_devices_addresses.append(device.address)


        if own_network_address == asdu.nwk_addr:
            node_descriptor = self.zdo.configuration.configNodeDescriptor
            # Send a Node Descriptor Request
            self.zdo.clusters["node_desc_rsp"].send_data(
                address,
                status=0,
                node_descriptor=node_descriptor,
                transaction=self.transaction
            )
            self.transaction += 1
        elif asdu.nwk_addr in associated_devices_addresses:
            self.zdo.clusters["node_desc_rsp"].send_data(
                address,
                status=3,
                node_descriptor=node_descriptor,
                transaction=self.transaction
            )
            self.transaction += 1
        else:
            self.zdo.clusters["node_desc_rsp"].send_data(
                address,
                status=1,
                node_descriptor=node_descriptor,
                transaction=self.transaction
            )
            self.transaction += 1

    def on_simple_desc_req(self, asdu, remote_address):
        """
        Callback called when a Simple Descriptor Request is received.
        """
        nwk_layer = self.zdo.manager.get_layer("nwk")
        own_network_address = nwk_layer.database.get("nwkNetworkAddress")

        apl_layer = self.zdo.manager.get_layer("apl")


        associated_devices_addresses = []
        for address, device in nwk_layer.database.get("nwkNeighborTable").table.items():
            if (
                device.relationship == ZigbeeRelationship.IS_CHILD and
                device.device_type == ZigbeeDeviceType.END_DEVICE
            ):
                associated_devices_addresses.append(device.address)


        if own_network_address == asdu.nwk_addr:
            # It matches our own address, check if endpoint in active endpoints
            endpoints = apl_layer.get_endpoints()

            if asdu.endpoint in endpoints and asdu.endpoint != 0:
                app = apl_layer.get_application_by_endpoint(asdu.endpoint)
                simple_descriptor = app.simple_descriptor

                self.zdo.clusters["simple_desc_rsp"].send_data(
                    status = 0, # success
                    local_address = own_network_address,
                    remote_address = remote_address,
                    descriptor = simple_descriptor,
                    transaction = self.transaction
                )
                self.transaction += 1
            else:
                self.zdo.clusters["simple_desc_rsp"].send_data(
                    status = 3, # no descriptor
                    local_address = own_network_address,
                    remote_address = remote_address,
                    transaction = self.transaction
                )
                self.transaction += 1
        elif asdu.nwk_addr in associated_devices_addresses:
            # It matches one of our children
            self.zdo.clusters["simple_desc_rsp"].send_data(
                status = 3, # no descriptor (we lie for now)
                local_address = own_network_address,
                remote_address = remote_address,
                transaction = self.transaction
            )
            self.transaction += 1
        else:
            self.zdo.clusters["simple_desc_rsp"].send_data(
                status = 1, # device not found
                local_address = own_network_address,
                remote_address = remote_address,
                transaction = self.transaction
            )
            self.transaction += 1


    def on_active_ep_req(self, asdu, remote_address):
        """
        Callback called when an active endpoint request is received.
        """
        nwk_layer = self.zdo.manager.get_layer("nwk")
        own_network_address = nwk_layer.database.get("nwkNetworkAddress")

        apl_layer = self.zdo.manager.get_layer("apl")

        if asdu.nwk_addr == own_network_address:
            endpoints = apl_layer.get_endpoints()
            endpoints.remove(0)
            self.zdo.clusters["active_ep_rsp"].send_data(
                status = 0,
                local_address = own_network_address,
                remote_address = remote_address,
                endpoints = endpoints,
                transaction = self.transaction
            )
            self.transaction += 1

        # Not implemented: discovery of sub devices in the discovery type
        else:
            self.zdo.clusters["active_ep_rsp"].send_data(
                status = 1, # dev not found
                local_address = asdu.nwk_addr,
                remote_address = remote_address,
                endpoints = [],
                transaction = self.transaction
            )
            self.transaction += 1


    def on_ieee_addr_req(self, asdu, remote_address):
        """
        Callback called when a IEEE address request is received.
        """
        nwk_layer = self.zdo.manager.get_layer("nwk")
        own_network_address = nwk_layer.database.get("nwkNetworkAddress")
        own_ieee_address = nwk_layer.database.get("nwkIeeeAddress")


        associated_devices_addresses = []
        for address, device in nwk_layer.database.get("nwkNeighborTable").table.items():
            if (
                device.relationship == ZigbeeRelationship.IS_CHILD and
                device.device_type == ZigbeeDeviceType.END_DEVICE
            ):
                associated_devices_addresses.append(device.address)


        match = False
        if own_network_address == asdu.nwk_addr or asdu.nwk_addr in associated_devices_addresses:
            match = True


        if match:
            if asdu.request_type == 0:
                self.zdo.clusters["ieee_addr_rsp"].send_data(
                    own_network_address,
                    own_ieee_address,
                    remote_address = remote_address,
                    status=0,
                    num_assoc_dev=0,
                    start_index=0,
                    associated_devices=[],
                    transaction=self.transaction
                )
            elif asdu.request_type == 1:
                self.zdo.clusters["ieee_addr_rsp"].send_data(
                    own_network_address,
                    own_ieee_address,
                    remote_address = remote_address,
                    status=0,
                    num_assoc_dev=len(associated_devices_addresses),
                    start_index=asdu.start_index,
                    associated_devices=associated_devices_addresses[asdu.start_index:],
                    transaction=self.transaction
                )
            else:
                self.zdo.clusters["ieee_addr_rsp"].send_data(
                    own_network_address,
                    own_ieee_address,
                    remote_address = remote_address,
                    status=2,
                    num_assoc_dev=0,
                    start_index=0,
                    associated_devices=[],
                    transaction=self.transaction
                )

            self.transaction += 1

        else:
            # no match, send device not found response
            self.zdo.clusters["ieee_addr_rsp"].send_data(
                own_network_address,
                own_ieee_address,
                remote_address = remote_address,
                status=1,
                num_assoc_dev=0,
                start_index=0,
                associated_devices=[],
                transaction=self.transaction
            )
            self.transaction += 1

    def wait_for_response(self, filter_function=lambda pkt:True, timeout=1):
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
