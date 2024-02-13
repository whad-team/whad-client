from whad.zigbee.stack.apl.zdo.object import ZDOObject
from whad.zigbee.stack.apl.zdo.descriptors import NodeDescriptor, SimpleDescriptor
from whad.zigbee.stack.apl.zdo.discovery.exceptions import ZDODeviceAndServiceDiscoveryTimeoutException
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

        # Trigger a Simple Descriptor Request
        transaction = self.transaction
        self.zdo.clusters["simple_desc_req"](node_address, endpoint, transaction)
        self.transaction += 1

        # Get Simple Descriptor Response or trigger an error if timeout
        try:
            response = self.wait_for_response(filter_function=
                lambda pkt:ZDPSimpleDescRsp in pkt and pkt.trans_seqnum == transaction
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
