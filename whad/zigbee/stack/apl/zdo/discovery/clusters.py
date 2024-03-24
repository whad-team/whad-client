from whad.zigbee.stack.apl.zdo.descriptors import NodeDescriptor, SimpleDescriptor
from whad.zigbee.stack.aps.constants import APSDestinationAddressMode
from whad.zigbee.stack.apl.cluster import Cluster
from whad.zigbee.stack.apl.constants import LogicalDeviceType
from whad.dot15d4.stack.mac.constants import MACDeviceType, MACPowerSource
from scapy.layers.zigbee import  ZigbeeDeviceProfile
from whad.scapy.layers.zdp import ZDPDeviceAnnce, ZDPNodeDescReq, ZDPNodeDescRsp, ZDPNWKAddrReq, \
    ZDPIEEEAddrReq, ZDPIEEEAddrRsp, ZDPActiveEPReq, ZDPActiveEPRsp, ZDPSimpleDescReq, ZDPSimpleDescRsp

class ZDPCluster(Cluster):
    """
    This class represents a Zigbee Device Profile cluster.
    """
    def __init__(self, zdo_object, cluster_id):
        super().__init__(cluster_id=cluster_id)
        self.zdo_object = zdo_object

    def send_data(
                    self,
                    command,
                    transaction,
                    destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
                    destination_address=0xFFFF,
                    use_network_key=True,
                    destination_endpoint=0
    ):
        """
        Method allowing to send ASDU related to cluster.
        """
        zdp_command =  ZigbeeDeviceProfile(trans_seqnum=transaction) / command
        super().send_data(
            zdp_command,
            destination_address_mode=destination_address_mode,
            destination_address=destination_address,
            use_network_key=use_network_key,
            destination_endpoint=destination_endpoint
        )

    def on_data(self, asdu, source_address, source_address_mode, security_status, link_quality):
        """
        Callback called when an ASDU related to the current cluster is received.
        """
        self.zdo_object.on_cluster_data(
            asdu,
            source_address,
            source_address_mode,
            security_status,
            link_quality
        )


class ZDONWKAddrReq(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x0000)

    def send_data(self, address=0xfffd, request_type=1, start_index=0, transaction=0):
        command = ZDPNWKAddrReq(
            ieee_addr=address,
            request_type=request_type,
            start_index=start_index
        )
        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=address,
            use_network_key=True,
            destination_endpoint=0
        )

class ZDONWKAddrRsp(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x8000)


class ZDOIEEEAddrReq(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x0001)

    def send_data(self, address, request_type=1, start_index=0, transaction=0):
        command = ZDPIEEEAddrReq(
            nwk_addr=address,
            request_type=request_type,
            start_index=start_index
        )
        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=address,
            use_network_key=True,
            destination_endpoint=0
        )

class ZDOIEEEAddrRsp(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x8001)


    def send_data(self, nwk_address, ieee_address,remote_address, status=0, num_assoc_dev=0, start_index=0, associated_devices=[], transaction=0):

        command = ZDPIEEEAddrRsp(
            ieee_addr=ieee_address,
            nwk_addr=nwk_address,
            status=status
        )
        if status == 0:
            command.num_assoc_dev=num_assoc_dev
            command.start_index = start_index
            command.associated_devices = associated_devices


        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=remote_address,
            use_network_key=True,
            destination_endpoint=0
        )
class ZDODeviceAnnce(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x0013)

    def send_data(self, transaction=0):
        node_descriptor = self.application.configuration.get("configNodeDescriptor")
        nwk_layer = self.application.manager.get_layer('nwk')
        command = ZDPDeviceAnnce(
            nwk_addr = nwk_layer.database.get("nwkNetworkAddress"),
            ieee_addr = nwk_layer.database.get("nwkIeeeAddress"),
            allocate_address = int(node_descriptor.allocate_address),
            security_capability = int(node_descriptor.security_capability),
            receiver_on_when_idle = int(node_descriptor.receiver_on_when_idle),
            power_source = int(node_descriptor.power_source),
            device_type = int(node_descriptor.logical_type),
            alternate_pan_coordinator = int(node_descriptor.alternate_pan_coordinator)
        )
        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=0xfffd,
            use_network_key=True,
            destination_endpoint=0
        )


class ZDONodeDescReq(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x0002)

    def send_data(self, address, transaction=0):
        command = ZDPNodeDescReq(
            nwk_addr = address
        )
        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=address,
            use_network_key=True,
            destination_endpoint=0
        )

class ZDONodeDescRsp(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x8002)

    def send_data(self, address, status, node_descriptor=None, transaction=0):
        if status == 0:
            command =  ZDPNodeDescRsp(
                nwk_addr=address,
                status=status,
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
        else:
            command =  ZDPNodeDescRsp(
                nwk_addr=address,
                status=status
            )
        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=address,
            use_network_key=True,
            destination_endpoint=0
        )


class ZDOActiveEPReq(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x0005)

    def send_data(self, address, transaction=0):
        command = ZDPActiveEPReq(
            nwk_addr = address
        )
        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=address,
            use_network_key=True,
            destination_endpoint=0
        )

class ZDOActiveEPRsp(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x8005)


    def send_data(self, local_address, remote_address, status=0, endpoints=[], transaction=0):
        command = ZDPActiveEPRsp(
            status=status,
            nwk_addr = local_address,
            active_endpoints=endpoints,
            num_active_endpoints=len(endpoints)
        )

        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=remote_address,
            use_network_key=True,
            destination_endpoint=0
        )

class ZDOSimpleDescReq(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x0004)

    def send_data(self, address, endpoint, transaction=0):
        command = ZDPSimpleDescReq(
            nwk_addr = address,
            endpoint = endpoint
        )
        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=address,
            use_network_key=True,
            destination_endpoint=0
        )

class ZDOSimpleDescRsp(ZDPCluster):
    def __init__(self, zdo_object):
        super().__init__(zdo_object, cluster_id=0x8004)

    def send_data(self, status, local_address, remote_address, descriptor=None, transaction=0):
        if descriptor is None:
            command = ZDPSimpleDescRsp(
                status = status,
                nwk_addr = address,
                descriptor_length = 0
            )
        else:
            command = ZDPSimpleDescRsp(
                status = status,
                nwk_addr = local_address,
                descriptor_length = (
                    6 +
                    (1 + 2 * len(descriptor.input_clusters)) +
                    (1 + 2 * len(descriptor.output_clusters))
                ),
                endpoint = descriptor.endpoint,
                profile_identifier = descriptor.profile_identifier,
                device_identifier = descriptor.device_identifier,
                device_version = descriptor.device_version,
                input_clusters_count = len(descriptor.input_clusters),
                input_clusters = descriptor.input_clusters,
                output_clusters_count = len(descriptor.output_clusters),
                output_clusters = descriptor.output_clusters
            )
        super().send_data(
            command,
            transaction,
            destination_address_mode=APSDestinationAddressMode.SHORT_ADDRESS_DST_ENDPOINT_PRESENT,
            destination_address=remote_address,
            use_network_key=True,
            destination_endpoint=0
        )
