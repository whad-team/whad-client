from whad.zigbee.stack.mac.constants import MACAddressMode

class ApplicationObject:
    def __init__(self, name, application_profile_identifier, application_device_identifier, application_device_version=0, input_clusters=[], output_clusters=[]):
        self.manager = None
        self.name = name
        self.application_profile_identifier = application_profile_identifier
        self.application_device_identifier = application_device_identifier
        self.application_device_version = application_device_version
        self.input_clusters = input_clusters
        self.output_clusters = output_clusters
        for cluster in self.input_clusters + self.output_clusters:
            cluster.application = self

    def start(self):
        pass

    def send_data(self, asdu, destination_address_mode, destination_address, destination_endpoint, alias_address=None, alias_sequence_number=0, radius=30, security_enabled_transmission=False, use_network_key=False, acknowledged_transmission=False, fragmentation_permitted=False, include_extended_nonce=False, cluster_id=None):
        return self.manager.send_data(
            asdu,
            destination_address_mode,
            destination_address,
            destination_endpoint,
            alias_address=alias_address,
            alias_sequence_number=alias_sequence_number,
            radius=radius,
            security_enabled_transmission=security_enabled_transmission,
            use_network_key=use_network_key,
            acknowledged_transmission=acknowledged_transmission,
            fragmentation_permitted=fragmentation_permitted,
            include_extended_nonce=include_extended_nonce,
            cluster_id=cluster_id,
            profile_id=self.application_profile_identifier,
            application=self
        )

    def send_interpan_data(self, asdu, asdu_handle=0, source_address_mode=MACAddressMode.SHORT, destination_pan_id=0xFFFF, destination_address=0xFFFF, cluster_id=0):
        return self.manager.send_interpan_data(asdu, asdu_handle=asdu_handle, source_address_mode=source_address_mode, destination_pan_id=destination_pan_id, destination_address=destination_address, profile_id=self.application_profile_identifier, cluster_id=cluster_id)

    def on_interpan_data(self, asdu, cluster_id=0, destination_pan_id=0xFFFF, destination_address=0xFFFF, source_pan_id=0xFFFF, source_address=0xFFFF, link_quality=255):
        for cluster in self.input_clusters:
            if cluster.cluster_id == cluster_id:
                cluster.on_interpan_data(asdu,  destination_pan_id=destination_pan_id, destination_address=destination_address, source_pan_id=source_pan_id, source_address=source_address, link_quality=link_quality)
                return True
        return False

    def on_data(self, asdu, source_address, source_address_mode, cluster_id, security_status, link_quality):
        # Checks if the application exposes a cluster matching the cluster id
        for cluster in self.input_clusters:
            if cluster.cluster_id == cluster_id:
                cluster.on_data(asdu, source_address, source_address_mode, security_status, link_quality)
                return True
        return False
