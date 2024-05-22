from whad.dot15d4.stack.mac.constants import MACAddressMode
from whad.zigbee.stack.apl.zdo.descriptors import SimpleDescriptor
class ApplicationObject:
    """
    This class implements an Application Object.
    In ZigBee stack, the APL layer forwards data to various applications, modelised as Application Objects.
    This class is the base class representing such an Application Object.
    """
    def __init__(
                    self,
                    name,
                    profile_id,
                    device_id,
                    device_version=0,
                    input_clusters=[],
                    output_clusters=[]
    ):
        # Reference to the manager will be populated when App is attached
        self.manager = None

        # App definition and identification
        self.name = name
        self.profile_id = profile_id
        self.device_id = device_id
        self.device_version = device_version

        # Input and output clusters, processing events
        self.input_clusters = input_clusters
        self.output_clusters = output_clusters

        # Link every cluster to the application
        for cluster in self.input_clusters + self.output_clusters:
            cluster.application = self

    @property
    def simple_descriptor(self):
        if self.manager is None:
            return None

        # Look for our own endpoint
        own_endpoint = None
        for endpoint, app in self.manager.endpoints.items():
            if app == self:
                own_endpoint = endpoint
                break

        if own_endpoint is None:
            return None

        return SimpleDescriptor(
                endpoint=own_endpoint,
                profile_identifier=self.profile_id,
                device_identifier=self.device_id,
                device_version=self.device_version,
                input_clusters=[cluster.cluster_id for cluster in app.input_clusters],
                output_clusters=[cluster.cluster_id  for cluster in app.output_clusters]
        )

    def initialize(self):
        """
        Initializes the application.
        """
        pass

    def start(self):
        """
        Starts the application.
        """
        pass

    def add_input_cluster(self, cluster):
        """
        Add an input cluster to the application.
        """
        self.input_clusters.append(cluster)
        cluster.application = self

    def add_output_cluster(self, cluster):
        """
        Add an output cluster to the application.
        """
        self.output_clusters.append(cluster)
        cluster.application = self


    def send_data(
                    self,
                    asdu,
                    destination_address_mode,
                    destination_address,
                    destination_endpoint,
                    alias_address=None,
                    alias_sequence_number=0,
                    radius=30,
                    security_enabled_transmission=False,
                    use_network_key=False,
                    acknowledged_transmission=False,
                    fragmentation_permitted=False,
                    include_extended_nonce=False,
                    cluster_id=None
    ):
        """
        Transmits a Data PDU through the APL layer.
        """
        if self.manager is None:
            return False

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
            profile_id=self.profile_id,
            application=self
        )

    def send_interpan_data(
                            self,
                            asdu,
                            asdu_handle=0,
                            source_address_mode=MACAddressMode.SHORT,
                            destination_pan_id=0xFFFF,
                            destination_address=0xFFFF,
                            destination_address_mode=MACAddressMode.SHORT,
                            cluster_id=0,
                            acknowledged_transmission=False
    ):
        """
        Transmits an InterPAN PDU through the APL layer.
        """

        if self.manager is None:
            return False

        return self.manager.send_interpan_data(
            asdu,
            asdu_handle=asdu_handle,
            source_address_mode=source_address_mode,
            destination_pan_id=destination_pan_id,
            destination_address=destination_address,
            destination_address_mode=destination_address_mode,
            profile_id=self.profile_id,
            cluster_id=cluster_id,
            acknowledged_transmission=acknowledged_transmission
        )

    def on_interpan_data(
                            self,
                            asdu,
                            cluster_id=0,
                            destination_pan_id=0xFFFF,
                            destination_address=0xFFFF,
                            source_pan_id=0xFFFF,
                            source_address=0xFFFF,
                            link_quality=255
    ):
        """
        Processes an InterPAN PDU from the APL layer.

        This method forwards the InterPAN PDU to the right cluster according
        to the cluster ID.
        """
        # Iterate over all clusters
        for cluster in self.input_clusters + self.output_clusters:
            # If a cluster matches, forwards the PDU to it
            if cluster.cluster_id == cluster_id:
                cluster.on_interpan_data(
                    asdu,
                    destination_pan_id=destination_pan_id,
                    destination_address=destination_address,
                    source_pan_id=source_pan_id,
                    source_address=source_address,
                    link_quality=link_quality
                )
                return True
        return False

    def on_data(
                self,
                asdu,
                source_address,
                source_address_mode,
                cluster_id,
                security_status,
                link_quality
    ):
        """
        Processes a Data PDU from the APL layer.

        This method forwards the Data PDU to the right cluster according
        to the cluster ID.
        """
        for cluster in self.input_clusters + self.output_clusters:
            # Iterate over all clusters
            if cluster.cluster_id == cluster_id:
                # If a cluster matches, forwards the PDU to it
                cluster.on_data(
                                asdu,
                                source_address,
                                source_address_mode,
                                security_status,
                                link_quality
                )
                return True
        return False
