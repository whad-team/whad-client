from whad.zigbee.stack.apl.zcl import ZCLClientCluster
from whad.zigbee.stack.apl.zcl.clusters import *
"""
This module defines classes and exceptions related to ZigBee node's Endpoints.
"""

class ClusterNotAvailable(Exception):
    """
    Exception raised when a cluster is not available.
    """
    pass

class Endpoint:
    def __init__(self, number, node):
        self.__number = number
        self.__node = node
        self.__descriptor = None

    @property
    def descriptor(self):
        """
        Property returning the descriptor associated to this endpoint.
        """

        if (
            self.__descriptor is None and
            self.__node.network.is_associated() and
            self.__node.network.is_authorized()
        ):
            self.__descriptor = self.stack.get_layer('apl').get_application_by_name("zdo").device_and_service_discovery.get_simple_descriptor(
                self.__node.address,
                self.__number
            )
        return self.__descriptor

    @property
    def stack(self):
        """
        Property returning the stack instance linked to this endpoint.
        """
        if self.__node is None:
            return None
        return self.__node.stack

    @property
    def node(self):
        """
        Property returning of this endpoint.
        """
        return self.__node


    @property
    def profile_id(self):
        """
        Property returning the profile ID of this endpoint.
        """
        return self.descriptor.profile_identifier

    @property
    def device_id(self):
        """
        Property indicating the device ID of this endpoint.
        """
        return self.descriptor.device_identifier

    @property
    def input_clusters(self):
        """
        Property returning the input clusters of this endpoint.
        """
        return self.descriptor.input_clusters

    @property
    def output_clusters(self):
        """
        Property returning the output clusters of this endpoint.
        """
        return self.descriptor.output_clusters

    def attach_to_input_cluster(self, cluster_id, application=None):
        """
        Attach the endpoint to an input cluster in the stack, according
        to the cluster id.
        """
        # Check if the cluster number is in the endpoint's input cluster list
        if cluster_id not in self.descriptor.input_clusters:
            raise ClusterNotAvailable

        # Select the first application matching the profile
        selected_application = None
        for application in self.stack.get_layer('apl').get_applications():
            if application.profile_id == self.profile_id:
                selected_application = application
                break

        # Check if a matching client cluster exists in our application
        selected_cluster = None
        for cluster in selected_application.output_clusters:
            if cluster.cluster_id == cluster_id:
                selected_cluster = cluster
                break

        if selected_cluster is None:
            # Only works with ZCL, we should adapt it for other clusters
            for candidate_cluster_class in ZCLClientCluster.child_clusters():
                if candidate_cluster_class().cluster_id == cluster_id:
                    selected_cluster = candidate_cluster_class()
                    break

        if selected_cluster is not None:
            selected_application.add_output_cluster(selected_cluster)
            selected_cluster.connect(self.node.address, self.number)

        return selected_cluster


    @property
    def number(self):
        return self.__number

    def __repr__(self):
        return "Endpoint(#%d, input_clusters=%s, output_clusters=%s)" % (self.number, str(self.input_clusters), str(self.output_clusters))
