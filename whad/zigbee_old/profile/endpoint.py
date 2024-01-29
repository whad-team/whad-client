from whad.zigbee.stack.apl.zcl import ZCLClientCluster
from whad.zigbee.stack.apl.zcl.clusters import *

class ClusterNotAvailable(Exception):
    pass

class Endpoint:
    def __init__(self, number, device):
        self.__number = number
        self.__device = device
        self.__descriptor = None

    @property
    def descriptor(self):
        if self.__descriptor is None and self.__device.network.is_associated() and self.__device.network.is_authorized():
            self.__descriptor = self.stack.apl.get_application_by_name("zdo").device_and_service_discovery.get_simple_descriptor(self.__device.address, self.__number)
        return self.__descriptor

    @property
    def stack(self):
        return self.__device.stack

    @property
    def device(self):
        return self.__device


    @property
    def profile_id(self):
        return self.descriptor.profile_identifier

    @property
    def device_id(self):
        return self.descriptor.device_identifier

    @property
    def input_clusters(self):
        return self.descriptor.input_clusters

    @property
    def output_clusters(self):
        return self.descriptor.output_clusters

    def attach_to_input_cluster(self, cluster_id, application=None):
        # Check if the cluster number is in the endpoint's input cluster list
        if cluster_id not in self.descriptor.input_clusters:
            raise ClusterNotAvailable

        # Select the first application matching the profile
        selected_application = None
        for application in self.stack.apl.get_applications():
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
            for candidate_cluster_class in ZCLClientCluster.child_clusters(): # Only works with ZCL, we should adapt it for other clusters
                if candidate_cluster_class().cluster_id == cluster_id:
                    selected_cluster = candidate_cluster_class()
                    break

        if selected_cluster is not None:
            selected_application.add_output_cluster(selected_cluster)
            selected_cluster.connect(self.device.address, self.number)
            
        return selected_cluster


    @property
    def number(self):
        return self.__number

    def __repr__(self):
        return "Endpoint(#%d, input_clusters=%s, output_clusters=%s)" % (self.number, str(self.input_clusters), str(self.output_clusters))
