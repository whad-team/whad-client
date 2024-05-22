from whad.dot15d4.stack.mac.constants import MACAddressMode

class Cluster:
    """
    This class represents a ZigBee cluster.

    Every application exposes several input and output clusters, that will
    act as server / client for a specific task.
    """
    def __init__(self, cluster_id):
        # Cluster definition
        self.cluster_id = cluster_id

        # Reference to application is populated when the cluster is attached to an app.
        self.application = None

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
                    use_network_key=True,
                    acknowledged_transmission=False,
                    fragmentation_permitted=False,
                    include_extended_nonce=False
    ):
        """
        This method allows to send a Data PDU to the underlying application.
        """
        if self.application is None:
            return False

        return self.application.send_data(
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
            cluster_id=self.cluster_id
        )

    def send_interpan_data(
                            self,
                            asdu,
                            asdu_handle=0,
                            source_address_mode=MACAddressMode.SHORT,
                            destination_pan_id=0xFFFF,
                            destination_address=0xFFFF,
                            destination_address_mode=MACAddressMode.SHORT,
                            acknowledged_transmission=False
    ):
        """
        This method allows to send an InterPAN PDU to the underlying application.
        """
        if self.application is None:
            return False

        return self.application.send_interpan_data(
            asdu,
            asdu_handle=asdu_handle,
            source_address_mode=source_address_mode,
            destination_pan_id=destination_pan_id,
            destination_address=destination_address,
            destination_address_mode=destination_address_mode,
            acknowledged_transmission=acknowledged_transmission,
            cluster_id=self.cluster_id
        )

    def on_data(
                self,
                asdu,
                source_address,
                source_address_mode,
                security_status,
                link_quality
    ):
        """
        This method is called when the underlying application forwards a Data PDU to the cluster.
        """
        pass

    def on_interpan_data(
                self,
                asdu,
                destination_pan_id,
                destination_address,
                source_pan_id,
                source_address,
                link_quality
    ):
        """
        This method is called when the underlying application forwards an InterPAN PDU to the cluster.
        """
        pass
