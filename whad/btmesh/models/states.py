"""
Definition of the Mesh States actual values.

For now seems very useless and repetitive, but needed that layer of abstaction for Bound States
"""

from whad.btmesh.models import ModelState, CompositeModelState


"""
Model Publication Composition State
"""


class ModelPublicationAddressState(ModelState):
    def __init__(self):
        super().__init__(
            name="model_publication_publish_address", default_value=b"\x00\x00"
        )


class ModelPublicationPeriodState(ModelState):
    def __init__(self):
        super().__init__(name="model_publication_publish_period", default_value=None)

        self.values["nb_of_steps"] = 0b00
        self.values["step_resolution"] = 0x01

    def get_publish_period(self):
        return self.get_value("nb_of_steps") * self.get_value("step_resolution")


class ModelPublicationAppKeyIndexState(ModelState):
    def __init__(self):
        super().__init__(
            name="model_publication_publish_app_key_index", default_value=0
        )


class ModelPublicationFriendshipCredentialFlagState(ModelState):
    def __init__(self):
        super().__init__(
            name="model_publication_publish_friendship_credential_flag", default_value=0
        )


class ModelPublicationTTLState(ModelState):
    def __init__(self):
        super().__init__(name="model_publication_publish_ttl", default_value=0xFF)


class ModelPublicationRetransmitCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="model_publication_publish_retransmit_count", default_value=0b011
        )


class ModelPublicationRetransmitIntervalStepsState(ModelState):
    def __init__(self):
        super().__init__(
            name="model_publication_publish_retransmit_interval_steps",
            default_value=0b10000,
        )

    def get_retransmission_interval(self):
        return (self.get_value() + 1) * 50


# COMPOSITE STATE
class ModelPublicationCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="model_publication",
            sub_states_cls=[
                ModelPublicationAddressState,
                ModelPublicationPeriodState,
                ModelPublicationAppKeyIndexState,
                ModelPublicationFriendshipCredentialFlagState,
                ModelPublicationTTLState,
                ModelPublicationRetransmitCountState,
                ModelPublicationRetransmitIntervalStepsState,
            ],
        )


"""
END MODEL Publication
"""


class SubscriptionListState(ModelState):
    """
    Should have one per Model.
    Extended and base model share one List !
    One list for label UUIDs (for virtual addresses)
    One for groups addrs
    """

    def __init__(self):
        super().__init__(name="subscription_list", default_value=None)

        self.values["label_uuids"] = []
        self.values["group_addrs"] = [b"\xff\xff"]  # Add the all-nodes addr


class NetKeyListState(ModelState):
    def __init__(self):
        """
        NetKey List State
        Each field has a NetworkLayerCryptoManager object
        Field name = net_key_index
        """
        super().__init__(
            name="net_key_list",
            default_value=None,
        )


class AppKeyListState(ModelState):
    def __init__(self):
        """
        AppKey List State

        Each field has a UpperLayerAppKeyCryptoManager object
        Field name = app_key_index
        """
        super().__init__(
            name="app_key_list",
            default_value=None,
        )


class ModelToAppKeyListState(ModelState):
    def __init__(self):
        """
        Each field has a list of app_key_indexes
        Field name is the model_id
        """
        super().__init__(name="model_to_app_key_list", default_value=None)


class DefaultTLLState(ModelState):
    def __init__(self):
        super().__init__(name="default_ttl", default_value=0x00)


class RelayState(ModelState):
    def __init__(self):
        super().__init__(name="relay", default_value=0x02)


class AttentionTimeState(ModelState):
    def __init__(self):
        super().__init__(name="attention_timer_state", default_value=0x00)


class SecureNetworkBeaconState(ModelState):
    def __init__(self):
        super().__init__(name="secure_network_beacon", default_value=0x00)


class GattProxyState(ModelState):
    """
    Need BOUNDED with DirectedForwardingCompositeStet -> DirectedProxy State
    """

    def __init__(self):
        super().__init__(name="gatt_proxy", default_value=0x02)

    def commit_to_bound_states(self):
        if self.get_value() == 0:
            try:
                if self.bound_states["directed_proxy"].get_value() != 0x02:
                    self.bound_states["directed_proxy"].set_value(0)
            except KeyError:
                print("MISSING BOUND STATE IN GattProxyState")


class NodeIdentityState(ModelState):
    def __init__(self):
        super().__init__(name="node_identity", default_value=0x02)


class FriendState(ModelState):
    """
    Needs DirectedFriendState BOUNDED
    """

    def __init__(self):
        super().__init__(name="friend", default_value=0x02)

    def commit_to_bound_states(self):
        if self.get_value() == 0x00:
            try:
                if self.bound_states["directed_friend"].get_value() != 0x02:
                    self.bound_states["directed_friend"].set_value(0)
            except KeyError:
                print("MISSING BOUND STATE IN FriendState")


class KeyRefreshPhaseState(ModelState):
    def __init__(self):
        super().__init__(name="key_refresh_phase", default_value=0x00)


"""
CURRENT HEALTH FAULT COMPOSITE STATE
"""


class CurrentHealthFaultState(ModelState):
    def __init__(self):
        super().__init__(name="current_health_fault", default_value=None)

        self.values["test_id"] = 0x00
        self.values["fault_array"] = []


class RegisteredFaultState(ModelState):
    def __init__(self):
        super().__init__(name="health_fault", default_value=None)

        self.values["test_id"] = 0x00
        self.values["fault_array"] = []


class CurrentHealthFaultCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="current_health",
            sub_states_cls=[CurrentHealthFaultState, RegisteredFaultState],
        )


"""
CURRENT HEALTH FAULT COMPOSITE STATE END
"""


class HealthFastPeriodDivisorState(ModelState):
    def __init__(self):
        super().__init__(name="health_fast_period_division", default_value=1)


"""
HEARTBEAT PUBLICATION COMPOSITE STATE
"""


class HeartbeatPublicationDestinationState(ModelState):
    def __init__(self):
        super().__init__(
            name="heartbeat_publication_destination", default_value=b"\x00\x00"
        )


class HeartbeatPublicationCountState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_publication_count", default_value=0x00)


class HeartbeatPublicationPeriodLogState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_publication_period_log", default_value=0x00)


class HeartbeatPublicationTTLState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_publication_ttl", default_value=0x00)


class HeartbeatPublicationFeaturesState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_publication_features", default_value=0x00)


class HeartbeatPublicationNetKeyIndexState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_publication_net_key_index", default_value=0x00)


class HeartbeatPublicationCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="heartbeat_publication",
            sub_states_cls=[
                HeartbeatPublicationDestinationState,
                HeartbeatPublicationCountState,
                HeartbeatPublicationPeriodLogState,
                HeartbeatPublicationTTLState,
                HeartbeatPublicationFeaturesState,
                HeartbeatPublicationNetKeyIndexState,
            ],
        )


"""
HEARTBEAT PUBLICATION COMPOSITE STATE END
"""


"""
Hearbeat Subscription COMPOSITE STATE
"""


class HeartbeatSubscriptionSourceState(ModelState):
    def __init__(self):
        super().__init__(
            name="heartbeat_subscription_source", default_value=b"\x00\x00"
        )


class HeartbeatSubscriptionDestinationState(ModelState):
    def __init__(self):
        super().__init__(
            name="heartbeat_subscription_destination", default_value=b"\x00\x00"
        )


class HeartbeatSubscriptionCountState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_subscription_count", default_value=0x0000)


class HeartbeatSubscriptionPeriodState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_subscription_period", default_value=0x00)


class HeartbeatSubscriptionMinHopsState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_subscription_min_hops", default_value=0x00)


class HeartbeatSubscriptionMaxHopsState(ModelState):
    def __init__(self):
        super().__init__(name="heartbeat_subscription_max_hops", default_value=0x00)


class HeartbeatSubscriptionCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="heartbeat_subscription",
            sub_states_cls=[
                HeartbeatSubscriptionSourceState,
                HeartbeatSubscriptionDestinationState,
                HeartbeatSubscriptionCountState,
                HeartbeatSubscriptionPeriodState,
                HeartbeatSubscriptionMinHopsState,
                HeartbeatSubscriptionMaxHopsState,
            ],
        )


"""
Heatbeat SUBSCRIPTION COMPOSITE STATE END
"""


"""
NETWORK TRANSMIT COMPOSITE STATE
"""


class NetworkTransmitCountState(ModelState):
    def __init__(self):
        super().__init__(name="network_transmit_count", default_value=0b000)


class NetworkTransmitIntervalStepsState(ModelState):
    def __init__(self):
        super().__init__(name="network_transmit_interval_steps", default_value=0b00000)


class NetworkTransmitCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="network_transmit",
            sub_states_cls=[
                NetworkTransmitCountState,
                NetworkTransmitIntervalStepsState,
            ],
        )


"""
NETWORK TRANSMIT COMPOSITE STATE END
"""

"""
RELAY TRANSMIT COMPOSITE STATE
"""


class RelayRetransmitCountState(ModelState):
    def __init__(self):
        super().__init__(name="relay_retransmit_count", default_value=0b000)


class RelayRetransmitIntervalStepsState(ModelState):
    def __init__(self):
        super().__init__(name="relay_retransmit_interval_steps", default_value=0b00000)


class RelayTransmitCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="relay_retransmit",
            sub_states_cls=[
                RelayRetransmitCountState,
                RelayRetransmitIntervalStepsState,
            ],
        )


"""
RELAY TRANSMIT COMPOSITE STATE END
"""


class PollTimeoutListState(ModelState):
    """
    Each field hasthe current value for the LPN in key.
    Field names are the addr of the associated LPN
    """

    def __init__(self):
        super().__init__(name="poll_timeout_list", default_value=None)


"""
REMOTE PROVISIONING SCAN CAPABILITIES COMPOSITE STATE
"""


class RemoteProvisioningMaxScannedItemsState(ModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisioning_max_scanned_items", default_value=0x04
        )


class RemoteProvisioningActiveScanState(ModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisioning_active_scan_state", default_value=0x00
        )


class RemoteProvisioningScanCapabilitiesCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisioning_scan_capabilities",
            sub_states_cls=[
                RemoteProvisioningMaxScannedItemsState,
                RemoteProvisioningActiveScanState,
            ],
        )


"""
REMOTE PROVISIONING SCAN CAPABILITIES COMPOSITE STATE END
"""


"""
REMOTE PROVISIONING SCAN PARAMETERS COMPOSITE STATE START
"""


class RemoteProvisioningScanState(ModelState):
    def __init__(self):
        super().__init__(name="remote_provisioning_scan_state", default_value=0x00)


class RemoteProvisioningScanItemsLimitState(ModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisioning_scan_items_limit", default_value=0x01
        )


class RemoteProvisioningTimeoutState(ModelState):
    def __init__(self):
        super().__init__(name="remote_provisioning_timeout", default_value=0x00)


class RemoteProvisoningScanParametersCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisioning_scan_parameters",
            sub_states_cls=[
                RemoteProvisioningScanState,
                RemoteProvisioningScanItemsLimitState,
                RemoteProvisioningTimeoutState,
            ],
        )


"""
REMOTE PROVISIONING SCAN PARAMETERS COMPOSITE STATE END
"""


"""
REMOTE PROVISIONING LINK PARAMETERS 
"""


class RemoteProvisioningLinkState(ModelState):
    def __init__(self):
        super().__init__(name="remote_provisioning_link", default_value=0x00)


class RemoteProvisioningDeviceUUIDState(ModelState):
    def __init__(self):
        super().__init__(name="remote_provisioning_device_uuid", default_value=0x00)


class RemoteProvisoningOutboundPDUCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisioning_outbound_pdu_count", default_value=0x00
        )


class RemoteProvisioningInboundPDUCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisioning_inbound_pdu_count", default_value=0x00
        )


class RemoteProvisioningLinkCloseReasonState(ModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisioning_link_close_reason", default_value=0x00
        )


class RemoteProvisioningLinkCloseStatusState(ModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisoning_link_close_status", default_value=0x00
        )


class RemoteProvisoningLinkParametersCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="remote_provisionig_link_parameters",
            sub_states_cls=[
                RemoteProvisioningLinkState,
                RemoteProvisioningDeviceUUIDState,
                RemoteProvisoningOutboundPDUCountState,
                RemoteProvisioningInboundPDUCountState,
                RemoteProvisioningLinkCloseReasonState,
                RemoteProvisioningLinkCloseStatusState,
            ],
        )


"""
REMOTE PROVISIONING LINK PARAMETERS END
"""

"""
DIRECTED CONTROL COMPOSITE STATE
"""


class DirectedForwardingState(ModelState):
    """
    Need DirectedRelayState, DirectedProxyState, DirectedFriendState BOUNDED
    """

    def __init__(self):
        super().__init__(name="directed_forwarding", default_value=0x00)

    def commit_to_bound_states(self):
        if self.get_value() == 0:
            try:
                self.bound_states["directed_relay"].set_value(0)
                if self.bound_states["directed_proxy"].get_value() != 0x02:
                    self.bound_states["directed_proxy"].set_value(0)
                if self.bound_states["directed_friend"].get_value() != 0x02:
                    self.bound_states["directed_friend"].set_value(0)
            except KeyError:
                print("MISSING BOUND STATES IN DIRECTED FORWARDING STATE")


class DirectedRelayState(ModelState):
    def __init__(self):
        super().__init__(name="directed_relay", default_value=0x00)


class DirectedProxyState(ModelState):
    """
    NEED DirectedProxyUseDirectDefault BOUNDED
    """

    def __init__(self):
        super().__init__(name="directed_proxy", default_value=0x00)

    def commit_to_bound_states(self):
        if self.get_value() == 0:
            try:
                self.bound_states["directed_proxy_use_default"].set_value(0x02)
            except KeyError:
                print("MISSING BOUND STATE IN DirectedProxyState")


class DirectedProxyUseDirectDefaultState(ModelState):
    def __init__(self):
        super().__init__(name="directed_proxy_use_default", default_value=0x02)


class DirectedFriendState(ModelState):
    def __init__(self):
        super().__init__(name="directed_friend", default_value=0x02)


class DirectedControlCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="directed_control",
            sub_states_cls=[
                DirectedForwardingState,
                DirectedRelayState,
                DirectedProxyState,
                DirectedProxyUseDirectDefaultState,
                DirectedFriendState,
            ],
        )

        self.get_sub_state("directed_forwarding").add_bound_state(
            self.get_sub_state("directed_relay")
        )
        self.get_sub_state("directed_forwarding").add_bound_state(
            self.get_sub_state("directed_proxy")
        )
        self.get_sub_state("directed_forwarding").add_bound_state(
            self.get_sub_state("directed_friend")
        )
        self.get_sub_state("directed_proxy").add_bound_state(
            self.get_sub_state("directed_proxy_use_default")
        )


"""
DIRECTED CONTROL COMPOSITE STATE END
"""


"""
PATH METRIC COMPOSITE STATE
"""


class PathMetricTypeState(ModelState):
    def __init__(self):
        super().__init__(name="path_metric_type", default_value=0b000)


class PathLifetimeState(ModelState):
    def __init__(self):
        super().__init__(name="path_lifetime", default_value=0b10)


class PathMetricCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="path_metric",
            sub_states_cls=[PathMetricTypeState, PathLifetimeState],
        )


"""
PATH METRIC COMPOSITE STATE END
"""


"""
DISCOVERY TABLE CAPABILITIES COMPOSITE STATE
"""


class MaxDiscoveryTableEntriesCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="max_discovery_table_entries_count_state", default_value=0x02
        )


class MaxConcurrentInitState(ModelState):
    def __init__(self):
        super().__init__(name="max_concurrent_init", default_value=0x02)


class DiscoveryTableCapabitlitiesCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="discovery_table_capanilities",
            sub_states_cls=[MaxDiscoveryTableEntriesCountState, MaxConcurrentInitState],
        )


"""
DISCOVERY TABLE CAPABILITIES COMPOSITE STATE END
"""


"""
FORWARDING TABLE COMPOSITE STATE
"""


class ForwardingTableUpdateIdentifierState(ModelState):
    def __init__(self):
        super().__init__(name="forwarding_table_update_identifier", default_value=0x00)


class ForwardingTableEntry:
    """
    Entry of the Forwarding Table, used in ForwardingTableEntriesState
    Check out Mesh PRT Spec Section 4.2.29.2 for details ...
    """

    def __init__(
        self,
        fixed_path=1,
        backward_validated_path=1,
        path_not_ready=1,
        path_origin=b"\x00\x00",
        path_origin_secondary_elements_count=0,
        dependent_origin_list=[],
        dependent_origin_secondary_elements_count_list=[],
        destination=b"\x00\x00",
        path_target_secondary_elements_count=0,
        dependent_target_list=[],
        dependent_target_secondary_elements_count_list=[],
        forwarding_number=0,
        bearer_toward_path_origin=0x0000,
        bearer_toward_path_target=0x0000,
    ):
        self.fixed_path = fixed_path
        self.backward_validated_path = backward_validated_path
        self.path_not_ready = path_not_ready
        self.path_origin = path_origin
        self.path_origin_secondary_elements_count = path_origin_secondary_elements_count
        self.dependent_origin_list = dependent_origin_list
        self.dependent_origin_secondary_elements_count_list = (
            dependent_origin_secondary_elements_count_list
        )
        self.destination = destination
        self.path_target_secondary_elements_count = path_target_secondary_elements_count
        self.dependent_target_list = dependent_target_list
        self.dependent_target_secondary_elements_count_list = (
            dependent_target_secondary_elements_count_list
        )
        self.forwarding_number = forwarding_number
        self.bearer_toward_path_origin = bearer_toward_path_origin
        self.bearer_toward_path_target = bearer_toward_path_target


class ForwardingTableEntriesState(ModelState):
    """
    Each field is indexed with numbers starting with 0.
    Contains a ForwardingTableEntry object
    """

    def __init__(self):
        super().__init__(name="forwarding_table_entries", default_value=None)


class ForwardingTableCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="forwarding_table",
            sub_states_cls=[
                ForwardingTableUpdateIdentifierState,
                ForwardingTableEntriesState,
            ],
        )


"""
FORWARDING TABLE COMPOSITE STATE END
"""


# Thede 2 states I have no idea what they are bound to...
class WantedLanesState(ModelState):
    def __init__(self):
        super().__init__(name="wanted_lanes", default_value=0x01)


class TwoWayPathState(ModelState):
    def __init__(self):
        super().__init__(name="two_way_path", default_value=0b1)


"""
PATH ECHO INTERVAL COMPOSITE STATE
"""


class UnicastEchoIntervalState(ModelState):
    def __init__(self):
        super().__init__(name="unicast_echo_interval", default_value=0x00)


class MulticastEchoIntervalState(ModelState):
    def __init__(self):
        super().__init__(name="multicast_echo_interval", default_value=0x00)


class PathEchoIntervalCompositState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="path_echo_interval",
            sub_states_cls=[UnicastEchoIntervalState, MulticastEchoIntervalState],
        )


"""
PATH ECHO INTERVAL COMPOSITE STATE END
"""


"""
Directed Network Transmit Composite State
"""


class DirectedNetworkTransitCountState(ModelState):
    def __init__(self):
        super().__init__(name="directed_network_transmit_count", default_value=0b001)


class DirectedNetworkTransmitIntervalStepsState(ModelState):
    def __init__(self):
        super().__init__(
            name="directed_network_transmit_interval_steps", default_value=0b01001
        )

    def get_transmission_interval(self):
        return (self.get_value() + 1) * 10


class DirectedNetworkTransmitCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="directed_network_transmit",
            sub_states_cls=[
                DirectedNetworkTransitCountState,
                DirectedNetworkTransmitIntervalStepsState,
            ],
        )


"""
Directed Network Transmit Composite State END
"""

"""
Directed Relay ReTransmit Composite State
"""


class DirectedRelayRetransmitCountState(ModelState):
    def __init__(self):
        super().__init__(name="directed_relay_retransmit_count", default_value=0b010)


class DirectedRelayRetransmitIntervalSteps(ModelState):
    def __init__(self):
        super().__init__(
            name="directed_relay_retransmit_interval_steps", default_value=0b01001
        )

    def get_transmission_interval(self):
        return (self.get_value() + 1) * 10


class DirectedRelayRetransmitCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="directed_relay_retransmit",
            sub_states_cls=[
                DirectedRelayRetransmitCountState,
                DirectedRelayRetransmitIntervalSteps,
            ],
        )


"""
Directed Relay ReTransmit Composite State
"""

"""
RSSI THRESHOLD COMPOSITE STATE
"""


class DefaultRSSIThresholdState(ModelState):
    def __init__(self):
        super().__init__(name="default_rssi_threshold", default_value=40)


class RSSIMarginState(ModelState):
    def __init__(self):
        super().__init__(name="rssi_margin", default_value=0x14)


class RSSIThresholdCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="rssi_threshold",
            sub_states_cls=[DefaultRSSIThresholdState, RSSIMarginState],
        )


"""
RSSI THRESHOLD COMPOSITE STATE
"""

"""
DIRECTED PATHS COMPOSITE STATE
"""


class DirectedNodePathsState(ModelState):
    def __init__(self):
        super().__init__(name="directed_node_paths", default_value=20)


class DirectedRelayPathsState(ModelState):
    def __init__(self):
        super().__init__(name="directed_relay_paths", default_value=20)


class DirectedProxyPathsState(ModelState):
    def __init__(self):
        super().__init__(name="directed_proxy_paths", default_value=0)


class DirectedFriendPathsState(ModelState):
    def __init__(self):
        super().__init__(name="directed_friend_paths", default_value=0)


class DirectedPathsCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="directed_paths",
            sub_states_cls=[
                DirectedNodePathsState,
                DirectedRelayPathsState,
                DirectedProxyPathsState,
                DirectedFriendPathsState,
            ],
        )


"""
DIRECTED PATHS COMPOSITE STATE END
"""


class DirectedPublishPolicyState(ModelState):
    def __init__(self):
        super().__init__(name="directed_publish_policy", default_value=0x00)


"""
Path DISCOVERY TIMING CONTROL COMPOSITE STATE
"""


class PathMonitoringIntervalState(ModelState):
    def __init__(self):
        super().__init__(name="path_monitoring_intevral", default_value=120)


class PathDiscoveryRetryIntervalState(ModelState):
    def __init__(self):
        super().__init__(name="path_discovery_retry_interval", default_value=300)


class PathDiscoveryIntervalState(ModelState):
    def __init__(self):
        super().__init__(name="path_discovery_interval", default_value=0b1)


class LaneDiscoveryGuardIntervalState(ModelState):
    def __init__(self):
        super().__init__(name="lane_discovery_guard_interval", default_value=0b1)


class PathDiscoveryTimingControlCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="path_discovery_timing_controll",
            sub_states_cls=[
                PathMonitoringIntervalState,
                PathDiscoveryRetryIntervalState,
                PathDiscoveryIntervalState,
                LaneDiscoveryGuardIntervalState,
            ],
        )


"""
Path DISCOVERY TIMING CONTROL COMPOSITE STATE
"""

"""
DIRECTED CONTROL NETWORK TRANSMIT COMPOSITE STATE
"""


class DirectedControlNetworkTransmitCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="directed_control_network_transmit_count", default_value=0b001
        )


class DirectedControlNetworkTransmitIntervalSteps(ModelState):
    def __init__(self):
        super().__init__(
            name="directed_control_network_transmit_interval_steps",
            default_value=0b10000,
        )

    def get_transmission_interval(self):
        return (self.get_value() + 1) * 10


class DirectedControlNetworkTransmitCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="directed_control_network_transmit",
            sub_states_cls=[
                DirectedNetworkTransitCountState,
                DirectedNetworkTransmitIntervalStepsState,
            ],
        )


"""
DIRECTED CONTROL NETWORK TRANSMIT COMPOSITE STATE END
"""

"""
DIRECTED CONTROL RELAY TRANSMIT COMPOSITE STATE
"""


class DirectedControlRelayTransmitCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="directed_control_relay_transmit_count", default_value=0b010
        )


class DirectedControlRelayTransmitIntervalSteps(ModelState):
    def __init__(self):
        super().__init__(
            name="directed_control_relay_transmit_interval_steps",
            default_value=0b01001,
        )

    def get_transmission_interval(self):
        return (self.get_value() + 1) * 10


class DirectedControlRelayTransmitCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="directed_control_relay_transmit",
            sub_states_cls=[
                DirectedNetworkTransitCountState,
                DirectedNetworkTransmitIntervalStepsState,
            ],
        )


"""
DIRECTED CONTROL RELAY TRANSMIT COMPOSITE STATE END
"""


class SubnetBridgeState(ModelState):
    def __init__(self):
        super().__init__(name="subnet_bridge", default_value=0x00)


class BridgingTableEntry:
    """
    USed in BridgingTableState
    Check out MEsh PRT Spec Section 4.2.42
    """

    def __init__(
        self,
        directions=0x02,
        net_key_index1=0x0000,
        net_key_index2=0x0000,
        addr1=0x0000,
        addr2=0x0000,
    ):
        self.directions = directions
        self.net_key_index1 = net_key_index1
        self.net_key_index2 = net_key_index2
        self.addr1 = addr1
        self.addr2 = addr2


class BridgingTableState(ModelState):
    """
    Field name = index of entry (not important)
    Values = BridgingTableEntry objects
    BOUND STATE FOR NETKEYLIST NOT IMPLEMENTED
    """

    def __init__(self):
        super().__init__(name="bridging_table", default_value=None)


class BridgingTableSizeState(ModelState):
    def __init__(self):
        super().__init__(name="bridging_table_size", default_value=16)


"""
MESH PRIVATE BEACON COMPOSITE STATE
"""


class PrivateBeaconState(ModelState):
    def __init__(self):
        super().__init__(name="private_beacon", default_value=0)


class RandomUpdateIntervalSteps(ModelState):
    def __init__(self):
        super().__init__(name="random_update_interval_steps", default_value=0x3C)


class MeshPrivateBeaconCompositeState(CompositeModelState):
    def __init__(self):
        super().__init__(
            name="mesh_private_beacon",
            sub_states_cls=[PrivateBeaconState, RandomUpdateIntervalSteps],
        )


"""
MESH PRIVATE BEACON COMPOSITE STATE END
"""


class PrivateGattProxyState(ModelState):
    """
    Binding not DONE (proxy not implemented anyway)
    """

    def __init__(self):
        super().__init__(name="private_gatt_proxy", default_value=0x02)


class PrivateNodeIdentityState(ModelState):
    """
    Binding not done
    """

    def __init__(self):
        super().__init__(
            name="private_node_identity", default_value=0x02
        )


class OnDemandeGATTProxyState(ModelState):
    """
    BINDING NOT DONE
    """

    def __init__(self):
        super().__init__(name="on_demande_gatt_proxy", default_value=0x00)


"""
SAR TRANSMITTER COMPOSITE STATE

IS INSTANCED IN THE CONFIGURATION SERVER MODEL !!!
"""


class SARSegmentIntervalStepState(ModelState):
    def __init__(self):
        super().__init__(name="sar_segment_interval_step", default_value=0b0101)

    def get_segment_retransmission_interval(self):
        return (self.get_value() + 1) * 10


class SARUnicastRetransmissionsCountState(ModelState):
    def __init__(self):
        super().__init__(name="sar_unicast_retransmissions_count", default_value=0b0011)


class SATUnicastRetransmissionsWithoutProgressCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="sar_unicast_retransmissions_without_progess_count",
            default_value=0b0011,
        )


class SARUnicastRetransmissionsIntervalStepState(ModelState):
    def __init__(self):
        super().__init__(
            name="sar_unicast_restransmissions_intreval_step", default_value=0b0111
        )

    def get_unicast_retransmission_interval_step(self):
        return (self.get_value() + 1) * 25


class SARUnicastRetransmissionsIntervalIncrementState(ModelState):
    def __init__(self):
        super().__init__(
            name="sar_unicast_retransmissions_interval_increment", default_value=0b0001
        )

    def get_unicast_restransmission_interval_increment(self):
        return (self.get_value() + 1) * 25


class SARMulticastRetransmissionsCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="sar_multicast_retransmissions_count", default_value=0x0010
        )


class SARMulticastRetransmissionsIntervalStepState(ModelState):
    def __init__(self):
        super().__init__(
            name="sar_multicast_retransmissions_interval_step", default_value=0b1001
        )

    def get_multicast_retransmissions_interval(self):
        return (self.get_value() + 1) * 25


class SARTransmitterCompositeState(CompositeModelState):
    """
    IS INSTANCED IN THE CONFIGURATION SERVER MODEL !!!
    """

    def __init__(self):
        super().__init__(
            name="sar_transmitter",
            sub_states_cls=[
                SARSegmentIntervalStepState,
                SARUnicastRetransmissionsCountState,
                SATUnicastRetransmissionsWithoutProgressCountState,
                SARUnicastRetransmissionsIntervalStepState,
                SARUnicastRetransmissionsIntervalIncrementState,
                SARMulticastRetransmissionsCountState,
                SARMulticastRetransmissionsIntervalStepState,
            ],
        )


"""
SAR TRANSMITTER COMPOSITE STATE END
"""

"""
SAR RECEIVER COMPOSITE STATE

IS INSTANCED IN THE CONFIGURATION SERVER MODEL !!!
"""


class SARSegmentThresholdState(ModelState):
    def __init__(self):
        super().__init__(name="sar_segment_threshold", default_value=0b00011)


class SARAcknowledgmentDelayIncrementState(ModelState):
    def __init__(self):
        super().__init__(name="sar_acknowledgment_delay_increment", default_value=0b001)

    def get_acknowledgement_increment(self):
        return self.get_value() + 1.5


class SARAcknowledgmentRetransmissionsCountState(ModelState):
    def __init__(self):
        super().__init__(
            name="sar_acknowledgment_retransmissions_count", default_value=0b00
        )


class SARDiscardTimeoutState(ModelState):
    def __init__(self):
        super().__init__(name="sar_discard_timeout", default_value=0b0001)

    def get_discard_timeout(self):
        return (self.get_value() + 1) * 5


class SARReceiverSegmentIntervalStepState(ModelState):
    def __init__(self):
        super().__init__(
            name="sar_receiver_segment_interval_step", default_value=0b0101
        )

    def get_segment_reception_interval(self):
        return (self.get_value() + 1) * 10


class SARReceiverCompositeState(CompositeModelState):
    """
    IS INSTANCED IN THE CONFIGURATION SERVER MODEL !!!
    """
    def __init__(self):
        super().__init__(
            name="sar_receiver",
            sub_states_cls=[
                SARSegmentThresholdState,
                SARAcknowledgmentDelayIncrementState,
                SARAcknowledgmentDelayIncrementState,
                SARAcknowledgmentRetransmissionsCountState,
                SARDiscardTimeoutState,
                SARReceiverSegmentIntervalStepState,
            ],
        )


"""
SAR RECEIVER COMPOSITE STATE END
"""


class GenericOnOffState(ModelState):
    def __init__(self):
        super().__init__(name="generic_onoff", default_value=0x00)
