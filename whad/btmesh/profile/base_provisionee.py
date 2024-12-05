"""
Bluetooth Mesh Base Profile

Supports only the Configuration Server Model on the primary element
"""

from whad.btmesh.models import Element, GlobalStatesManager
from whad.btmesh.models.configuration import ConfigurationModelServer
from whad.btmesh.models.states import (
    ModelPublicationCompositeState,
    SubscriptionListState,
    NetKeyListState,
    AppKeyListState,
    ModelToAppKeyListState,
    DefaultTLLState,
    RelayState,
    AttentionTimeState,
    SecureNetworkBeaconState,
    GattProxyState,
    NodeIdentityState,
    HeartbeatPublicationCompositeState,
    HeartbeatSubscriptionCompositeState,
    SARReceiverCompositeState,
    SARTransmitterCompositeState,
)
from whad.btmesh.profile import BaseMeshProfile


class BaseMeshProfileProvisionee(BaseMeshProfile):
    """
    Base class for Blutooth Mesh Profiles as a provisionee node (other profiles should inherit this one)
    """

    def __init__(self):
        # Elements of the node. Ordered.
        super().__init__()

    def __populate_base_models_and_states(self):
        """
        Populate elements and models for the node (except the ConfigurationModelServer and primary element creation, by default)
        """
        pass

