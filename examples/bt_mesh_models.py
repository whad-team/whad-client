from whad.bt_mesh.models.states import *
from whad.bt_mesh.models.configuration import ConfigurationModelServer
from whad.bt_mesh.models import GlobalStatesManager, Element
from whad.bt_mesh.crypto import (
    NetworkLayerCryptoManager,
    UpperTransportLayerAppKeyCryptoManager,
)
from whad.scapy.layers.bt_mesh import *

# Example net_key and app_key
primary_net_key = NetworkLayerCryptoManager(
    key_index=0, net_key=bytes.fromhex("7dd7364cd842ad18c17c2b820c84c3d6")
)
app_key = UpperTransportLayerAppKeyCryptoManager(
    app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
    net_key_index=0,
    key_index=0,
)

primary_element = Element(addr=b"\x00\x01", is_primary=True)

global_states = GlobalStatesManager()


conf_model = ConfigurationModelServer(element_addr=primary_element.addr)

# Instance of all states and models for the ConfigurationModelServer
conf_publish_state = ModelPublicationCompositeState()
global_states.add_state(
    conf_publish_state, element_addr=primary_element.addr, model_id=conf_model.model_id
)

conf_sub_state = SubscriptionListState()
global_states.add_state(
    conf_sub_state, element_addr=primary_element.addr, model_id=conf_model.model_id
)

conf_net_key_state = NetKeyListState()
global_states.add_state(conf_net_key_state)
conf_net_key_state.set_value(
    field_name=primary_net_key.key_index, value=primary_net_key
)

conf_app_key_state = AppKeyListState()
conf_app_key_state.set_value(field_name=app_key.key_index, value=app_key)
global_states.add_state(conf_app_key_state)


conf_model_to_app_key = ModelToAppKeyListState()
global_states.add_state(conf_model_to_app_key)

conf_ttl = DefaultTLLState()
global_states.add_state(conf_ttl)

conf_relay = RelayState()
global_states.add_state(conf_relay)

conf_attention = AttentionTimeState()
global_states.add_state(conf_attention)

conf_secure_net_beacon = SecureNetworkBeaconState()
global_states.add_state(conf_secure_net_beacon)

conf_gatt_proxy = GattProxyState()
global_states.add_state(conf_gatt_proxy)

conf_node_id = NodeIdentityState()
global_states.add_state(conf_node_id, net_key_index=primary_net_key.key_index)

conf_hb_pub = HeartbeatPublicationCompositeState()
global_states.add_state(conf_hb_pub)

conf_hb_sub = HeartbeatSubscriptionCompositeState()
global_states.add_state(conf_hb_sub)


primary_element.register_model(conf_model)

pkt = BTMesh_Model_Message() / BTMesh_Model_Config_Model_App_Bind(
    element_addr=b"\x00\x01", app_key_index=0, model_identifier=0
)
primary_element.handle_message(pkt)

print(global_states.get_state("model_to_app_key_list").get_value(0))
