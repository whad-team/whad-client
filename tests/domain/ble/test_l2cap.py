'''BLE L2CAP protocol layer unit tests.

This module provides a single set of tests:

- TestL2CAPLayer: checks L2CAP encapsulation works as expected

'''
import pytest

from scapy.layers.bluetooth4LE import L2CAP_Hdr
from scapy.layers.bluetooth import ATT_Hdr

from whad.common.stack import alias
from whad.common.stack.tests import Sandbox, LayerMessage
from whad.ble.stack.l2cap import L2CAPLayer
from whad.ble.stack.att import ATTLayer
from whad.ble.stack.gatt import GattLayer

# Remove ATT and GATT layer to avoid them being instantiated
# when L2CAPLayer is instantiated.
L2CAPLayer.remove(ATTLayer)
L2CAPLayer.remove(GattLayer)


@alias('ll')
class LinkLayerMock(Sandbox):

    def __init__(self, parent=None, layer_name=None, options={}):
        super().__init__(parent=parent, layer_name=layer_name, options=options)
        
        # Instantiate a L2CAP layer and configure target
        self.__l2cap = self.instantiate(L2CAPLayer)
        self.target = self.__l2cap.name

    @property
    def l2cap(self):
        return self.__l2cap
LinkLayerMock.add(L2CAPLayer)
    
class L2CAPTest(object):

    @pytest.fixture
    def ll_instance(self):
        return LinkLayerMock()

class TestL2CAPLayer(L2CAPTest):

    def test_non_fragmented_data(self, ll_instance):
        # Send an encapsulated L2CAP packet
        packet = L2CAP_Hdr() / ATT_Hdr() / b'Payload'
        
        # We need to serialize/deserialize to force scapy to fill all the fields
        expected_result = ATT_Hdr(bytes(packet[ATT_Hdr]))

        # Send packet
        ll_instance.send(ll_instance.target, bytes(packet), fragment=False)
        
        # Check L2CAP sent data to ATT
        assert ll_instance.expect(LayerMessage(
            ll_instance.target,
            'att',
            expected_result,
            tag='default'
        ))

    def test_fragmented_data(self, ll_instance):
        # Create an encapsulated L2CAP packet
        packet = L2CAP_Hdr() / ATT_Hdr() / b'ThisIsAlongPayload'
        expected_result = ATT_Hdr(bytes(packet[ATT_Hdr]))
        # Split packet
        packet = bytes(packet)
        packet_0 = packet[:6]
        packet_1 = packet[6:]

        # Send first part
        ll_instance.send(ll_instance.target, packet_0, fragment=True)

        # Second part
        ll_instance.send(ll_instance.target, packet_1, fragment=True)

        # Check data has been forwarded to ATT
        assert ll_instance.expect(LayerMessage(
            ll_instance.target,
            'att',
            expected_result,
            tag='default'
        ))