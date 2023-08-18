'''BLE stack Link-layer unit tests

This module provides 3 sets of tests:

- TestBleStackLinkLayerSupportedPDUs: checks all the supported PDUs are correctly handled
- TestBleStackUnsupportedPDUs: checks all unsupported PDUs generate errors
- TestBleStackL2CAPForwarding: check that data PDU are forwarded to L2CAP layer

'''
import pytest

from scapy.layers.bluetooth4LE import *

from whad.common.stack import alias
from whad.common.stack.tests import Sandbox, LayerMessage

from whad.ble.stack.constants import BtVersion
from whad.ble.stack.llm import LinkLayer, CONNECTION_UPDATE_REQ, \
    CHANNEL_MAP_REQ, ENC_REQ, ENC_RSP, START_ENC_REQ, START_ENC_RSP, \
    FEATURE_RSP, PAUSE_ENC_REQ, PAUSE_ENC_RSP, SLAVE_FEATURE_REQ, \
    CONNECTION_PARAM_REQ, CONNECTION_PARAM_RSP, REJECT_IND, REJECT_IND_EXT, \
    PING_REQ, PING_RSP, LENGTH_REQ, LENGTH_RSP

# Create our sandboxed link-layer (mock phy layer)
@alias('phy')
class LLSandbox(Sandbox):

    @property
    def bt_version(self):
        return BtVersion(4, 0)

    @property
    def manufacturer_id(self):
        return 0x0002

    @property
    def bt_sub_version(self):
        return 0x0100

LLSandbox.add(LinkLayer)


class BleLLTest(object):

    @pytest.fixture
    def sandbox(self):
        return LLSandbox()

    @pytest.fixture
    def phy_layer(self, sandbox):
        return sandbox.get_layer('phy')
    
    @pytest.fixture
    def phy_instance(self, phy_layer):
        phy_layer.get_layer('ll').state.connections[42] = {
            'l2cap': 'l2cap#0',
            'version_sent': False,  # version exchanged
            'version_remote': None,
            'nb_pdu_recvd': 0
        }
        return phy_layer

# Test supported control PDUs
class TestBleStackLinkLayerSupportedPDUs(BleLLTest):
    

    def test_feature_req(self, phy_instance):
        '''Processing of LL_FEATURE_REQ
        '''
        phy_instance.send('ll', BTLE_CTRL()/LL_FEATURE_REQ(), tag='control', conn_handle=42)
        assert phy_instance.expect(LayerMessage(
            'll',
            'phy',
            BTLE_CTRL() / LL_FEATURE_RSP(feature_set=[
                'le_encryption',
                'le_ping'                
            ]),
            tag='control',
            encrypt=None
        ))

    def test_version_ind(self, phy_instance):
        '''Processing LL_VERSION_IND
        '''
        phy_instance.send('ll', BTLE_CTRL()/LL_VERSION_IND(), tag='control', conn_handle=42)
        assert phy_instance.expect(LayerMessage(
        'll',
        'phy',
        BTLE_CTRL() / LL_VERSION_IND(
            version=0x06,
            company=0x0002,
            subversion=0x0100
        ),
        tag='control',
        encrypt=None
        ))

    def test_terminate_ind(self, phy_instance):
        '''Processing LL_TERMINATE_IND
        '''
        phy_instance.send('ll', BTLE_CTRL()/LL_TERMINATE_IND(code=0x12), tag='control', conn_handle=42)
        
        # We expect the connection to have been removed
        with pytest.raises(IndexError):
            phy_instance.get_layer('ll').state.get_connection(42)


# Test unsupported control PDUs

class TestBleStackUnsupportedPDUs(BleLLTest):

    unsupported_pdus = [
        (BleLLTest.phy_instance, LL_CONNECTION_UPDATE_IND(), LL_UNKNOWN_RSP(code=CONNECTION_UPDATE_REQ)),
        (BleLLTest.phy_instance, LL_CHANNEL_MAP_IND(), LL_UNKNOWN_RSP(code=CHANNEL_MAP_REQ)),
        (BleLLTest.phy_instance, LL_ENC_REQ(), LL_UNKNOWN_RSP(code=ENC_REQ)),
        (BleLLTest.phy_instance, LL_ENC_RSP(), LL_UNKNOWN_RSP(code=ENC_RSP)),
        (BleLLTest.phy_instance, LL_START_ENC_REQ(), LL_UNKNOWN_RSP(code=START_ENC_REQ)),
        (BleLLTest.phy_instance, LL_START_ENC_RSP(), LL_UNKNOWN_RSP(code=START_ENC_RSP)),
        (BleLLTest.phy_instance, LL_PAUSE_ENC_REQ(), LL_UNKNOWN_RSP(code=PAUSE_ENC_REQ)),
        (BleLLTest.phy_instance, LL_PAUSE_ENC_RSP(), LL_UNKNOWN_RSP(code=PAUSE_ENC_RSP)),
        (BleLLTest.phy_instance, LL_SLAVE_FEATURE_REQ(), LL_UNKNOWN_RSP(code=SLAVE_FEATURE_REQ)),
        (BleLLTest.phy_instance, LL_CONNECTION_PARAM_REQ(), LL_UNKNOWN_RSP(code=CONNECTION_PARAM_REQ)),
        (BleLLTest.phy_instance, LL_PING_REQ(), LL_UNKNOWN_RSP(code=PING_REQ)),
        (BleLLTest.phy_instance, LL_LENGTH_REQ(), LL_UNKNOWN_RSP(code=LENGTH_REQ)),
    ]

    @pytest.mark.parametrize("phy_instance,pdu,expected", unsupported_pdus, indirect=["phy_instance"])
    def test_unsupported_op(self, phy_instance, pdu, expected):
        phy_instance.send('ll', BTLE_CTRL() / pdu, tag='control', conn_handle=42)
        assert phy_instance.expect(LayerMessage(
            'll',
            'phy',
            BTLE_CTRL() / expected,
            tag='control',
            encrypt=None
        ))

class TestBleStackL2CAPForwarding:

    @pytest.fixture
    def phy_layer(self):
        return LLSandbox()

    @pytest.fixture
    def phy_instance(self, phy_layer):
        phy_layer.get_layer('ll').state.connections[42] = {
            'l2cap': 'l2cap#0',
            'version_sent': False,  # version exchanged
            'version_remote': None,
            'nb_pdu_recvd': 0
        }
        return phy_layer
    
    # Test L2CAP forwarding
    def test_l2cap_forwarding(self, phy_instance):
        '''Forward a L2CAP packet to our link-layer manager
        '''
        phy_instance.send('ll', BTLE_DATA()/L2CAP_Hdr()/b'TestPayload', tag='data', conn_handle=42)
        assert phy_instance.expect(LayerMessage(
            'll',
            'l2cap#0',
            bytes(L2CAP_Hdr()/b'TestPayload'),
            fragment=False,
            encrypt=None
        ))