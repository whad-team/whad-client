"""Protocol hub Dot15d4 PDU messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.zigbee.zigbee_pb2 import SetNodeAddressCmd, AddressType, \
    StartCmd, StopCmd
from whad.hub.dot15d4 import Dot15d4Domain, SendPdu, SendRawPdu, PduReceived, RawPduReceived


@pytest.fixture
def send_pdu():
    """Create Dot15d4 send PDU protocol buffer message
    """
    msg = Message()
    msg.zigbee.send.channel = 26
    msg.zigbee.send.pdu = b"FOOBAR"
    return msg

@pytest.fixture
def send_raw_pdu():
    """Create Dot15d4 send raw PDU protocol buffer message
    """
    msg = Message()
    msg.zigbee.send_raw.channel = 26
    msg.zigbee.send_raw.pdu = b"FOOBAR"
    msg.zigbee.send_raw.fcs = 0x4242
    return msg

@pytest.fixture
def pdu_received():
    """Create Dot15d4 received PDU protocol buffer message
    """
    msg = Message()
    msg.zigbee.pdu.channel = 26
    msg.zigbee.pdu.pdu = b"FOOBAR"
    msg.zigbee.pdu.fcs_validity = True
    msg.zigbee.pdu.rssi = -40
    msg.zigbee.pdu.timestamp = 1234
    return msg

@pytest.fixture
def raw_pdu_received():
    """Create Dot15d4 received raw PDU protocol buffer message
    """
    msg = Message()
    msg.zigbee.raw_pdu.channel = 26
    msg.zigbee.raw_pdu.pdu = b"FOOBAR"
    msg.zigbee.raw_pdu.fcs_validity = True
    msg.zigbee.raw_pdu.rssi = -40
    msg.zigbee.raw_pdu.timestamp = 1234
    msg.zigbee.raw_pdu.fcs = 0xAABB
    return msg

class TestPdu(object):
    """Test PDU-related messages parser/factory
    """

    def test_send_pdu(self, send_pdu):
        """Check Dot15d4 Send message parsing
        """
        parsed_obj = SendPdu.parse(1, send_pdu)
        assert isinstance(parsed_obj, SendPdu)
        assert parsed_obj.channel == 26
        assert parsed_obj.pdu == b"FOOBAR"

    def test_send_raw_pdu(self, send_raw_pdu):
        """Check Dot15d4 Send raw message parsing
        """
        parsed_obj = SendRawPdu.parse(1, send_raw_pdu)
        assert isinstance(parsed_obj, SendRawPdu)
        assert parsed_obj.channel == 26
        assert parsed_obj.pdu == b"FOOBAR"
        assert parsed_obj.fcs == 0x4242

    def test_pdu_received(self, pdu_received):
        """Check Dot15d4 PduReceived message parsing
        """
        parsed_obj = PduReceived.parse(1, pdu_received)
        assert isinstance(parsed_obj, PduReceived)
        assert parsed_obj.channel == 26
        assert parsed_obj.pdu == b"FOOBAR"
        assert parsed_obj.fcs_validity == True
        assert parsed_obj.rssi == -40
        assert parsed_obj.timestamp == 1234
        assert parsed_obj.lqi is None

    def test_raw_pdu_received(self, raw_pdu_received):
        """Check Dot15d4 RawPduReceived message parsing
        """
        parsed_obj = RawPduReceived.parse(1, raw_pdu_received)
        assert isinstance(parsed_obj, RawPduReceived)
        assert parsed_obj.channel == 26
        assert parsed_obj.pdu == b"FOOBAR"
        assert parsed_obj.fcs_validity == True
        assert parsed_obj.rssi == -40
        assert parsed_obj.timestamp == 1234
        assert parsed_obj.lqi is None
        assert parsed_obj.fcs == 0xAABB