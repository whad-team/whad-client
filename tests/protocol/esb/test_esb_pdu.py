"""Protocol hub ESB PDU messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.esb.esb_pb2 import StartCmd as EsbStartCmd, StopCmd as EsbStopCmd
from whad.hub.esb import SendPdu, SendRawPdu, PduReceived, RawPduReceived

DEFAULT_NODE_ADDR = bytes([0x11, 0x22, 0x33, 0x44, 0x55])

@pytest.fixture
def send_esb_pdu():
    """Create a SendPdu protobuf message
    """
    msg = Message()
    msg.esb.send.channel = 12
    msg.esb.send.pdu = b"HELLOWORLD"
    msg.esb.send.retransmission_count = 1
    return msg

@pytest.fixture
def send_esb_raw_pdu():
    """Create a SendRawPdu protobuf message
    """
    msg = Message()
    msg.esb.send_raw.channel = 15
    msg.esb.send_raw.pdu = b"HELLOWORLD_RAW"
    msg.esb.send_raw.retransmission_count = 3
    return msg

@pytest.fixture
def esb_pdu():
    """Create a PduReceived protobuf message
    """
    msg = Message()
    msg.esb.pdu.channel = 10
    msg.esb.pdu.rssi = -58
    msg.esb.pdu.timestamp = 1234
    msg.esb.pdu.address = DEFAULT_NODE_ADDR
    msg.esb.pdu.pdu = b"FOOBAR"
    return msg

@pytest.fixture
def esb_raw_pdu():
    """Create a RawPduReceived protobuf message
    """
    msg = Message()
    msg.esb.raw_pdu.channel = 37
    msg.esb.raw_pdu.rssi = -40
    msg.esb.raw_pdu.address = DEFAULT_NODE_ADDR
    msg.esb.raw_pdu.pdu = b"FOOBAR"
    msg.esb.raw_pdu.crc_validity = True
    return msg

class TestEsbPduParsing(object):
    """Check ESB PDU messages parsing
    """

    def test_send_pdu(self, send_esb_pdu):
        """Check SendPdu parsing
        """
        parsed_obj = SendPdu.parse(1, send_esb_pdu)
        assert isinstance(parsed_obj, SendPdu)
        assert parsed_obj.channel == 12
        assert parsed_obj.pdu == b"HELLOWORLD"
        assert parsed_obj.retr_count == 1

    def test_send_raw_pdu(self, send_esb_raw_pdu):
        """Check SendRawPdu parsing
        """
        parsed_obj = SendRawPdu.parse(1, send_esb_raw_pdu)
        assert isinstance(parsed_obj, SendRawPdu)
        assert parsed_obj.channel == 15
        assert parsed_obj.pdu == b"HELLOWORLD_RAW"
        assert parsed_obj.retr_count == 3

    def test_pdu_received(self, esb_pdu):
        """Check PduReceived notification parsing
        """
        parsed_obj = PduReceived.parse(1, esb_pdu)
        assert isinstance(parsed_obj, PduReceived)
        assert parsed_obj.channel == 10
        assert parsed_obj.rssi == -58
        assert parsed_obj.timestamp == 1234
        assert parsed_obj.address == DEFAULT_NODE_ADDR
        assert parsed_obj.pdu == b"FOOBAR"
        assert parsed_obj.crc_validity is None

    def test_raw_pdu_received(self, esb_raw_pdu):
        """Check RawPduReceived notification parsing
        """
        parsed_obj = RawPduReceived.parse(1, esb_raw_pdu)
        assert isinstance(parsed_obj, RawPduReceived)
        assert parsed_obj.channel == 37
        assert parsed_obj.rssi == -40
        assert parsed_obj.timestamp is None
        assert parsed_obj.address == DEFAULT_NODE_ADDR
        assert parsed_obj.pdu == b"FOOBAR"
        assert parsed_obj.crc_validity == True
