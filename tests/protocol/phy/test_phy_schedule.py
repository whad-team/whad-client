"""Protocol hub PHY schedule packet messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.hub.phy import PhyDomain, SchedulePacket, ScheduledPacketSent, SchedulePacketResponse

@pytest.fixture
def schedule_packet_send():
    """Create a SendSchedulePacketCmd protobuf message
    """
    msg = Message()
    msg.phy.sched_send.packet = b"HELLOWORLD"
    msg.phy.sched_send.timestamp = 12349876
    return msg

@pytest.fixture
def schedule_packet_resp():
    """Create a SchedulePacketResp protobuf message
    """
    msg = Message()
    msg.phy.sched_pkt_rsp.id = 1234
    msg.phy.sched_pkt_rsp.full = False
    return msg

@pytest.fixture
def schedule_packet_sent():
    """Create a SchedulePacketSent protobuf message
    """
    msg = Message()
    msg.phy.sched_pkt_sent.id = 1234
    return msg

class TestScheduledPackets(object):
    """Test parsing of scheduled packets commands.
    """

    def test_sched_packet_send_parsing(self, schedule_packet_send):
        """Check parsing of ScheduleSendCmd
        """
        parsed_obj = SchedulePacket.parse(1, schedule_packet_send)
        assert isinstance(parsed_obj, SchedulePacket)
        assert parsed_obj.packet == b"HELLOWORLD"
        assert parsed_obj.timestamp == 12349876

    def test_sched_packet_resp_parsing(self, schedule_packet_resp):
        """Check parsing of ScheduleSendCmd
        """
        parsed_obj = SchedulePacketResponse.parse(1, schedule_packet_resp)
        assert isinstance(parsed_obj, SchedulePacketResponse)
        assert parsed_obj.id == 1234
        assert parsed_obj.full == False

    def test_sched_packet_sent_parsing(self, schedule_packet_sent):
        """Check parsing of ScheduleSendCmd
        """
        parsed_obj = ScheduledPacketSent.parse(1, schedule_packet_sent)
        assert isinstance(parsed_obj, ScheduledPacketSent)
        assert parsed_obj.id == 1234
