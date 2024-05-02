"""Protocol hub PHY packet messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.phy.phy_pb2 import Endianness, TXPower
from whad.hub.phy import PhyDomain, SetDatarate, SetEndianness, SetTxPower, SetPacketSize, \
    SetSyncWord, SendPacket, SendRawPacket, PacketReceived, RawPacketReceived

@pytest.fixture
def set_datarate():
    """Create a SetDatrarateCmd protobuf message
    """
    msg = Message()
    msg.phy.datarate.rate = 50000
    return msg

@pytest.fixture
def set_endianness():
    """Create a SetDatrarateCmd protobuf message
    """
    msg = Message()
    msg.phy.endianness.endianness = Endianness.LITTLE
    return msg

@pytest.fixture
def set_txpower():
    """Create a SetDatrarateCmd protobuf message
    """
    msg = Message()
    msg.phy.tx_power.tx_power = TXPower.MEDIUM
    return msg

@pytest.fixture
def set_packet_size():
    """Create a SetPacketSizeCmd protobuf message
    """
    msg = Message()
    msg.phy.packet_size.packet_size = 32
    return msg

@pytest.fixture
def set_sync_word():
    """Create a SetSyncWordCmd protobuf message
    """
    msg = Message()
    msg.phy.sync_word.sync_word = b"AAAA"
    return msg

@pytest.fixture
def send_packet():
    """Create a SendCmd protobuf message
    """
    msg = Message()
    msg.phy.send.packet = b"FOOBAR"
    return msg

@pytest.fixture
def send_raw_packet():
    """Create a SendCmd protobuf message
    """
    msg = Message()
    msg.phy.send_raw.iq.append(42)
    msg.phy.send_raw.iq.append(-42)
    return msg

@pytest.fixture
def packet_received():
    """Create a PacketReceivedCmd protobuf message
    """
    msg = Message()
    msg.phy.packet.frequency=2404000000
    msg.phy.packet.rssi = -40
    msg.phy.packet.timestamp.sec=1234
    msg.phy.packet.timestamp.usec=9876
    msg.phy.packet.packet = b"HELLOWORLD"
    return msg

@pytest.fixture
def raw_packet_received():
    """Create a PacketReceivedCmd protobuf message
    """
    msg = Message()
    msg.phy.raw_packet.frequency=2404000000
    msg.phy.raw_packet.rssi = -40
    msg.phy.raw_packet.timestamp.sec=1234
    msg.phy.raw_packet.timestamp.usec=9876
    msg.phy.raw_packet.packet = b"HELLOWORLD"
    return msg

class TestPacketConfig(object):
    """Test parsing of PHY packet configuration messages.
    """

    def test_datarate_parsing(self, set_datarate):
        """Check parsing of SetDataRateCmd
        """
        parsed_obj = SetDatarate.parse(1, set_datarate)
        assert isinstance(parsed_obj, SetDatarate)
        assert parsed_obj.rate == 50000

    def test_endianness_parsing(self, set_endianness):
        """Check parsing of SetEndiannessCmd
        """
        parsed_obj = SetEndianness.parse(1, set_endianness)
        assert isinstance(parsed_obj, SetEndianness)
        assert parsed_obj.endianness == Endianness.LITTLE

    def test_txpower_parsing(self, set_txpower):
        """Check parsing of SetTxPowerCmd
        """
        parsed_obj = SetTxPower.parse(1, set_txpower)
        assert isinstance(parsed_obj, SetTxPower)
        assert parsed_obj.power == TXPower.MEDIUM

    def test_packetsize_parsing(self, set_packet_size):
        """Check parsing of SetTxPowerCmd
        """
        parsed_obj = SetPacketSize.parse(1, set_packet_size)
        assert isinstance(parsed_obj, SetPacketSize)
        assert parsed_obj.packet_size == 32

    def test_sync_word_parsing(self, set_sync_word):
        """Check parsing of SetSyncWordCmd
        """
        parsed_obj = SetSyncWord.parse(1, set_sync_word)
        assert isinstance(parsed_obj, SetSyncWord)
        assert parsed_obj.sync_word == b"AAAA"

    def test_send_packet_parsing(self, send_packet):
        """Check parsing of SendCmd
        """
        parsed_obj = SendPacket.parse(1, send_packet)
        assert isinstance(parsed_obj, SendPacket)
        assert parsed_obj.packet == b"FOOBAR"

    def test_send_raw_packet_parsing(self, send_raw_packet):
        """Check parsing of SendRawCmd
        """
        parsed_obj = SendRawPacket.parse(1, send_raw_packet)
        assert isinstance(parsed_obj, SendRawPacket)
        assert len(parsed_obj.iq) == 2

    def test_packet_recvd_parsing(self, packet_received):
        """Check parsing of SendRawCmd
        """
        parsed_obj = PacketReceived.parse(1, packet_received)
        assert isinstance(parsed_obj, PacketReceived)
        assert parsed_obj.frequency == 2404000000
        assert parsed_obj.rssi == -40
        assert parsed_obj.timestamp.sec == 1234
        assert parsed_obj.timestamp.usec == 9876
        assert parsed_obj.packet == b"HELLOWORLD"

    def test_raw_packet_recvd_parsing(self, raw_packet_received):
        """Check parsing of SendRawCmd
        """
        parsed_obj = RawPacketReceived.parse(1, raw_packet_received)
        assert isinstance(parsed_obj, RawPacketReceived)
        assert parsed_obj.frequency == 2404000000
        assert parsed_obj.rssi == -40
        assert parsed_obj.timestamp.sec == 1234
        assert parsed_obj.timestamp.usec == 9876
        assert parsed_obj.packet == b"HELLOWORLD"
