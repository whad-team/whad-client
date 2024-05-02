"""Protocol hub Dot15d4 messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.hub.dot15d4 import Dot15d4Domain, SetNodeAddress, NodeAddressShort, NodeAddressExt, \
    NodeAddress, NodeAddressType, SniffMode, JamMode, EnergyDetectionMode, EndDeviceMode, \
    RouterMode, CoordMode, Start, Stop, MitmRole, MitmMode, SendPdu, SendRawPdu, Jammed, \
    EnergyDetectionSample, RawPduReceived, PduReceived

class TestDot15d4DomainFactory(object):
    """Test Dot15d4 factory
    """

    @pytest.fixture
    def factory(self):
        return Dot15d4Domain(1)
    
    def test_set_node_address_short(self, factory: Dot15d4Domain):
        """Test creation of SetNodeAddress message for short addresses
        """
        msg = factory.createSetNodeAddress(NodeAddressShort(0x1234))
        assert isinstance(msg, SetNodeAddress)
        assert msg.address == 0x1234
        assert msg.addr_type == NodeAddressType.SHORT

    def test_set_node_address_ext(self, factory: Dot15d4Domain):
        """Test creation of SetNodeAddress message for extended addresses
        """
        msg = factory.createSetNodeAddress(NodeAddressExt(0x12345678))
        assert isinstance(msg, SetNodeAddress)
        assert msg.address == 0x12345678
        assert msg.addr_type == NodeAddressType.EXTENDED
    
    def test_sniff_mode(self, factory: Dot15d4Domain):
        """Test creation of SniffMode message
        """
        msg = factory.createSniffMode(26)
        assert isinstance(msg, SniffMode)
        assert msg.channel == 26

    def test_jam_mode(self, factory: Dot15d4Domain):
        """Test creation of JamMode message
        """
        msg = factory.createJamMode(26)
        assert isinstance(msg, JamMode)
        assert msg.channel == 26

    def test_energy_detect_mode(self, factory: Dot15d4Domain):
        """Test creation of EnergyDetectionMode message
        """
        msg = factory.createEnergyDetectionMode(26)
        assert isinstance(msg, EnergyDetectionMode)
        assert msg.channel == 26

    def test_end_device_mode(self, factory: Dot15d4Domain):
        """Test creation of EnergyDetectionMode message
        """
        msg = factory.createEndDeviceMode(26)
        assert isinstance(msg, EndDeviceMode)
        assert msg.channel == 26

    def test_router_mode(self, factory: Dot15d4Domain):
        """Test creation of RouterMode message
        """
        msg = factory.createRouterMode(26)
        assert isinstance(msg, RouterMode)
        assert msg.channel == 26

    def test_coord_mode(self, factory: Dot15d4Domain):
        """Test creation of CoordMode message
        """
        msg = factory.createCoordMode(26)
        assert isinstance(msg, CoordMode)
        assert msg.channel == 26

    def test_start(self, factory: Dot15d4Domain):
        """Test creation of Start message
        """
        msg = factory.createStart()
        assert isinstance(msg, Start)

    def test_stop(self, factory: Dot15d4Domain):
        """Test creation of Stop message
        """
        msg = factory.createStop()
        assert isinstance(msg, Stop)

    def test_mitm_mode(self, factory: Dot15d4Domain):
        """Test creation of MitmMode message
        """
        msg = factory.createMitmMode(MitmRole.REACTIVE)
        assert isinstance(msg, MitmMode)
        assert msg.role == MitmRole.REACTIVE

    def test_send_pdu(self, factory: Dot15d4Domain):
        """Test creation of SendPdu message
        """
        msg = factory.createSendPdu(15, b"FOOBAR")
        assert isinstance(msg, SendPdu)
        assert msg.channel == 15
        assert msg.pdu == b"FOOBAR"

    def test_send_raw_pdu(self, factory: Dot15d4Domain):
        """Test creation of SendPdu message
        """
        msg = factory.createSendRawPdu(15, b"FOOBAR", 0xAABB)
        assert isinstance(msg, SendRawPdu)
        assert msg.channel == 15
        assert msg.pdu == b"FOOBAR"
        assert msg.fcs == 0xAABB

    def test_jammed(self, factory: Dot15d4Domain):
        """Test creation of Jammed notification message
        """
        msg = factory.createJammed(1234)
        assert isinstance(msg, Jammed)
        assert msg.timestamp == 1234

    def test_energy_detect_sample(self, factory: Dot15d4Domain):
        """Test creation of EnergyDetectionSample notification message
        """
        msg = factory.createEnergyDetectionSample(1234, 9000)
        assert isinstance(msg, EnergyDetectionSample)
        assert msg.timestamp == 1234
        assert msg.sample == 9000

    def test_raw_pdu_received(self, factory: Dot15d4Domain):
        """Test creation of RawPduReceived notification message
        """
        msg = factory.createRawPduReceived(12, b"HELLOWORLD", 0x1234, rssi=-40, \
                                           fcs_validity=True, lqi=10)
        assert isinstance(msg, RawPduReceived)
        assert msg.channel == 12
        assert msg.pdu == b"HELLOWORLD"
        assert msg.fcs == 0x1234
        assert msg.rssi == -40
        assert msg.timestamp is None
        assert msg.fcs_validity == True
        assert msg.lqi == 10
    
    def test_pdu_received(self, factory: Dot15d4Domain):
        """Test creation of RawPduReceived notification message
        """
        msg = factory.createPduReceived(12, b"HELLOWORLD", timestamp=1234, rssi=-40, \
                                           fcs_validity=False, lqi=10)
        assert isinstance(msg, PduReceived)
        assert msg.channel == 12
        assert msg.pdu == b"HELLOWORLD"
        assert msg.rssi == -40
        assert msg.timestamp == 1234
        assert msg.fcs_validity == False
        assert msg.lqi == 10