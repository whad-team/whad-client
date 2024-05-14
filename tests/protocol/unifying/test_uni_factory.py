"""Protocol hub ESB factory unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.hub.esb import EsbNodeAddress, EsbNodeAddressError
from whad.hub.unifying import UnifyingDomain, SetNodeAddress, SniffMode, JamMode, Jammed, SendPdu, \
    SendRawPdu, PduReceived, RawPduReceived, UnifyingStart, UnifyingStop, DongleMode, \
    KeyboardMode, MouseMode, SniffPairing

from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble.chanmap import DefaultChannelMap

DEFAULT_NODE_ADDRESS = EsbNodeAddress(0x1122334455, 5)

class TestBleDomainFactory(object):
    """Test BleDomain factory
    """

    @pytest.fixture
    def factory(self):
        return UnifyingDomain(1)

    def test_SetNodeAddress(self, factory: UnifyingDomain):
        """Check SetNodeAddress crafting
        """
        msg = factory.createSetNodeAddress(DEFAULT_NODE_ADDRESS)
        assert isinstance(msg, SetNodeAddress)
        assert msg.address == DEFAULT_NODE_ADDRESS.value

    def test_SniffMode(self, factory: UnifyingDomain):
        """Check SniffMode crafting
        """
        msg = factory.createSniffMode(DEFAULT_NODE_ADDRESS, 12, True)
        assert isinstance(msg, SniffMode)
        assert msg.address == DEFAULT_NODE_ADDRESS.value
        assert msg.channel == 12
        assert msg.show_acks == True

    def test_JamMode(self, factory: UnifyingDomain):
        """Check JamMode crafting
        """
        msg = factory.createJamMode(32)
        assert isinstance(msg, JamMode)
        assert msg.channel == 32

    def test_Jammed(self, factory: UnifyingDomain):
        """Check Jammed crafting
        """
        msg = factory.createJammed(1234)
        assert isinstance(msg, Jammed)
        assert msg.timestamp == 1234

    def test_SendPdu(self, factory: UnifyingDomain):
        """Check SendPdu crafting
        """
        msg = factory.createSendPdu(27, b"FOOBAR", 1)
        assert isinstance(msg, SendPdu)
        assert msg.channel == 27
        assert msg.pdu == b"FOOBAR"
        assert msg.retr_count == 1

    def test_SendRawPdu(self, factory: UnifyingDomain):
        """Check SendRawPdu crafting
        """
        msg = factory.createSendRawPdu(11, b"HELLOWORLD", 2)
        assert isinstance(msg, SendRawPdu)
        assert msg.channel == 11
        assert msg.pdu == b"HELLOWORLD"
        assert msg.retr_count == 2

    def test_PduReceived_0(self, factory: UnifyingDomain):
        """Check PduReceived crafting
        """
        msg = factory.createPduReceived(17, b"FOOBAR")
        assert isinstance(msg, PduReceived)
        assert msg.channel == 17
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi is None
        assert msg.timestamp is None
        assert msg.address is None
        assert msg.crc_validity is None

    def test_PduReceived_1(self, factory: UnifyingDomain):
        """Check PduReceived crafting, including rssi
        """
        msg = factory.createPduReceived(5, b"FOOBAR", rssi=-40)
        assert isinstance(msg, PduReceived)
        assert msg.channel == 5
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi == -40
        assert msg.timestamp is None
        assert msg.address is None
        assert msg.crc_validity is None

    def test_PduReceived_2(self, factory: UnifyingDomain):
        """Check PduReceived crafting, including timestamp
        """
        msg = factory.createPduReceived(5, b"FOOBAR",timestamp=1234)
        assert isinstance(msg, PduReceived)
        assert msg.channel == 5
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi is None
        assert msg.timestamp == 1234
        assert msg.address is None
        assert msg.crc_validity is None

    def test_PduReceived_3(self, factory: UnifyingDomain):
        """Check PduReceived crafting, including address
        """
        msg = factory.createPduReceived(5, b"FOOBAR", address=DEFAULT_NODE_ADDRESS)
        assert isinstance(msg, PduReceived)
        assert msg.channel == 5
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi is None
        assert msg.timestamp is None
        assert msg.address == DEFAULT_NODE_ADDRESS.value
        assert msg.crc_validity is None

    def test_PduReceived_4(self, factory: UnifyingDomain):
        """Check PduReceived crafting, including crc_validity
        """
        msg = factory.createPduReceived(5, b"FOOBAR", crc_validity=True)
        assert isinstance(msg, PduReceived)
        assert msg.channel == 5
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi is None
        assert msg.timestamp is None
        assert msg.address is None
        assert msg.crc_validity == True

    def test_RawPduReceived_0(self, factory: UnifyingDomain):
        """Check RawPduReceived crafting
        """
        msg = factory.createRawPduReceived(17, b"FOOBAR")
        assert isinstance(msg, RawPduReceived)
        assert msg.channel == 17
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi is None
        assert msg.timestamp is None
        assert msg.address is None
        assert msg.crc_validity is None

    def test_RawPduReceived_1(self, factory: UnifyingDomain):
        """Check RawPduReceived crafting, including rssi
        """
        msg = factory.createRawPduReceived(5, b"FOOBAR", rssi=-40)
        assert isinstance(msg, RawPduReceived)
        assert msg.channel == 5
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi == -40
        assert msg.timestamp is None
        assert msg.address is None
        assert msg.crc_validity is None

    def test_RawPduReceived_2(self, factory: UnifyingDomain):
        """Check RawPduReceived crafting, including timestamp
        """
        msg = factory.createRawPduReceived(5, b"FOOBAR",timestamp=1234)
        assert isinstance(msg, RawPduReceived)
        assert msg.channel == 5
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi is None
        assert msg.timestamp == 1234
        assert msg.address is None
        assert msg.crc_validity is None

    def test_RawPduReceived_3(self, factory: UnifyingDomain):
        """Check RawPduReceived crafting, including address
        """
        msg = factory.createRawPduReceived(5, b"FOOBAR", address=DEFAULT_NODE_ADDRESS)
        assert isinstance(msg, RawPduReceived)
        assert msg.channel == 5
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi is None
        assert msg.timestamp is None
        assert msg.address == DEFAULT_NODE_ADDRESS.value
        assert msg.crc_validity is None

    def test_RawPduReceived_4(self, factory: UnifyingDomain):
        """Check RawPduReceived crafting, including crc_validity
        """
        msg = factory.createRawPduReceived(5, b"FOOBAR", crc_validity=True)
        assert isinstance(msg, RawPduReceived)
        assert msg.channel == 5
        assert msg.pdu == b"FOOBAR"
        assert msg.rssi is None
        assert msg.timestamp is None
        assert msg.address is None
        assert msg.crc_validity == True

    def test_DongleMode(self, factory: UnifyingDomain):
        """Check DongleMode crafting
        """
        msg = factory.createDongleMode(18)
        assert isinstance(msg, DongleMode)
        assert msg.channel == 18

    def test_KeyboardMode(self, factory: UnifyingDomain):
        """Check KeyboardMode crafting
        """
        msg = factory.createKeyboardMode(18)
        assert isinstance(msg, KeyboardMode)
        assert msg.channel == 18

    def test_MouseMode(self, factory: UnifyingDomain):
        """Check MouseMode crafting
        """
        msg = factory.createMouseMode(18)
        assert isinstance(msg, MouseMode)
        assert msg.channel == 18

    def test_SniffPairing(self, factory: UnifyingDomain):
        """Check SniffPairing crafting
        """
        msg = factory.createSniffPairing()
        assert isinstance(msg, SniffPairing)

    def test_UnifyingStart(self, factory: UnifyingDomain):
        """Check EsbStart crafting
        """
        msg = factory.createStart()
        assert isinstance(msg, UnifyingStart)

    def test_UnifyingStop(self, factory: UnifyingDomain):
        """Check EsbStop crafting
        """
        msg = factory.createStop()
        assert isinstance(msg, UnifyingStop)