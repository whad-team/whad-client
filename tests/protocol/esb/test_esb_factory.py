"""Protocol hub ESB factory unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.hub.esb import EsbDomain, SetNodeAddress, SniffMode, JamMode, Jammed, SendPdu, \
    SendRawPdu, PduReceived, RawPduReceived, PrxMode, PtxMode, EsbStart, EsbStop, \
    EsbNodeAddress, EsbNodeAddressError

from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble.chanmap import DefaultChannelMap

DEFAULT_NODE_ADDRESS = EsbNodeAddress(0x1122334455, 5)

class TestBleDomainFactory(object):
    """Test BleDomain factory
    """

    @pytest.fixture
    def factory(self):
        return EsbDomain(1)
    
    def test_EsbNodeAddress_int(self, factory: EsbDomain):
        """Check ESB node address creation from integer
        """
        addr = EsbNodeAddress(0x1122334455, 5)
        assert addr.value == bytes([0x11, 0x22, 0x33, 0x44, 0x55])

    def test_EsbNodeAddress_bytes(self, factory: EsbDomain):
        """Check ESB node address creation from integer
        """
        addr = EsbNodeAddress(bytes([0x11, 0x22, 0x33, 0x44, 0x55]))
        assert addr.value == bytes([0x11, 0x22, 0x33, 0x44, 0x55])

    def test_EsbNodeAddress_overflow(self, factory: EsbDomain):
        """Check ESB node address creation from integer
        """
        with pytest.raises(EsbNodeAddressError):
            addr = EsbNodeAddress(0x1122334455, 3)

    def test_EsbNodeAddress_toobig(self, factory: EsbDomain):
        """Check ESB node address creation from integer
        """
        with pytest.raises(EsbNodeAddressError):
            addr = EsbNodeAddress(0x11223344556677, 7)

    def test_SetNodeAddress(self, factory: EsbDomain):
        """Check SetNodeAddress crafting
        """
        msg = factory.createSetNodeAddress(DEFAULT_NODE_ADDRESS)
        assert isinstance(msg, SetNodeAddress)
        assert msg.address == DEFAULT_NODE_ADDRESS.value

    def test_SniffMode(self, factory: EsbDomain):
        """Check SniffMode crafting
        """
        msg = factory.createSniffMode(DEFAULT_NODE_ADDRESS, 12, True)
        assert isinstance(msg, SniffMode)
        assert msg.address == DEFAULT_NODE_ADDRESS.value
        assert msg.channel == 12
        assert msg.show_acks == True

    def test_JamMode(self, factory: EsbDomain):
        """Check JamMode crafting
        """
        msg = factory.createJamMode(32)
        assert isinstance(msg, JamMode)
        assert msg.channel == 32

    def test_Jammed(self, factory: EsbDomain):
        """Check Jammed crafting
        """
        msg = factory.createJammed(1234)
        assert isinstance(msg, Jammed)
        assert msg.timestamp == 1234

    def test_SendPdu(self, factory: EsbDomain):
        """Check SendPdu crafting
        """
        msg = factory.createSendPdu(27, b"FOOBAR", 1)
        assert isinstance(msg, SendPdu)
        assert msg.channel == 27
        assert msg.pdu == b"FOOBAR"
        assert msg.retr_count == 1

    def test_SendRawPdu(self, factory: EsbDomain):
        """Check SendRawPdu crafting
        """
        msg = factory.createSendRawPdu(11, b"HELLOWORLD", 2)
        assert isinstance(msg, SendRawPdu)
        assert msg.channel == 11
        assert msg.pdu == b"HELLOWORLD"
        assert msg.retr_count == 2

    def test_PduReceived_0(self, factory: EsbDomain):
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

    def test_PduReceived_1(self, factory: EsbDomain):
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

    def test_PduReceived_2(self, factory: EsbDomain):
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

    def test_PduReceived_3(self, factory: EsbDomain):
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

    def test_PduReceived_4(self, factory: EsbDomain):
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

    def test_RawPduReceived_0(self, factory: EsbDomain):
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

    def test_RawPduReceived_1(self, factory: EsbDomain):
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

    def test_RawPduReceived_2(self, factory: EsbDomain):
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

    def test_RawPduReceived_3(self, factory: EsbDomain):
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

    def test_RawPduReceived_4(self, factory: EsbDomain):
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

    def test_PrxMode(self, factory: EsbDomain):
        """Check PrxMode crafting
        """
        msg = factory.createPrxMode(18)
        assert isinstance(msg, PrxMode)
        assert msg.channel == 18

    def test_PtxMode(self, factory: EsbDomain):
        """Check PtxMode crafting
        """
        msg = factory.createPtxMode(18)
        assert isinstance(msg, PtxMode)
        assert msg.channel == 18

    def test_EsbStart(self, factory: EsbDomain):
        """Check EsbStart crafting
        """
        msg = factory.createStart()
        assert isinstance(msg, EsbStart)

    def test_EsbStop(self, factory: EsbDomain):
        """Check EsbStop crafting
        """
        msg = factory.createStop()
        assert isinstance(msg, EsbStop)