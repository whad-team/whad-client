"""Protocol hub ESB messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.esb.esb_pb2 import StartCmd as EsbStartCmd, StopCmd as EsbStopCmd
from whad.hub.esb import EsbDomain, SetNodeAddress, SniffMode, JamMode, PrxMode, PtxMode, \
    Jammed, EsbStart, EsbStop, SendPdu, SendRawPdu, PduReceived, RawPduReceived

from test_esb_pdu import esb_pdu, esb_raw_pdu, send_esb_pdu, send_esb_raw_pdu

DEFAULT_NODE_ADDR = bytes([0x11, 0x22, 0x33, 0x44, 0x55])

@pytest.fixture
def set_node_addr():
    msg = Message()
    msg.esb.set_node_addr.address = DEFAULT_NODE_ADDR
    return msg

@pytest.fixture
def sniff_mode():
    msg = Message()
    msg.esb.sniff.channel = 25
    msg.esb.sniff.address = DEFAULT_NODE_ADDR
    msg.esb.sniff.show_acknowledgements = False
    return msg

@pytest.fixture
def jam_mode():
    msg = Message()
    msg.esb.jam.channel = 42
    return msg

@pytest.fixture
def prx_mode():
    msg = Message()
    msg.esb.prx.channel = 42
    return msg

@pytest.fixture
def ptx_mode():
    msg = Message()
    msg.esb.ptx.channel = 42
    return msg

@pytest.fixture
def esb_jammed():
    msg = Message()
    msg.esb.jammed.timestamp = 1234
    return msg

@pytest.fixture
def esb_start():
    msg = Message()
    msg.esb.start.CopyFrom(EsbStartCmd())
    return msg

@pytest.fixture
def esb_stop():
    msg = Message()
    msg.esb.stop.CopyFrom(EsbStopCmd())
    return msg

class TestEsbParsing(object):
    """Test ESB messages parsing
    """

    def test_set_node_address(self, set_node_addr):
        """Check SetNodeAddress parsing
        """
        parsed_obj = SetNodeAddress.parse(1, set_node_addr)
        assert isinstance(parsed_obj, SetNodeAddress)
        assert parsed_obj.address == DEFAULT_NODE_ADDR

    def test_sniff_mode(self, sniff_mode):
        """Check SniffMode parsing
        """
        parsed_obj = SniffMode.parse(1, sniff_mode)
        assert isinstance(parsed_obj, SniffMode)
        assert parsed_obj.address == DEFAULT_NODE_ADDR
        assert parsed_obj.channel == 25
        assert parsed_obj.show_acks == False

    def test_jam_mode(self, jam_mode):
        """Check JamMode parsing
        """
        parsed_obj = JamMode.parse(1, jam_mode)
        assert isinstance(parsed_obj, JamMode)
        assert parsed_obj.channel == 42 

    def test_prx_mode(self, prx_mode):
        """Check PrxMode
        """
        parsed_obj = PrxMode.parse(1, prx_mode)
        assert isinstance(parsed_obj, PrxMode)
        assert parsed_obj.channel == 42 

    def test_ptx_mode(self, ptx_mode):
        """Check PtxMode
        """
        parsed_obj = PtxMode.parse(1, ptx_mode)
        assert isinstance(parsed_obj, PtxMode)
        assert parsed_obj.channel == 42

    def test_jammed(self, esb_jammed):
        """Check Jammed notification
        """
        parsed_obj = Jammed.parse(1, esb_jammed)
        assert isinstance(parsed_obj, Jammed)
        assert parsed_obj.timestamp == 1234

    def test_start(self, esb_start):
        """Check EsbStart message parsing
        """
        parsed_obj = EsbStart.parse(1, esb_start)
        assert isinstance(parsed_obj, EsbStart)

    def test_stop(self, esb_stop):
        """Check EsbStop message parsing
        """
        parsed_obj = EsbStop.parse(1, esb_stop)
        assert isinstance(parsed_obj, EsbStop)


class TestEsbDomainParsing(object):
    """Check ESB domain messages parsing
    """

    def test_SetNodeAddress(self, set_node_addr):
        """Check SetNodeAddress parsing.
        """
        msg = EsbDomain.parse(1, set_node_addr)
        assert isinstance(msg, SetNodeAddress)

    def test_SniffMode(self, sniff_mode):
        """Check SetNodeAddress parsing.
        """
        msg = EsbDomain.parse(1, sniff_mode)
        assert isinstance(msg, SniffMode)

    def test_JamMode(self, jam_mode):
        """Check JamMode parsing.
        """
        msg = EsbDomain.parse(1, jam_mode)
        assert isinstance(msg, JamMode)

    def test_Jammed(self, esb_jammed):
        """Check Jammed parsing.
        """
        msg = EsbDomain.parse(1, esb_jammed)
        assert isinstance(msg, Jammed)

    def test_PrxMode(self, prx_mode):
        """Check PrxMode parsing.
        """
        msg = EsbDomain.parse(1, prx_mode)
        assert isinstance(msg, PrxMode)

    def test_PtxMode(self, ptx_mode):
        """Check PtxMode parsing.
        """
        msg = EsbDomain.parse(1, ptx_mode)
        assert isinstance(msg, PtxMode)

    def test_EsbStart(self, esb_start):
        """Check EsbStart parsing.
        """
        msg = EsbDomain.parse(1, esb_start)
        assert isinstance(msg, EsbStart)

    def test_EsbStop(self, esb_stop):
        """Check EsbStop parsing.
        """
        msg = EsbDomain.parse(1, esb_stop)
        assert isinstance(msg, EsbStop)

    def test_SendPdu(self, send_esb_pdu):
        """Check SendPdu parsing.
        """
        msg = EsbDomain.parse(1, send_esb_pdu)
        assert isinstance(msg, SendPdu)

    def test_SendRawPdu(self, send_esb_raw_pdu):
        """Check SendRawPdu parsing.
        """
        msg = EsbDomain.parse(1, send_esb_raw_pdu)
        assert isinstance(msg, SendRawPdu)

    def test_PduReceived(self, esb_pdu):
        """Check PduReceived parsing.
        """
        msg = EsbDomain.parse(1, esb_pdu)
        assert isinstance(msg, PduReceived)

    def test_RawPduReceived(self, esb_raw_pdu):
        """Check RawPduReceived parsing.
        """
        msg = EsbDomain.parse(1, esb_raw_pdu)
        assert isinstance(msg, RawPduReceived)