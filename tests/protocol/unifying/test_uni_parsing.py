"""Protocol hub Logitech Unifying messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.unifying.unifying_pb2 import StartCmd as UniStartCmd, StopCmd as UniStopCmd, \
    SniffPairingCmd
from whad.hub.unifying import UnifyingDomain, SetNodeAddress, SniffMode, JamMode, DongleMode, \
    KeyboardMode, MouseMode, SniffPairing, Jammed, UnifyingStart, UnifyingStop, SendPdu, \
    SendRawPdu, PduReceived, RawPduReceived

from test_uni_pdu import uni_pdu, uni_raw_pdu, send_uni_pdu, send_uni_raw_pdu

DEFAULT_NODE_ADDR = bytes([0x11, 0x22, 0x33, 0x44, 0x55])

@pytest.fixture
def set_node_addr():
    msg = Message()
    msg.unifying.set_node_addr.address = DEFAULT_NODE_ADDR
    return msg

@pytest.fixture
def sniff_mode():
    msg = Message()
    msg.unifying.sniff.channel = 25
    msg.unifying.sniff.address = DEFAULT_NODE_ADDR
    msg.unifying.sniff.show_acknowledgements = False
    return msg

@pytest.fixture
def jam_mode():
    msg = Message()
    msg.unifying.jam.channel = 42
    return msg

@pytest.fixture
def dongle_mode():
    msg = Message()
    msg.unifying.dongle.channel = 42
    return msg

@pytest.fixture
def keyboard_mode():
    msg = Message()
    msg.unifying.keyboard.channel = 42
    return msg

@pytest.fixture
def mouse_mode():
    msg = Message()
    msg.unifying.mouse.channel = 42
    return msg

@pytest.fixture
def sniff_pairing():
    msg = Message()
    msg.unifying.sniff_pairing.CopyFrom(SniffPairingCmd())
    return msg

@pytest.fixture
def uni_jammed():
    msg = Message()
    msg.unifying.jammed.timestamp = 1234
    return msg

@pytest.fixture
def uni_start():
    msg = Message()
    msg.unifying.start.CopyFrom(UniStartCmd())
    return msg

@pytest.fixture
def uni_stop():
    msg = Message()
    msg.unifying.stop.CopyFrom(UniStopCmd())
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

    def test_dongle_mode(self, dongle_mode):
        """Check PrxMode
        """
        parsed_obj = DongleMode.parse(1, dongle_mode)
        assert isinstance(parsed_obj, DongleMode)
        assert parsed_obj.channel == 42 

    def test_keyboard_mode(self, keyboard_mode):
        """Check KeyboardMode
        """
        parsed_obj = KeyboardMode.parse(1, keyboard_mode)
        assert isinstance(parsed_obj, KeyboardMode)
        assert parsed_obj.channel == 42

    def test_mouse_mode(self, mouse_mode):
        """Check MouseMode
        """
        parsed_obj = MouseMode.parse(1, mouse_mode)
        assert isinstance(parsed_obj, MouseMode)
        assert parsed_obj.channel == 42

    def test_sniff_pairing(self, sniff_pairing):
        """Check SniffPairing
        """
        parsed_obj = SniffPairing.parse(1, sniff_pairing)
        assert isinstance(parsed_obj, SniffPairing)

    def test_jammed(self, uni_jammed):
        """Check Jammed notification
        """
        parsed_obj = Jammed.parse(1, uni_jammed)
        assert isinstance(parsed_obj, Jammed)
        assert parsed_obj.timestamp == 1234

    def test_start(self, uni_start):
        """Check UnifyingStart message parsing
        """
        parsed_obj = UnifyingStart.parse(1, uni_start)
        assert isinstance(parsed_obj, UnifyingStart)

    def test_stop(self, uni_stop):
        """Check UnifyingStop message parsing
        """
        parsed_obj = UnifyingStop.parse(1, uni_stop)
        assert isinstance(parsed_obj, UnifyingStop)


class TestUnifyingDomainParsing(object):
    """Check ESB domain messages parsing
    """

    def test_SetNodeAddress(self, set_node_addr):
        """Check SetNodeAddress parsing.
        """
        msg = UnifyingDomain.parse(1, set_node_addr)
        assert isinstance(msg, SetNodeAddress)

    def test_SniffMode(self, sniff_mode):
        """Check SetNodeAddress parsing.
        """
        msg = UnifyingDomain.parse(1, sniff_mode)
        assert isinstance(msg, SniffMode)

    def test_JamMode(self, jam_mode):
        """Check JamMode parsing.
        """
        msg = UnifyingDomain.parse(1, jam_mode)
        assert isinstance(msg, JamMode)

    def test_Jammed(self, uni_jammed):
        """Check Jammed parsing.
        """
        msg = UnifyingDomain.parse(1, uni_jammed)
        assert isinstance(msg, Jammed)

    def test_DongleMode(self, dongle_mode):
        """Check DongleMode parsing.
        """
        msg = UnifyingDomain.parse(1, dongle_mode)
        assert isinstance(msg, DongleMode)

    def test_KeyboardMode(self, keyboard_mode):
        """Check KeyboardMode parsing.
        """
        msg = UnifyingDomain.parse(1, keyboard_mode)
        assert isinstance(msg, KeyboardMode)

    def test_MouseMode(self, mouse_mode):
        """Check MouseMode parsing.
        """
        msg = UnifyingDomain.parse(1, mouse_mode)
        assert isinstance(msg, MouseMode)

    def test_SniffPairing(self, sniff_pairing):
        """Check SniffPairing parsing.
        """
        msg = UnifyingDomain.parse(1, sniff_pairing)
        assert isinstance(msg, SniffPairing)

    def test_UnifyingStart(self, uni_start):
        """Check UnifyingStart parsing.
        """
        msg = UnifyingDomain.parse(1, uni_start)
        assert isinstance(msg, UnifyingStart)

    def test_UnifyingStop(self, uni_stop):
        """Check UnifyingStop parsing.
        """
        msg = UnifyingDomain.parse(1, uni_stop)
        assert isinstance(msg, UnifyingStop)

    def test_SendPdu(self, send_uni_pdu):
        """Check SendPdu parsing.
        """
        msg = UnifyingDomain.parse(1, send_uni_pdu)
        assert isinstance(msg, SendPdu)

    def test_SendRawPdu(self, send_uni_raw_pdu):
        """Check SendRawPdu parsing.
        """
        msg = UnifyingDomain.parse(1, send_uni_raw_pdu)
        assert isinstance(msg, SendRawPdu)

    def test_PduReceived(self, uni_pdu):
        """Check PduReceived parsing.
        """
        msg = UnifyingDomain.parse(1, uni_pdu)
        assert isinstance(msg, PduReceived)

    def test_RawPduReceived(self, uni_raw_pdu):
        """Check RawPduReceived parsing.
        """
        msg = UnifyingDomain.parse(1, uni_raw_pdu)
        assert isinstance(msg, RawPduReceived)