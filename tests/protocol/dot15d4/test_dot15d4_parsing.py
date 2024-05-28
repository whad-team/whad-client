"""Protocol hub Discovery messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.dot15d4.dot15d4_pb2 import SetNodeAddressCmd, AddressType, \
    StartCmd, StopCmd
from whad.hub.dot15d4 import Dot15d4Domain, SetNodeAddress, SniffMode, JamMode, \
    RouterMode, EndDeviceMode, CoordMode, EnergyDetectionMode, MitmMode, Start, \
    Stop, Jammed, EnergyDetectionSample, SendPdu, SendRawPdu, PduReceived, RawPduReceived

from test_dot15d4_pdu import send_pdu, send_raw_pdu, pdu_received, raw_pdu_received

EXT_NODE_ADDRESS_DEFAULT = 0x1122334455667788
SHORT_NODE_ADDRESS_DEFAULT = 0xAABB

@pytest.fixture
def set_node_addr_ext():
    """Create a SetNodeAddress protobuf message
    """
    msg = Message()
    msg.dot15d4.set_node_addr.address_type = AddressType.EXTENDED
    msg.dot15d4.set_node_addr.address = EXT_NODE_ADDRESS_DEFAULT
    return msg

@pytest.fixture
def set_node_addr_short():
    """Create a SetNodeAddress protobuf message
    """
    msg = Message()
    msg.dot15d4.set_node_addr.address_type = AddressType.SHORT
    msg.dot15d4.set_node_addr.address = SHORT_NODE_ADDRESS_DEFAULT
    return msg

class TestSetNodeAddress(object):
    """Test SetNodeAddress message parsing/crafting.
    """

    def test_parsing_short(self, set_node_addr_short):
        """Check SetNodeAddress parsing when address is short
        """
        parsed_obj = SetNodeAddress.parse(1, set_node_addr_short)
        assert isinstance(parsed_obj, SetNodeAddress)
        assert parsed_obj.addr_type == AddressType.SHORT
        assert parsed_obj.address == SHORT_NODE_ADDRESS_DEFAULT

    def test_parsing_ext(self, set_node_addr_ext):
        """Check SetNodeAddress parsing when address is extended
        """
        parsed_obj = SetNodeAddress.parse(1, set_node_addr_ext)
        assert isinstance(parsed_obj, SetNodeAddress)
        assert parsed_obj.addr_type == AddressType.EXTENDED
        assert parsed_obj.address == EXT_NODE_ADDRESS_DEFAULT

@pytest.fixture
def sniff_mode():
    """Create a SniffCmd protobuf message
    """
    msg = Message()
    msg.dot15d4.sniff.channel = 42
    return msg

@pytest.fixture
def jam_mode():
    """Create a JamCmd protobuf message
    """
    msg = Message()
    msg.dot15d4.jam.channel = 42
    return msg

@pytest.fixture
def router_mode():
    """Create a RouterCmd protobuf message
    """
    msg = Message()
    msg.dot15d4.router.channel = 42
    return msg

@pytest.fixture
def end_device_mode():
    """Create a EndDeviceCmd protobuf message
    """
    msg = Message()
    msg.dot15d4.end_device.channel = 42
    return msg

@pytest.fixture
def coord_mode():
    """Create a CoordinatorCmd protobuf message
    """
    msg = Message()
    msg.dot15d4.coordinator.channel = 42
    return msg

@pytest.fixture
def energy_detect_mode():
    """Create a EnergyDetectionCmd protobuf message
    """
    msg = Message()
    msg.dot15d4.ed.channel = 42
    return msg

@pytest.fixture
def mitm_mode():
    """Create a ManInTheMiddleCmd protobuf message
    """
    msg = Message()
    msg.dot15d4.mitm.role = 1
    return msg

@pytest.fixture
def start():
    """Create Dot15d4 start protocol buffer message
    """
    msg = Message()
    msg.dot15d4.start.CopyFrom(StartCmd())
    return msg

@pytest.fixture
def stop():
    """Create Dot15d4 stop protocol buffer message
    """
    msg = Message()
    msg.dot15d4.stop.CopyFrom(StopCmd())
    return msg

@pytest.fixture
def jammed():
    """Create Dot15d4 jammed notification protocol buffer message
    """
    msg = Message()
    msg.dot15d4.jammed.timestamp = 1234
    return msg

@pytest.fixture
def energy_detection_sample():
    """Create Dot15d4 energy detection sample notification protocol buffer message
    """
    msg = Message()
    msg.dot15d4.ed_sample.timestamp = 1234
    msg.dot15d4.ed_sample.sample = 9876
    return msg

class TestModes(object):
    """Test Dot15d4 modes message parsing/crafting.
    """

    def test_sniff_mode(self, sniff_mode):
        """Check SniffMode parsing
        """
        parsed_obj = SniffMode.parse(1, sniff_mode)
        assert isinstance(parsed_obj, SniffMode)
        assert parsed_obj.channel == 42

    def test_jam_mode(self, jam_mode):
        """Check JamMode parsing
        """
        parsed_obj = JamMode.parse(1, jam_mode)
        assert isinstance(parsed_obj, JamMode)
        assert parsed_obj.channel == 42

    def test_router_mode(self, router_mode):
        """Check RouterMode parsing
        """
        parsed_obj = RouterMode.parse(1, router_mode)
        assert isinstance(parsed_obj, RouterMode)
        assert parsed_obj.channel == 42

    def test_end_device_mode(self, end_device_mode):
        """Check EndDeviceMode parsing
        """
        parsed_obj = EndDeviceMode.parse(1, end_device_mode)
        assert isinstance(parsed_obj, EndDeviceMode)
        assert parsed_obj.channel == 42

    def test_coord_mode(self, coord_mode):
        """Check CoordMode parsing
        """
        parsed_obj = CoordMode.parse(1, coord_mode)
        assert isinstance(parsed_obj, CoordMode)
        assert parsed_obj.channel == 42

    def test_energy_detect_mode(self, energy_detect_mode):
        """Check EnergyDetectionMode parsing
        """
        parsed_obj = EnergyDetectionMode.parse(1, energy_detect_mode)
        assert isinstance(parsed_obj, EnergyDetectionMode)
        assert parsed_obj.channel == 42

    def test_mitm_mode(self, mitm_mode):
        """Check MitmMode parsing
        """
        parsed_obj = MitmMode.parse(1, mitm_mode)
        assert isinstance(parsed_obj, MitmMode)
        assert parsed_obj.role == 1

    def test_start(self, start):
        """Check Start parsing
        """
        parsed_obj = Start.parse(1, start)
        assert isinstance(parsed_obj, Start)

    def test_stop(self, stop):
        """Check Stop parsing
        """
        parsed_obj = Stop.parse(1, stop)
        assert isinstance(parsed_obj, Stop)

    def test_jammed(self, jammed):
        """Check Jammed parsing
        """
        parsed_obj = Jammed.parse(1, jammed)
        assert isinstance(parsed_obj, Jammed)
        assert parsed_obj.timestamp == 1234

    def test_energy_detect_sample(self, energy_detection_sample):
        """Check EnergyDetectionSample parsing
        """
        parsed_obj = EnergyDetectionSample.parse(1, energy_detection_sample)
        assert isinstance(parsed_obj, EnergyDetectionSample)
        assert parsed_obj.timestamp == 1234
        assert parsed_obj.sample == 9876


class TestParsing(object):
    """Test Dot15d4 domain message parsing
    """

    def test_set_node_addr_short(self, set_node_addr_short):
        """Check Dot15d4 SetNodeAddress message parsing for short address
        """
        parsed_obj = Dot15d4Domain.parse(1, set_node_addr_short)
        assert isinstance(parsed_obj, SetNodeAddress)

    def test_set_node_addr_ext(self, set_node_addr_ext):
        """Check Dot15d4 SetNodeAddress message parsing for extended address
        """
        parsed_obj = Dot15d4Domain.parse(1, set_node_addr_ext)
        assert isinstance(parsed_obj, SetNodeAddress)

    def test_sniff(self, sniff_mode):
        """Check sniff mode message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, sniff_mode)
        assert isinstance(parsed_obj, SniffMode)

    def test_jam(self, jam_mode):
        """Check jamming mode message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, jam_mode)
        assert isinstance(parsed_obj, JamMode)

    def test_energy_detect(self, energy_detect_mode):
        """Check energy detection mode message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, energy_detect_mode)
        assert isinstance(parsed_obj, EnergyDetectionMode)

    def test_end_device(self, end_device_mode):
        """Check end device mode message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, end_device_mode)
        assert isinstance(parsed_obj, EndDeviceMode)

    def test_router(self, router_mode):
        """Check router mode message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, router_mode)
        assert isinstance(parsed_obj, RouterMode)

    def test_coord(self, coord_mode):
        """Check coordinator mode message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, coord_mode)
        assert isinstance(parsed_obj, CoordMode)

    def test_start(self, start):
        """Check start message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, start)
        assert isinstance(parsed_obj, Start)

    def test_stop(self, stop):
        """Check stop message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, stop)
        assert isinstance(parsed_obj, Stop)

    def test_mitm(self, mitm_mode):
        """Check MitmMode message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, mitm_mode)
        assert isinstance(parsed_obj, MitmMode)

    def test_jammed(self, jammed):
        """Check Jammed message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, jammed)
        assert isinstance(parsed_obj, Jammed)

    def test_energy_detect_sample(self, energy_detection_sample):
        """Check EnergyDetectionSample message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, energy_detection_sample)
        assert isinstance(parsed_obj, EnergyDetectionSample)

    def test_send_pdu(self, send_pdu):
        """Check SendPdu message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, send_pdu)
        assert isinstance(parsed_obj, SendPdu)

    def test_send_raw_pdu(self, send_raw_pdu):
        """Check SendRawPdu message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, send_raw_pdu)
        assert isinstance(parsed_obj, SendRawPdu)

    def test_pdu(self, pdu_received):
        """Check PduReceived message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, pdu_received)
        assert isinstance(parsed_obj, PduReceived)

    def test_raw_pdu(self, raw_pdu_received):
        """Check RawPduReceived message parsing
        """
        parsed_obj = Dot15d4Domain.parse(1, raw_pdu_received)
        assert isinstance(parsed_obj, RawPduReceived)