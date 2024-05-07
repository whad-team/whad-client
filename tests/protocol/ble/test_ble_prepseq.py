"""Protocol hub BLE prepare sequence messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import PrepareSequenceCmd
from whad.hub.ble import Direction, PrepareSequenceManual, \
    PrepareSequenceConnEvt, PrepareSequencePattern, Trigger, Triggered, \
    DeleteSequence

@pytest.fixture
def prep_seq_manual():
    """Create a BLE prepare sequence with manual trigger protocol buffer message
    """
    msg = Message()
    msg.ble.prepare.trigger.manual.CopyFrom(PrepareSequenceCmd.ManualTrigger())
    msg.ble.prepare.id = 12
    msg.ble.prepare.direction = Direction.MASTER_TO_SLAVE
    pkt = msg.ble.prepare.sequence.add()
    pkt.packet = b"FOOBAR"
    return msg

class TestPrepareSequenceManualTrigger(object):
    """Test BLE PrepareSequence with manual trigger message parsing/crafting
    """

    def test_parsing(self, prep_seq_manual):
        """Check PrepareSequenceManual parsing
        """
        parsed_obj = PrepareSequenceManual.parse(1, prep_seq_manual)
        assert isinstance(parsed_obj, PrepareSequenceManual)
        assert parsed_obj.sequence_id == 12
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.count_packets() == 1
        assert parsed_obj.get_packet(0) == b"FOOBAR"

    def test_crafting(self):
        """Check PrepareSequenceManual crafting
        """
        msg = PrepareSequenceManual(
            sequence_id=42,
            direction=Direction.SLAVE_TO_MASTER
        )
        msg.add_packet(b"HELLOWORLD")
        msg.add_packet(b"FOOBAR")
        assert msg.sequence_id == 42
        assert msg.direction == Direction.SLAVE_TO_MASTER
        assert msg.count_packets() == 2
        assert msg.get_packet(0) == b"HELLOWORLD"
        assert msg.get_packet(1) == b"FOOBAR"

@pytest.fixture
def prep_seq_connevt():
    """Create a BLE prepare sequence with conn event trigger protocol buffer
    message
    """
    msg = Message()
    msg.ble.prepare.trigger.connection_event.connection_event = 42
    msg.ble.prepare.id = 33
    msg.ble.prepare.direction = Direction.MASTER_TO_SLAVE
    pkt = msg.ble.prepare.sequence.add()
    pkt.packet = b"FOOBAR"
    return msg

class TestPrepareSequenceConnEventTrigger(object):
    """Test BLE PrepareSequence with connection event trigger message
    parsing/crafting
    """

    def test_parsing(self, prep_seq_connevt):
        """Check PrepareSequenceConnEvt parsing
        """
        parsed_obj = PrepareSequenceConnEvt.parse(1, prep_seq_connevt)
        assert isinstance(parsed_obj, PrepareSequenceConnEvt)
        assert parsed_obj.connection_event == 42
        assert parsed_obj.sequence_id == 33
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.count_packets() == 1
        assert parsed_obj.get_packet(0) == b"FOOBAR"

    def test_crafting(self):
        """Check PrepareSequenceConnEvt crafting
        """
        msg = PrepareSequenceConnEvt(
            connection_event=66,
            sequence_id=42,
            direction=Direction.SLAVE_TO_MASTER
        )
        msg.add_packet(b"HELLOWORLD")
        msg.add_packet(b"FOOBAR")
        assert msg.connection_event == 66
        assert msg.sequence_id == 42
        assert msg.direction == Direction.SLAVE_TO_MASTER
        assert msg.count_packets() == 2
        assert msg.get_packet(0) == b"HELLOWORLD"
        assert msg.get_packet(1) == b"FOOBAR"

@pytest.fixture
def prep_seq_reception():
    """Create a BLE prepare sequence with reception trigger protocol buffer
    message
    """
    msg = Message()
    msg.ble.prepare.trigger.reception.pattern = b"SOME"
    msg.ble.prepare.trigger.reception.mask = b"\xFF\xFF\xFF\xFF"
    msg.ble.prepare.trigger.reception.offset = 0
    msg.ble.prepare.id = 99
    msg.ble.prepare.direction = Direction.MASTER_TO_SLAVE
    pkt = msg.ble.prepare.sequence.add()
    pkt.packet = b"FOOBAR"
    return msg

class TestPrepareSequenceReceptionTrigger(object):
    """Test BLE PrepareSequence with reception trigger message
    parsing/crafting
    """

    def test_parsing(self, prep_seq_reception):
        """Check PrepareSequenceConnEvt parsing
        """
        parsed_obj = PrepareSequencePattern.parse(1, prep_seq_reception)
        assert isinstance(parsed_obj, PrepareSequencePattern)
        assert parsed_obj.pattern == b"SOME"
        assert parsed_obj.mask == b"\xFF\xFF\xFF\xFF"
        assert parsed_obj.offset == 0
        assert parsed_obj.sequence_id == 99
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.count_packets() == 1
        assert parsed_obj.get_packet(0) == b"FOOBAR"

    def test_crafting(self):
        """Check PrepareSequenceConnEvt crafting
        """
        msg = PrepareSequencePattern(
            pattern=b"FOOBAR",
            mask=b"\xFF\x00\xFF\x00",
            offset=2,
            sequence_id=112,
            direction=Direction.SLAVE_TO_MASTER
        )
        msg.add_packet(b"HELLOWORLD")
        msg.add_packet(b"FOOBAR")
        assert msg.pattern == b"FOOBAR"
        assert msg.mask == b"\xFF\x00\xFF\x00"
        assert msg.offset == 2
        assert msg.sequence_id == 112
        assert msg.direction == Direction.SLAVE_TO_MASTER
        assert msg.count_packets() == 2
        assert msg.get_packet(0) == b"HELLOWORLD"
        assert msg.get_packet(1) == b"FOOBAR"

@pytest.fixture
def ble_trigger():
    msg = Message()
    msg.ble.trigger.id = 5
    return msg


class TestTriggerSequence(object):
    """Test BLE Trigger  message parsing/crafting
    """

    def test_parsing(self, ble_trigger):
        """Check Trigger parsing
        """
        parsed_obj = Trigger.parse(1, ble_trigger)
        assert isinstance(parsed_obj, Trigger)
        assert parsed_obj.sequence_id == 5

    def test_crafting(self):
        """Check Trigger crafting
        """
        msg = Trigger(sequence_id=12)
        assert msg.sequence_id == 12

@pytest.fixture
def ble_delete_seq():
    msg = Message()
    msg.ble.delete_seq.id = 7
    return msg

class TestDeleteSequence(object):
    """Test BLE DeleteSequence  message parsing/crafting
    """

    def test_parsing(self, ble_delete_seq):
        """Check DeleteSequence parsing
        """
        parsed_obj = DeleteSequence.parse(1, ble_delete_seq)
        assert isinstance(parsed_obj, DeleteSequence)
        assert parsed_obj.sequence_id == 7

    def test_crafting(self):
        """Check DeleteSequence crafting
        """
        msg = DeleteSequence(sequence_id=12)
        assert msg.sequence_id == 12

@pytest.fixture
def ble_triggered():
    msg = Message()
    msg.ble.triggered.id = 5
    return msg

class TestTriggered(object):
    """Test BLE Triggered  message parsing/crafting
    """

    def test_parsing(self, ble_triggered):
        """Check Trigger parsing
        """
        parsed_obj = Triggered.parse(1, ble_triggered)
        assert isinstance(parsed_obj, Triggered)
        assert parsed_obj.sequence_id == 5

    def test_crafting(self):
        """Check Trigger crafting
        """
        msg = Triggered(sequence_id=12)
        assert msg.sequence_id == 12