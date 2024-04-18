"""Protocol hub BLE hijack messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.hub.ble import HijackMaster, HijackSlave, HijackBoth, Hijacked

@pytest.fixture
def hijack_master():
    """Create a BLE hijack_master protocol buffer message
    """
    msg = Message()
    msg.ble.hijack_master.access_address = 0x11223344
    return msg

class TestHijackMaster(object):
    """Test HijackMaster message parsing/crafting
    """

    def test_parsing(self, hijack_master):
        """Check HijackMaster parsing
        """
        parsed_obj = HijackMaster.parse(1, hijack_master)
        assert isinstance(parsed_obj, HijackMaster)
        assert parsed_obj.access_address == 0x11223344

    def test_crafting(self):
        """Check HijackMaster crafting
        """
        msg = HijackMaster(access_address=0x99887766)
        assert msg.access_address == 0x99887766

@pytest.fixture
def hijack_slave():
    """Create a BLE hijack_slave protocol buffer message
    """
    msg = Message()
    msg.ble.hijack_slave.access_address = 0x11223344
    return msg

class TestHijackSlave(object):
    """Test HijackSlave message parsing/crafting
    """

    def test_parsing(self, hijack_slave):
        """Check HijackSlave parsing
        """
        parsed_obj = HijackSlave.parse(1, hijack_slave)
        assert isinstance(parsed_obj, HijackSlave)
        assert parsed_obj.access_address == 0x11223344

    def test_crafting(self):
        """Check HijackSlave crafting
        """
        msg = HijackSlave(access_address=0x99887766)
        assert msg.access_address == 0x99887766

@pytest.fixture
def hijack_both():
    """Create a BLE hijack_both protocol buffer message
    """
    msg = Message()
    msg.ble.hijack_both.access_address = 0x11223344
    return msg

class TestHijackBoth(object):
    """Test HijackBoth message parsing/crafting
    """

    def test_parsing(self, hijack_both):
        """Check HijackBoth parsing
        """
        parsed_obj = HijackBoth.parse(1, hijack_both)
        assert isinstance(parsed_obj, HijackBoth)
        assert parsed_obj.access_address == 0x11223344

    def test_crafting(self):
        """Check HijackBoth crafting
        """
        msg = HijackBoth(access_address=0x99887766)
        assert msg.access_address == 0x99887766

@pytest.fixture
def hijacked():
    """Create a BLE hijacked protocol buffer message
    """
    msg = Message()
    msg.ble.hijacked.success = True
    msg.ble.hijacked.access_address = 0x11223344
    return msg

class TestHijacked(object):
    """Test Hijacked message parsing/crafting
    """

    def test_parsing(self, hijacked):
        """Check Hijacked parsing
        """
        parsed_obj = Hijacked.parse(1, hijacked)
        assert isinstance(parsed_obj, Hijacked)
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.success == True

    def test_crafting(self):
        """Check Hijacked crafting
        """
        msg = Hijacked(success=False, access_address=0x99887766)
        assert msg.access_address == 0x99887766
        assert msg.success == False