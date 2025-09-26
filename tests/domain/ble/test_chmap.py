"""BLE channel map implementation unit tests.
"""

import pytest
from whad.hub.ble.chanmap import ChannelMap

class TestChannelMap(object):
    """Test BLE channel map
    """

    def test_chanmap_init(self):
        """Test channel map initialization
        """
        chanmap = ChannelMap(channels=[1, 12, 3, 6])
        assert chanmap.value == b'J\x10\x00\x00\x00'

    def test_chanmap_add(self):
        """Test channel map add() method.
        """
        chanmap = ChannelMap()
        chanmap.add(20)
        assert chanmap.value == b'\x00\x00\x10\x00\x00'

    def test_chanmap_remove(self):
        """Test channel map remove() method
        """
        chanmap = ChannelMap(channels=[12, 13, 14])
        chanmap.remove(13)
        assert chanmap.value == b'\x00P\x00\x00\x00'

    def test_chanmap_has(self):
        chanmap = ChannelMap(channels=[12, 13, 14])
        assert chanmap.has(12) == True
        assert chanmap.has(13) == True
        assert chanmap.has(14)

    def test_chanmap_invalid_chan(self):
        chanmap = ChannelMap(channels=[12, 13, 14])
        with pytest.raises(ValueError) as e_info:
            chanmap.remove(55)

    def test_chanmap_from_bytes(self):
        chanmap = ChannelMap.from_bytes(b"\xff\xff\xff\xff\x1f")
        assert chanmap.value == b"\xff\xff\xff\xff\x1f"

    def test_chanmap_from_int(self):
        chanmap = ChannelMap.from_int(0x1faabbccdd)
        assert chanmap.value == b"\xdd\xcc\xbb\xaa\x1f"

    def test_chanmap_filter(self):
        chanmap = ChannelMap([1,2,3,4,5, 20, 21, 22])
        chanmap.filter(lambda x: x>=20)
        assert chanmap == ChannelMap([20, 21, 22])

    def test_chanmap_compare(self):
        a = ChannelMap([1,2,3])
        b = ChannelMap([1,2,3])
        assert a==b

    def test_chanmap_compare_different(self):
        a = ChannelMap([1,2,3])
        b = ChannelMap([5,6,7])
        assert a != b

    def test_chanmap_len(self):
        a = ChannelMap([1,2,3,4,5])
        assert len(a) == 5
