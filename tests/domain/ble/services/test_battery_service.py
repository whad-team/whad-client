"""Test standard Battery service implementation
"""
import pytest

from whad.ble import BatteryService, UUID

@pytest.fixture
def service():
    return BatteryService()

class TestBatteryService:

    def test_structure(self, service):
        """Test battery service structure."""
        # Check service's UUID
        assert service.uuid == UUID(0x180f)

        #Check characteristics
        assert service.char('2a19') is not None

    def test_read_percentage(self, service):
        """Test battery percentage read."""
        assert service.percentage == 100

    def test_encoding(self, service):
        """Test percentage encoding."""
        service.percentage = 80
        assert service.level.value == b'\x50'

    @pytest.mark.parametrize(['level', 'result'],[
        (10, 10),
        (-1, 100),
        (200, 100),
    ])
    def test_update_percentage(self, service, level, result):
        """Test updating percentage."""
        service.percentage = level
        assert service.percentage == result
