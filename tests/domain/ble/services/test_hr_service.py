"""Test standard Heart Rate service implementation
"""
from typing import Optional

import pytest

from whad.ble import HeartRateService, UUID

@pytest.fixture
def hr_service():
    return HeartRateService()

@pytest.fixture
def hr_service_sensor():
    service = HeartRateService()
    service.enable_contact(True)
    return service

class TestHRService:

    def test_structure(self, hr_service):
        """Test service structure."""
        # Check service's UUID
        assert hr_service.uuid == UUID(0x180d)

        # Make sure the required characteristics are populated
        assert hr_service.char('2a37') is not None
        assert hr_service.char('2a38') is not None

    @pytest.mark.parametrize(
    ['rate', 'energy', 'skin', 'value'],
    [
        (80, None, None, b'\x00\x50'),
        (80, 2, None, b'\x08\x50\x02\x00'),
        (80, None, True, b'\x00\x50'),
        (80, 2, False, b'\x08\x50\x02\x00'),
        (2000, 42, None, b'\x09\xd0\x07\x2a\x00'),
    ])
    def test_update(self, hr_service, rate: int, energy: Optional[int], skin: Optional[bool], value: bytes):
        """Update service with values and check measurement value."""
        hr_service.update(rate, energy, skin)
        assert hr_service.measurement.value == value

    @pytest.mark.parametrize(
    ['rate', 'energy', 'skin'],
    [
        (100000, None, None),
        (-1, None, None),
    ])
    def test_update_bad_values(self, hr_service, rate: int, energy: Optional[int], skin: Optional[bool]):
        """Update service with values and check measurement value."""
        with pytest.raises(ValueError):
            hr_service.update(rate, energy, skin)

    @pytest.mark.parametrize(
        ['value', 'rate', 'energy', 'skin'],
        [
            (b'\x00\x10', 16, None, False),
            (b'\x09\xd0\x07\x2a\x00', 2000, 42, False),
            (b'\x08\x50\x02\x00', 80, 2, False),
            (b'\x06\x50', 80, None, True),
            (b'\x02\x50', 80, None, False),
        ])
    def test_parsing(self, hr_service, value, rate, energy, skin):
        """Test parsing measurement value."""
        # Simulate a characteristic notification
        hr_service.on_update(None, value, False)

        # Check basic features
        assert hr_service.rate == rate
        assert hr_service.energy_expended == energy
        assert hr_service.skin_contact == skin

    @pytest.mark.parametrize(
        ['value'],
        [
            (b'\x08\x10',),
            (b'\x09\xd0\x07\x2a',),
        ])
    def test_parsing_error(self, hr_service, value):
        """Test parsing measurement value."""
        with pytest.raises(ValueError):
            # Simulate a characteristic notification
            hr_service.on_update(None, value, False)


