"""Bluetooth Low Energy Peripheral connector unit tests.
"""
import pytest

from whad.ble.mock.peripheral import PeripheralMock
from whad.ble.connector import Peripheral

from whad.ble.profile.advdata import AdvDataFieldList, AdvFlagsField, AdvShortenedLocalName

@pytest.fixture
def periph_mock() -> PeripheralMock:
    """Create a default BLE peripheral mock"""
    return PeripheralMock()

def test_create(periph_mock):
    """Test Peripheral connector creation."""
    periph = Peripheral(periph_mock)

    # Peripheral must implement Peripheral mode and be able
    # to send PDU.
    assert periph.can_be_peripheral()
    assert periph.can_send()

def test_advertising(periph_mock):
    """Test peripheral advertising settings."""
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)
    adv_data = AdvDataFieldList.from_bytes(periph_mock.get_adv_data())
    print(adv_data)
    assert adv_data.get(AdvFlagsField) is not None
    assert adv_data.get(AdvShortenedLocalName) is not None
    assert adv_data.get(AdvShortenedLocalName).name == b"TestPeriph"

def test_start(periph_mock):
    """Test peripheral mode start."""
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)
    periph.start()
    assert periph_mock.is_started()

def test_stop(periph_mock):
    """Test peripheral mode stop."""
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)
    periph.start()
    periph.stop()
    assert periph_mock.is_stopped()

