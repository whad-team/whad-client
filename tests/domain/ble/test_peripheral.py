"""Bluetooth Low Energy Peripheral connector unit tests.
"""
import pytest

from whad.ble.mock.peripheral import PeripheralMock
from whad.ble import BDAddress, Peripheral

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
    _ = Peripheral(periph_mock, adv_data=periph_adv)
    adv_data = AdvDataFieldList.from_bytes(periph_mock.get_adv_data())
    assert adv_data.get(AdvFlagsField) is not None
    assert adv_data.get(AdvShortenedLocalName) is not None
    short_local_name = adv_data.get(AdvShortenedLocalName)
    assert isinstance(short_local_name, AdvShortenedLocalName)
    assert short_local_name.name == b"TestPeriph"

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

def test_connect(periph_mock):
    """Test peripheral connection."""
    # Create a peripheral connector
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)

    # Start advertising
    periph.start()

    # Make our Peripheral mock trigger a Connected event
    assert periph_mock.make_connection(BDAddress("11:22:33:44:55:66"))

    # Make sure the connection has successfully been processed
    # by our connector
    assert periph.wait_connection(timeout=1.0)

def test_connect_fail(periph_mock):
    """Test failure of a peripheral connection."""
    # Create a peripheral connector
    periph_adv = AdvDataFieldList(
        AdvFlagsField(),
        AdvShortenedLocalName(b"TestPeriph")
    )
    periph = Peripheral(periph_mock, adv_data=periph_adv)

    # Start advertising
    periph.start()

    # Wait for a connection while no connection has been initiated. We expect
    # this method to return False.
    assert not periph.wait_connection(timeout=1.0)

