"""Bluetooth Low Energy Advertisor connector testing
"""
import pytest

from whad.ble.mock import AdvertiserMock
from whad.ble import Advertiser
from whad.hub.ble import AdvType, ChannelMap
from whad.ble.profile.advdata import AdvDataFieldList, AdvCompleteLocalName, AdvFlagsField, AdvShortenedLocalName, AdvTxPowerLevel

@pytest.fixture
def adv_mock():
    """Create a BLE Advertiser mock.
    """
    return AdvertiserMock()

@pytest.fixture
def def_adv(adv_mock):
    """Default advertiser."""
    adv_data = AdvDataFieldList(
        AdvFlagsField(),
        AdvCompleteLocalName(b"MockDevice")
    )

    scan_data = AdvDataFieldList(
        AdvTxPowerLevel(10)
    )

    return Advertiser(
        adv_mock,
        adv_data,
        scan_data,
        AdvType.ADV_NONCONN_IND,
        [37, 38, 39],
        0x20, 0x4000
    )


def test_advertiser_create(adv_mock):
    """ Test creating an advertiser """
    adv_data = AdvDataFieldList(
        AdvFlagsField(),
        AdvCompleteLocalName(b"MockDevice")
    )

    scan_data = AdvDataFieldList(
        AdvTxPowerLevel(10)
    )

    _ = Advertiser(
        adv_mock,
        adv_data,
        scan_data,
        AdvType.ADV_NONCONN_IND,
        [37, 38, 39],
        0x20, 0x4000
    )
    assert adv_mock.adv_data == adv_data.to_bytes()
    assert adv_mock.scan_resp == scan_data.to_bytes()
    assert adv_mock.channel_map == ChannelMap([37,38,39])
    assert adv_mock.adv_interval == (0x20, 0x4000)

def test_advertiser_bad_channelmap(adv_mock):
    """Create an advertiser with an empty channel map."""
    with pytest.raises(ValueError):
        _ = Advertiser(adv_mock, AdvDataFieldList(), None, AdvType.ADV_IND, [])


def test_advertiser_bad_interval(adv_mock):
    """Create an advertiser with a bad advertisement type value."""
    with pytest.raises(ValueError):
        _ = Advertiser(adv_mock, AdvDataFieldList(), None, AdvType.ADV_IND,
                       [37, 38, 39], 0x1000, 0x0042)

def test_advertiser_start_stop(def_adv):
    """Test starting the advertiser."""
    def_adv.start()
    assert def_adv.device.is_started()
    def_adv.stop()
    assert def_adv.device.is_stopped()

def test_advertiser_data_update(def_adv):
    """Update advertising data with advertiser in stopped state."""
    new_adv_data = AdvDataFieldList(AdvShortenedLocalName(b"FOOBAR"))
    def_adv.update(new_adv_data, None)
    assert def_adv.device.adv_data == new_adv_data.to_bytes()

def test_advertiser_data_update_while_started(def_adv):
    """Update advertising data with advertiser in started state."""
    new_adv_data = AdvDataFieldList(AdvShortenedLocalName(b"FOOBAR"))
    def_adv.start()
    def_adv.update(new_adv_data, None)
    assert def_adv.device.adv_data == new_adv_data.to_bytes()

def test_advertiser_adv_type_update(def_adv):
    """Update adv_type while advertiser is stopped"""
    def_adv.adv_type = AdvType.ADV_IND
    assert def_adv.adv_type == AdvType.ADV_IND

def test_advertiser_adv_type_update_started(def_adv):
    """Update adv_type while advertiser is started"""
    def_adv.start()
    def_adv.adv_type = AdvType.ADV_IND
    assert def_adv.adv_type == AdvType.ADV_IND
    assert def_adv.device.adv_type == AdvType.ADV_NONCONN_IND

def test_advertiser_adv_type_update_stop(def_adv):
    """Start advertiser, stop advertiser, update adv_type and start advertiser again."""
    def_adv.start()
    def_adv.stop()
    def_adv.adv_type = AdvType.ADV_IND
    def_adv.start()
    assert def_adv.device.adv_type == AdvType.ADV_IND

