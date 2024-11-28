"""Test device database used when scanning BLE devices.
"""
from scapy.layers.bluetooth4LE import BTLE, BTLE_ADV, BTLE_ADV_IND
from whad.hub.ble.bdaddr import BDAddress
from whad.ble.scanning import AdvertisingDevice, AdvertisingDevicesDB

def test_adv_device():
    """Test advertising device implementation
    """
    dev = AdvertisingDevice(-40, 0, BDAddress("00:11:22:33:44:AA"), b"\x02\x01\x06", None, True, True)
    assert dev.address_type == 0
    assert dev.address == "00:11:22:33:44:aa"
    assert dev.rssi == -40
    assert dev.adv_records == b"\x02\x01\x06"
    assert dev.connectable
    assert not dev.got_scan_rsp
    assert dev.last_seen is not None

def test_dev_database():
    """Test device database
    """
    db = AdvertisingDevicesDB()
    dev = AdvertisingDevice(-40, 0, BDAddress("00:11:22:33:44:AA"), b"", None, True, True)
    db.register_device(dev)
    assert db.find_device("00:11:22:33:44:aA") is not None
    db.reset()
    assert db.find_device("00:11:22:33:44:aa") is None

def test_dev_db_scanrsp():
    """Test device scanning
    """
    db = AdvertisingDevicesDB()
    pkt = BTLE()/BTLE_ADV()/BTLE_ADV_IND(AdvA="00:11:22:33:44:BB")
    devices = db.on_device_found(-40, pkt, None)
    db.find_device("00:11:22:33:44:BB").set_scan_rsp(None)
    devices = db.on_device_found(-35, pkt, None)
    assert len(devices) == 1
