"""Test Bluetooth Low Energy Sniffer class.
"""
import pytest

from scapy.layers.bluetooth4LE import BTLE_ADV_IND

from whad.ble.mock import DeviceScan, EmulatedDevice
from whad.ble import BDAddress
from whad.ble.connector.sniffer import Sniffer, SnifferConfiguration


@pytest.fixture
def mock_devices():
    """BLE mock devices
    """
    return [
        EmulatedDevice(BDAddress("00:11:22:33:44:55", random=False),
                    adv_data=b"\x02\x01\x06", scan_data=b"\x07\x08foobar"),
    ]

@pytest.fixture
def sniff_mock(mock_devices):
    """Create a BLE DeviceScan mock.
    """
    return DeviceScan(devices=mock_devices, sniffing=True, nowait=True)

def test_sniffer_create(sniff_mock):
    """Test creating a Bluetooth sniffer.
    """
    sniffer = Sniffer(sniff_mock)
    sniffer.start()
    packets = []
    for packet in sniffer.sniff(timeout=2.0):
        packets.append(packet)
        break
    sniffer.stop()
    assert packets[0][BTLE_ADV_IND].AdvA == "00:11:22:33:44:55"

def test_sniffer_channel_set(sniff_mock):
    """Test sniffing on different channels
    """
    # Create sniffer
    sniffer = Sniffer(sniff_mock)

    # Create a specific configuration to sniff on channel 38
    sniffer_cfg = SnifferConfiguration()
    sniffer_cfg.channel = 38
    sniffer.configuration = sniffer_cfg

    # Sniff for advertisement data
    sniffer.start()
    packets = []
    for packet in sniffer.sniff(timeout=2.0):
        packets.append(packet)
        break
    sniffer.stop()
    assert packets[0].metadata.channel is None

def test_sniffer_channel_default(sniff_mock):
    """Test sniffing on different channels
    """
    # Create sniffer
    sniffer = Sniffer(sniff_mock)

    # Create a specific configuration to sniff on channel 38
    sniffer_cfg = SnifferConfiguration()
    sniffer.configuration = sniffer_cfg

    # Sniff for advertisement data
    sniffer.start()
    packets = []
    for packet in sniffer.sniff(timeout=2.0):
        packets.append(packet)
        break
    sniffer.stop()
    assert packets[0].metadata.channel is None

def test_sniffer_address_filter_match(sniff_mock):
    """Test sniffing advertisements sent by a specific device
    """
    # Create sniffer
    sniffer = Sniffer(sniff_mock)

    # Create a specific configuration to sniff on channel 38
    sniffer_cfg = SnifferConfiguration()
    sniffer_cfg.filter = "00:11:22:33:44:55"
    sniffer.configuration = sniffer_cfg

    # Sniff for advertisement data
    sniffer.start()
    packets = []
    for packet in sniffer.sniff(timeout=2.0):
        packets.append(packet)
        break
    sniffer.stop()

    # We must have a single packet with BD address matching our filtered address
    assert len(packets) >= 1
    assert packets[0][BTLE_ADV_IND].AdvA == "00:11:22:33:44:55"

def test_sniffer_address_filter_nomatch(sniff_mock):
    """Test sniffing advertisements sent by a specific device
    """
    # Create sniffer
    sniffer = Sniffer(sniff_mock)

    # Create a specific configuration to sniff on channel 38
    sniffer_cfg = SnifferConfiguration()
    sniffer_cfg.filter = "00:11:22:33:44:66"
    sniffer.configuration = sniffer_cfg

    # Sniff for advertisement data
    sniffer.start()
    packets = []
    for packet in sniffer.sniff(timeout=0.5):
        packets.append(packet)
        break
    sniffer.stop()

    # We expect no packet as we filtered on the wrong BD address
    assert len(packets) == 0
