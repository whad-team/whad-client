""" WHAD generic connector unit tests"""

import pytest
from time import sleep, time
from queue import Queue, Empty

from whad.device import Connector, DeviceEvt, MessageReceived, Disconnected
from whad.device.mock import MockDevice, MockConnector, ReplayMock
from whad.exceptions import RequiredImplementation

from whad.hub import ProtocolHub
from whad.hub.ble import Commands, Direction, AddressType
from whad.hub.ble.connect import Disconnected as BleDisconnected
from whad.hub.ble.pdu import BlePduReceived
from whad.hub.discovery import Capability, Domain

@pytest.fixture
def mock_device():
    # Default commands
    commands = [
        Commands.CentralMode,
        Commands.Start, Commands.Stop,
        Commands.ConnectTo,
        Commands.SendPDU,
    ]
    capabilities = Capability.NoRawData

    caps = {
        Domain.BtLE : (
            # We can only scan and sniff with no raw data support
            capabilities,
            commands
        )
    }
    return MockDevice(capabilities=caps)

@pytest.fixture
def mock_replay():
    # Default commands
    commands = [
        Commands.CentralMode,
        Commands.Start, Commands.Stop,
        Commands.ConnectTo,
        Commands.SendPDU,
    ]
    capabilities = Capability.NoRawData

    caps = {
        Domain.BtLE : (
            # We can only scan and sniff with no raw data support
            capabilities,
            commands
        )
    }

    # Default messages
    class DummyConnector:
        interface='dummy'

    hub = ProtocolHub()
    msg = hub.ble.create_pdu_received(
        direction=Direction.SLAVE_TO_MASTER,
        conn_handle=12,
        pdu=b"FOOBAR",
        processed=False,
        decrypted=False
    )

    messages = [
        MessageReceived(DummyConnector(), msg),
        Disconnected(),
    ]
    return ReplayMock(capabilities=caps, messages=messages, delay=0.2)

def test_create_without_device():
    """Instantiate a connector with no device."""
    conn = Connector()
    assert conn.device is None

def test_create_with_device(mock_device):
    """Instantiate a connector with a mock device."""
    conn = Connector(mock_device)
    assert conn.device == mock_device
    assert conn.is_locked() == False

def test_locking(mock_device):
    """
    Test WHAD's connector locking mechanism: when locked, the connector
    should send any received PDU into a dedicated queue, that is process
    once unlocked.
    """
    hub = ProtocolHub()
    unlocked_msgs = []

    # Custom PDU dispatch callback to keep track of unlocked PDUs.
    def local_pdu_cb(message):
        unlocked_msgs.append(message)

    # Instantiate a connector not tied to a device (simulated here)
    conn = Connector(mock_device)

    # We lock our connector
    conn.lock()

    # We send a MessageReceived event with some basic BLE PDU
    pdu = hub.ble.create_pdu_received(Direction.MASTER_TO_SLAVE, b"FOOBAR", 1)
    event = MessageReceived(conn.device, pdu)
    conn.send_event(event)

    # Wait for the connector IO thread to process our event and detect any deadlock
    _start = time()
    while not conn.has_locked_pdus() and (time() - _start) < 5.0:
        sleep(.1)

    # This event should end up in the connector's locked PDUs
    conn.unlock(dispatch_callback=local_pdu_cb)
    assert len(unlocked_msgs) == 1
    assert unlocked_msgs[0] == pdu

def test_attach_callback_nothing():
    """Try attaching a callback to a connector."""
    conn = Connector()

    # Our custom callback function
    def _callback(packet):
        pass

    # Attach our callback on nothing
    assert conn.attach_callback(_callback, on_reception=False,
                                on_transmission=False) == False

def test_attach_callback_rx():
    """Test attaching a callback for RX packets."""
    conn = Connector()

    def _callback(packet):
        """Dummy callback"""

    assert conn.attach_callback(_callback, on_reception=True)

def test_detach_unregistered_callback():
    """Try to detach an unregistered callback"""
    conn = Connector()

    def _callback(packet):
        """Dummy callback"""

    assert conn.detach_callback(_callback) == False

def test_attach_callback_tx():
    """Test attaching a callback for TX packets."""
    conn = Connector()

    def _callback(packet):
        """Dummy callback"""

    assert conn.attach_callback(_callback, on_transmission=True)

def test_rx_callback(mock_device):
    """Set an RX callback and check it is called as expected when
    a PDU is received.
    """
    hub = ProtocolHub()
    mon_pkts = Queue()

    def _rx_cb(packet):
        mon_pkts.put(packet)

    # Create a mock connector, just to get rid of RequiredImplementation errors.
    conn = MockConnector(mock_device)

    # Attach our RX callback
    conn.attach_callback(_rx_cb, on_reception=True, packet= lambda x: True)

    # Send a received PDU (it will raise an exception as in the default connector
    # the method handling BLE PDU should be defined by inherited classes.
    pdu = hub.ble.create_pdu_received(Direction.MASTER_TO_SLAVE, b"FOOBAR", 1)
    event = MessageReceived(conn.device, pdu)
    conn.send_event(event)

    # Check that our monitor caught the packet
    try:
        rx_pkt = mon_pkts.get(block=True, timeout=.1)
    except Empty:
        assert False

def test_tx_callback(mock_device):
    """Set an TX callback and check it is called as expected when
    a PDU is received.
    """
    hub = ProtocolHub()
    mon_pkts = Queue()

    def _tx_cb(packet):
        mon_pkts.put(packet)

    # Create a mock connector, just to get rid of RequiredImplementation errors.
    conn = MockConnector(mock_device)

    # Attach our TX callback
    conn.attach_callback(_tx_cb, on_transmission=True, packet= lambda x: True)

    # Send a transmit PDU (it will raise an exception as in the default connector
    # the method handling BLE PDU should be defined by inherited classes.
    pdu = hub.ble.create_send_pdu(Direction.MASTER_TO_SLAVE, b"FOOBAR", 1)
    event = MessageReceived(conn.device, pdu)
    conn.send_event(event)

    # Check that our monitor caught the packet
    try:
        tx_pkt = mon_pkts.get(block=True, timeout=.1)
    except Empty:
        assert False

def test_enabling_synchronous_mode():
    """Test enabling synchronous mode"""
    conn = Connector()
    conn.enable_synchronous(True)
    assert conn.is_synchronous() == True

def test_disabling_synchronous_mode():
    """Test enabling synchronous mode"""
    conn = Connector()
    conn.enable_synchronous(True)
    conn.enable_synchronous(False)
    assert conn.is_synchronous() == False

def test_sniffing_all(mock_replay):
    """Try sniffing data from a device."""
    conn = Connector(mock_replay)
    mock_replay.open()
    mock_replay.discover()
    messages = []
    for message in conn.sniff(timeout=.5):
        messages.append(message)
    assert len(messages) == 1
    assert isinstance(messages[0], BlePduReceived)

def test_sniffing_filter_nomatch(mock_replay):
    """Try sniffing specific messages from a device."""
    conn = MockConnector(mock_replay)
    mock_replay.open()
    mock_replay.discover()
    messages = []
    for message in conn.sniff(messages=(Connector), timeout=1.0):
        messages.append(message)
    assert len(messages) == 0

def test_sniffing_filter_match(mock_replay):
    """Sniff messages with a single match."""
    conn = MockConnector(mock_replay)
    mock_replay.open()
    mock_replay.discover()
    messages = []
    for message in conn.sniff(messages=(BlePduReceived), timeout=1.0):
        messages.append(message)
    assert len(messages) == 1

