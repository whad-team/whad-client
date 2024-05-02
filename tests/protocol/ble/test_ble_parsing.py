"""Protocol hub Discovery messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import JamAdvCmd, CentralModeCmd, StartCmd, StopCmd
from whad.hub.ble import BleDomain, SetBdAddress, SniffAdv, SniffConnReq, \
    SniffAccessAddress, SniffActiveConn, AccessAddressDiscovered, JamAdv, \
    JamAdvChan,JamConn, ScanMode, AdvMode, CentralMode, PeriphMode, SetAdvData, \
    SendRawPdu, SendPdu, AdvPduReceived,AddressType, \
    PduReceived, RawPduReceived, ConnectTo, Disconnect, Connected, Disconnected, \
    Start, Stop, HijackMaster, HijackSlave, HijackBoth, Hijacked, ReactiveJam, \
    Synchronized, Desynchronized, PrepareSequenceManual, PrepareSequenceConnEvt, \
    PrepareSequencePattern, Injected

from tests.protocol.ble.test_ble_hijack import hijack_master, hijack_slave, hijack_both, hijacked
from tests.protocol.ble.test_ble_pdu import send_pdu, send_raw_pdu, raw_pdu, pdu, adv_pdu, set_adv_data
from tests.protocol.ble.test_ble_prepseq import prep_seq_manual, prep_seq_connevt, prep_seq_reception

BD_ADDRESS_DEFAULT = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

@pytest.fixture
def set_bd_addr():
    """Create a SetBdAddress protobuf message
    """
    msg = Message()
    msg.ble.set_bd_addr.addr_type = AddressType.PUBLIC
    msg.ble.set_bd_addr.bd_address = BD_ADDRESS_DEFAULT
    return msg

class TestSetBdAddress(object):
    """Test SetBdAddress message parsing/crafting.
    """

    def test_parsing(self, set_bd_addr):
        """Check SetBdAddress parsing
        """
        parsed_obj = SetBdAddress.parse(1, set_bd_addr)
        assert isinstance(parsed_obj, SetBdAddress)
        assert parsed_obj.addr_type == AddressType.PUBLIC
        assert parsed_obj.bd_address == BD_ADDRESS_DEFAULT

    def test_crafting(self):
        """Check SetBdAddress crafting.
        """
        msg = SetBdAddress(
            addr_type=AddressType.PUBLIC,
            bd_address=BD_ADDRESS_DEFAULT
        )
        assert msg.addr_type == AddressType.PUBLIC
        assert msg.bd_address == BD_ADDRESS_DEFAULT

@pytest.fixture
def sniff_adv():
    """Create a SniffAdv protobuf message
    """
    msg = Message()
    msg.ble.sniff_adv.use_extended_adv = False
    msg.ble.sniff_adv.channel = 2
    msg.ble.sniff_adv.bd_address = BD_ADDRESS_DEFAULT
    return msg

class TestSniffAdv(object):
    """Test SniffAdv message parsing/crafting.
    """

    def test_parsing(self, sniff_adv):
        """Check SniffAdv parsing
        """
        parsed_obj = SniffAdv.parse(1, sniff_adv)
        assert isinstance(parsed_obj, SniffAdv)
        assert parsed_obj.channel == 2
        assert parsed_obj.use_extended_adv == False
        assert parsed_obj.bd_address == BD_ADDRESS_DEFAULT

    def test_crafting(self):
        """Check SniffAdv crafting.
        """
        msg = SniffAdv(use_extended_adv=True, channel=37, bd_address=BD_ADDRESS_DEFAULT)
        assert msg.use_extended_adv == True
        assert msg.channel == 37
        assert msg.bd_address == BD_ADDRESS_DEFAULT

@pytest.fixture
def sniff_connreq():
    """Create a SniffAdv protobuf message
    """
    msg = Message()
    msg.ble.sniff_connreq.show_empty_packets = False
    msg.ble.sniff_connreq.show_advertisements = True
    msg.ble.sniff_connreq.channel = 15
    msg.ble.sniff_connreq.bd_address = BD_ADDRESS_DEFAULT
    return msg

class TestSniffConnReq(object):
    """Test SniffConnReq message parsing/crafting.
    """

    def test_parsing(self, sniff_connreq):
        """Check SniffConnReq parsing.
        """
        parsed_obj = SniffConnReq.parse(1, sniff_connreq)
        assert isinstance(parsed_obj, SniffConnReq)
        assert parsed_obj.show_empty_packets == False
        assert parsed_obj.show_advertisements == True
        assert parsed_obj.channel == 15
        assert parsed_obj.bd_address == BD_ADDRESS_DEFAULT

    def test_crafting(self):
        """Check SniffConnReq message crafting.
        """
        msg = SniffConnReq(
            show_empty_packets=True,
            show_advertisements=False,
            channel=16,
            bd_address=BD_ADDRESS_DEFAULT
        )
        assert msg.show_empty_packets == True
        assert msg.show_advertisements == False
        assert msg.channel == 16
        assert msg.bd_address == BD_ADDRESS_DEFAULT

@pytest.fixture
def sniff_aa():
    """Create a SniffAdv protobuf message
    """
    msg = Message()
    msg.ble.sniff_aa.monitored_channels = bytes([2, 17, 28])
    return msg

class TestSniffAccessAddress(object):
    """Test SniffAccessAddress message parsing/crafting
    """

    def test_parsing(self, sniff_aa):
        """Check SniffAccessAddress parsing
        """
        parsed_obj = SniffAccessAddress.parse(1, sniff_aa)
        assert isinstance(parsed_obj, SniffAccessAddress)
        assert parsed_obj.monitored_channels == bytes([2, 17, 28])

    def test_crafting(self):
        """Check SniffAccessAddress crafting
        """
        msg = SniffAccessAddress(monitored_channels=bytes([2, 17, 28]))
        assert msg.monitored_channels == bytes([2, 17, 28])


@pytest.fixture
def sniff_conn():
    """Create a SniffActiveConn protobuf message
    """
    msg = Message()
    msg.ble.sniff_conn.access_address = 0x12345678
    msg.ble.sniff_conn.crc_init = 0xaabbcc
    msg.ble.sniff_conn.channel_map = bytes(range(37))
    msg.ble.sniff_conn.hop_interval = 6
    msg.ble.sniff_conn.hop_increment = 21
    msg.ble.sniff_conn.monitored_channels = bytes(range(37))
    return msg


class TestSniffActiveConn(object):
    """Test SniffActiveConn message parsing/crafting
    """

    def test_parsing(self, sniff_conn):
        """Check SniffActiveConn parsing
        """
        parsed_obj = SniffActiveConn.parse(1, sniff_conn)
        assert isinstance(parsed_obj, SniffActiveConn)
        assert parsed_obj.access_address == 0x12345678
        assert parsed_obj.crc_init == 0xaabbcc
        assert parsed_obj.channel_map == bytes(range(37))
        assert parsed_obj.hop_interval == 6
        assert parsed_obj.hop_increment == 21
        assert parsed_obj.monitored_channels == bytes(range(37))

    def test_crafting(self):
        """Check SniffActiveConn crafting
        """
        msg = SniffActiveConn(
            access_address=0x12345678,
            crc_init=0xAABBCC,
            channel_map=bytes(range(37)),
            hop_interval=6,
            hop_increment=21,
            monitored_channels=bytes(range(37))
        )
        assert msg.access_address == 0x12345678
        assert msg.crc_init == 0xAABBCC
        assert msg.channel_map == bytes(range(37))
        assert msg.hop_interval == 6
        assert msg.hop_increment == 21
        assert msg.monitored_channels == bytes(range(37))

@pytest.fixture
def aa_disc():
    msg = Message()
    msg.ble.aa_disc.access_address = 0x11223344
    msg.ble.aa_disc.rssi = -40
    msg.ble.aa_disc.timestamp = 1234
    return msg

class TestAccessAddressDiscovered(object):
    """Test AccessAddressDiscovered notification message parsing/crafting
    """

    def test_parsing(self, aa_disc):
        """Check AccessAddressDiscovered parsing
        """
        parsed_obj = AccessAddressDiscovered.parse(1, aa_disc)
        assert isinstance(parsed_obj, AccessAddressDiscovered)
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.rssi == -40
        assert parsed_obj.timestamp == 1234

    def test_crafting(self):
        """Check AccessAddressDiscovered crafting
        """
        msg = AccessAddressDiscovered(
            access_address=0x99887766,
            rssi=-68,
            timestamp=7890
        )
        assert msg.access_address == 0x99887766
        assert msg.rssi == -68
        assert msg.timestamp == 7890

@pytest.fixture
def jam_adv():
    msg = Message()
    msg.ble.jam_adv.CopyFrom(JamAdvCmd())
    return msg

class TestJamAdv(object):
    """Test JamAdv message parsing
    """

    def test_jam_adv(self, jam_adv):
        """Check JamAdv parsing
        """
        parsed_obj = JamAdv.parse(1, jam_adv)
        assert isinstance(parsed_obj, JamAdv)

@pytest.fixture
def jam_adv_chan():
    msg = Message()
    msg.ble.jam_adv_chan.channel = 12
    return msg

class TestJamAdvChan(object):
    """Test JamAdvChan message parsing/crafting
    """

    def test_jam_adv_chan(self, jam_adv_chan):
        """Check JamAdvChan parsing
        """
        parsed_obj = JamAdvChan.parse(1, jam_adv_chan)
        assert isinstance(parsed_obj, JamAdvChan)
        assert parsed_obj.channel == 12

    def test_crafting(self):
        """Check JamAdvChan crafting
        """
        msg = JamAdvChan(channel=25)
        assert msg.channel == 25

@pytest.fixture
def jam_conn():
    msg = Message()
    msg.ble.jam_conn.access_address = 0x11223344
    return msg

class TestJamConn(object):
    """Test JamConn message parsing/crafting
    """

    def test_parsing(self, jam_conn):
        """Check JamConn parsing
        """
        parsed_obj = JamConn.parse(1, jam_conn)
        assert isinstance(parsed_obj, JamConn)
        assert parsed_obj.access_address == 0x11223344

    def test_crafting(self):
        """Check JamConn crafting
        """
        msg = JamConn(access_address=0x99887766)
        assert msg.access_address == 0x99887766

@pytest.fixture
def reactive_jam():
    """Create a BLE reactive jam protocol buffer message
    """
    msg = Message()
    msg.ble.reactive_jam.channel = 2
    msg.ble.reactive_jam.pattern = b"PATTERN"
    msg.ble.reactive_jam.position = 1
    return msg

class TestReactiveJam(object):
    """Test ReactiveJam message parsing/crafting
    """

    def test_parsing(self, reactive_jam):
        """Check ReactiveJam parsing
        """
        parsed_obj = ReactiveJam.parse(1, reactive_jam)
        assert isinstance(parsed_obj, ReactiveJam)
        assert parsed_obj.channel == 2
        assert parsed_obj.pattern == b"PATTERN"
        assert parsed_obj.position == 1

    def test_crafting(self):
        """Check ReactiveJam crafting
        """
        msg = ReactiveJam(channel=3, pattern=b"FOOBAR", position=2)
        assert msg.channel == 3
        assert msg.pattern == b"FOOBAR"
        assert msg.position == 2

@pytest.fixture
def scan_mode():
    msg = Message()
    msg.ble.scan_mode.active_scan = True
    return msg

class TestScanMode(object):
    """Test ScanMode message parsing/crafting
    """

    def test_parsing(self, scan_mode):
        """Check ScanMode parsing
        """
        parsed_obj = ScanMode.parse(1, scan_mode)
        assert isinstance(parsed_obj, ScanMode)
        assert parsed_obj.active == True

    def test_crafting(self):
        """Check ScanMode crafting
        """
        msg = ScanMode(active=False)
        assert msg.active == False

@pytest.fixture
def adv_mode():
    msg = Message()
    msg.ble.adv_mode.scan_data = b'TEST'
    msg.ble.adv_mode.scanrsp_data = b'RESPONSE'
    return msg

class TestAdvMode(object):
    """Test AdvMode message parsing/crafting
    """

    def test_parsing(self, adv_mode):
        """Check AdvMode parsing
        """
        parsed_obj = AdvMode.parse(1, adv_mode)
        assert isinstance(parsed_obj, AdvMode)
        assert parsed_obj.scan_data == b'TEST'
        assert parsed_obj.scanrsp_data == b'RESPONSE'

    def test_crafting(self):
        """Check AdvMode crafting
        """
        msg = AdvMode(
            scan_data=b'HELLOWORLD',
            scanrsp_data=b'FOOBAR'
        )
        assert msg.scan_data == b'HELLOWORLD'
        assert msg.scanrsp_data == b'FOOBAR'

@pytest.fixture
def central_mode():
    msg = Message()
    msg.ble.central_mode.CopyFrom(CentralModeCmd())
    return msg

class TestCentralMode(object):
    """Test CentralMode parsing
    """

    def test_parsing(self, central_mode):
        """Check CentralMode parsing
        """
        parsed_obj = CentralMode.parse(1, central_mode)
        assert isinstance(parsed_obj, CentralMode)

@pytest.fixture
def periph_mode():
    msg = Message()
    msg.ble.periph_mode.scan_data = b'TEST'
    msg.ble.periph_mode.scanrsp_data = b'RESPONSE'
    return msg

class TestPeriphMode(object):
    """Test PeriphMode message parsing/crafting
    """

    def test_parsing(self, periph_mode):
        """Check PeriphMode parsing
        """
        parsed_obj = PeriphMode.parse(1, periph_mode)
        assert isinstance(parsed_obj, PeriphMode)
        assert parsed_obj.scan_data == b'TEST'
        assert parsed_obj.scanrsp_data == b'RESPONSE'

    def test_crafting(self):
        """Check PeriphMode crafting
        """
        msg = PeriphMode(
            scan_data=b'HELLOWORLD',
            scanrsp_data=b'FOOBAR'
        )
        assert msg.scan_data == b'HELLOWORLD'
        assert msg.scanrsp_data == b'FOOBAR'

@pytest.fixture
def start():
    """Create BLE start protocol buffer message
    """
    msg = Message()
    msg.ble.start.CopyFrom(StartCmd())
    return msg

class TestStart(object):
    """Test Start message parsing/crafting
    """

    def test_parsing(self, start):
        """Check Start parsing
        """
        parsed_obj = Start.parse(1, start)
        assert isinstance(parsed_obj, Start)

@pytest.fixture
def stop():
    """Create BLE stop protocol buffer message
    """
    msg = Message()
    msg.ble.stop.CopyFrom(StopCmd())
    return msg   

class TestStop(object):
    """Test Stop message parsing/crafting
    """

    def test_parsing(self, stop):
        """Check Stop parsing
        """
        parsed_obj = Stop.parse(1, stop)
        assert isinstance(parsed_obj, Stop)

@pytest.fixture
def connect():
    """Create a BLE connect protocol buffer message
    """
    msg = Message()
    msg.ble.connect.bd_address = BD_ADDRESS_DEFAULT
    msg.ble.connect.addr_type = AddressType.PUBLIC
    msg.ble.connect.access_address = 0x11223344
    msg.ble.connect.channel_map = bytes(range(5))
    msg.ble.connect.hop_interval = 6
    msg.ble.connect.hop_increment = 22
    msg.ble.connect.crc_init = 0x112233
    return msg

class TestConnectTo(object):
    """Test ConnectTo message parsing/crafting
    """

    def test_parsing(self, connect):
        """Check ConnectTo parsing
        """
        parsed_obj = ConnectTo.parse(1, connect)
        assert isinstance(parsed_obj, ConnectTo)
        assert parsed_obj.bd_address == BD_ADDRESS_DEFAULT
        assert parsed_obj.addr_type == AddressType.PUBLIC
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.channel_map == bytes(range(5))
        assert parsed_obj.hop_interval == 6
        assert parsed_obj.hop_increment == 22
        assert parsed_obj.crc_init == 0x112233

    def test_crafting(self):
        """Check ConnectTo crafting
        """
        msg = ConnectTo(
            bd_address=BD_ADDRESS_DEFAULT,
            addr_type=AddressType.RANDOM,
            access_address=0x99887766,
            channel_map=bytes([1,2,3]),
            hop_interval=12,
            hop_increment=8,
            crc_init=0x424242
        )
        assert msg.bd_address == BD_ADDRESS_DEFAULT
        assert msg.addr_type == AddressType.RANDOM
        assert msg.access_address == 0x99887766
        assert msg.channel_map == bytes([1,2,3])
        assert msg.hop_interval == 12
        assert msg.hop_increment == 8
        assert msg.crc_init == 0x424242

@pytest.fixture
def disconnect():
    """Create a BLE disconnect protocol buffer message
    """
    msg = Message()
    msg.ble.disconnect.conn_handle = 3
    return msg


class TestDisconnect(object):
    """Test Disconnect message parsing/crafting
    """

    def test_parsing(self, disconnect):
        """Check Disconnect parsing
        """
        parsed_obj = Disconnect.parse(1, disconnect)
        assert isinstance(parsed_obj, Disconnect)
        assert parsed_obj.conn_handle == 3

    def test_crafting(self):
        """Check Disconnect crafting
        """
        msg = Disconnect(conn_handle=1)
        assert msg.conn_handle == 1

@pytest.fixture
def connected():
    """Create a BLE connected protocol buffer message
    """
    msg = Message()
    msg.ble.connected.initiator = BD_ADDRESS_DEFAULT
    msg.ble.connected.advertiser = BD_ADDRESS_DEFAULT
    msg.ble.connected.access_address = 0x11223344
    msg.ble.connected.conn_handle = 2
    msg.ble.connected.adv_addr_type = AddressType.PUBLIC
    msg.ble.connected.init_addr_type = AddressType.RANDOM
    return msg

class TestConnected(object):
    """Test Connected message parsing/crafting
    """

    def test_parsing(self, connected):
        """Check Connected parsing
        """
        parsed_obj = Connected.parse(1, connected)
        assert isinstance(parsed_obj, Connected)
        assert parsed_obj.initiator == BD_ADDRESS_DEFAULT
        assert parsed_obj.advertiser == BD_ADDRESS_DEFAULT
        assert parsed_obj.conn_handle == 2
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.adv_addr_type == AddressType.PUBLIC
        assert parsed_obj.init_addr_type == AddressType.RANDOM

    def test_crafting(self):
        """Check Connected crafting
        """
        msg = Connected(
            initiator=BD_ADDRESS_DEFAULT,
            advertiser=BD_ADDRESS_DEFAULT,
            access_address=0x99887766,
            conn_handle=3,
            adv_addr_type=AddressType.RANDOM,
            init_addr_type=AddressType.PUBLIC
        )
        assert msg.advertiser == BD_ADDRESS_DEFAULT
        assert msg.initiator == BD_ADDRESS_DEFAULT
        assert msg.conn_handle == 3
        assert msg.access_address == 0x99887766
        assert msg.adv_addr_type == AddressType.RANDOM
        assert msg.init_addr_type == AddressType.PUBLIC

@pytest.fixture
def synchronized():
    """Create a BLE synchronized protocol buffer message
    """
    msg = Message()
    msg.ble.synchronized.access_address = 0x11223344
    msg.ble.synchronized.channel_map = bytes(range(5))
    msg.ble.synchronized.hop_interval = 6
    msg.ble.synchronized.hop_increment = 22
    msg.ble.synchronized.crc_init = 0x112233
    return msg

class TestSynchronized(object):
    """Test Synchronized message parsing/crafting
    """

    def test_parsing(self, synchronized):
        """Check ConnectTo parsing
        """
        parsed_obj = Synchronized.parse(1, synchronized)
        assert isinstance(parsed_obj, Synchronized)
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.channel_map == bytes(range(5))
        assert parsed_obj.hop_interval == 6
        assert parsed_obj.hop_increment == 22
        assert parsed_obj.crc_init == 0x112233

    def test_crafting(self):
        """Check ConnectTo crafting
        """
        msg = Synchronized(
            access_address=0x99887766,
            channel_map=bytes([1,2,3]),
            hop_interval=12,
            hop_increment=8,
            crc_init=0x424242
        )
        assert msg.access_address == 0x99887766
        assert msg.channel_map == bytes([1,2,3])
        assert msg.hop_interval == 12
        assert msg.hop_increment == 8
        assert msg.crc_init == 0x424242

@pytest.fixture
def disconnected():
    """Create a BLE disconnected protocol buffer message
    """
    msg = Message()
    msg.ble.disconnected.reason = 42
    msg.ble.disconnected.conn_handle = 3
    return msg

class TestDisconnected(object):
    """Test Disconnected message parsing/crafting
    """

    def test_parsing(self, disconnected):
        """Check Disconnected parsing
        """
        parsed_obj = Disconnected.parse(1, disconnected)
        assert isinstance(parsed_obj, Disconnected)
        assert parsed_obj.reason == 42
        assert parsed_obj.conn_handle == 3

    def test_crafting(self):
        """Check Disconnected crafting
        """
        msg = Disconnected(reason=33, conn_handle=5)
        assert msg.reason == 33
        assert msg.conn_handle == 5

@pytest.fixture
def desynchronized():
    """Create a BLE desynchronized protocol buffer message
    """
    msg = Message()
    msg.ble.desynchronized.access_address = 0x11223344
    return msg    

class TestDesynchronized(object):
    """Test Desynchronized message parsing/crafting
    """

    def test_parsing(self, desynchronized):
        """Check Desynchronized parsing
        """
        parsed_obj = Desynchronized.parse(1, desynchronized)
        assert isinstance(parsed_obj, Desynchronized)
        assert parsed_obj.access_address == 0x11223344

    def test_crafting(self):
        """Check Desynchronized crafting
        """
        msg = Desynchronized(access_address=0x99887766)
        assert msg.access_address == 0x99887766


@pytest.fixture
def injected():
    """Create a BLE injected protocol buffer message
    """
    msg = Message()
    msg.ble.injected.success = True
    msg.ble.injected.access_address = 0x11223344
    msg.ble.injected.injection_attempts = 2
    return msg

class TestInjected(object):
    """Test Injected message parsing/crafting
    """

    def test_parsing(self, injected):
        """Check Injected parsing
        """
        parsed_obj = Injected.parse(1, injected)
        assert isinstance(parsed_obj, Injected)
        assert parsed_obj.success == True
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.injection_attempts == 2

    def test_crafting(self):
        """Check Injected crafting
        """
        msg = Injected(success=False, access_address=0x99887766, injection_attempts=1)
        assert msg.success == False
        assert msg.access_address == 0x99887766
        assert msg.injection_attempts == 1

###
# BLE Domain parsing
###

class TestBleDomainParsing(object):
    """Test BLE domain message parsing
    """

    def test_set_bd_addr_parsing(self, set_bd_addr):
        """Check SetBdAddress message parsing
        """
        msg = BleDomain.parse(1, set_bd_addr)
        assert isinstance(msg, SetBdAddress)

    def test_sniff_adv_parsing(self, sniff_adv):
        """Check SniffAdv message parsing
        """
        msg = BleDomain.parse(1, sniff_adv)
        assert isinstance(msg, SniffAdv)

    def test_sniff_connreq_parsing(self, sniff_connreq):
        """Check SniffConnReq message parsing
        """
        msg = BleDomain.parse(1, sniff_connreq)
        assert isinstance(msg, SniffConnReq)

    def test_sniff_aa_parsing(self, sniff_aa):
        """Check SniffAccessAddress message parsing
        """
        msg = BleDomain.parse(1, sniff_aa)
        assert isinstance(msg, SniffAccessAddress)

    def test_sniff_conn_parsing(self, sniff_conn):
        """Check SniffActiveConn message parsing
        """
        msg = BleDomain.parse(1, sniff_conn)
        assert isinstance(msg, SniffActiveConn)

    def test_aa_disc_parsing(self, aa_disc):
        """Check AccessAddressDiscovered message parsing
        """
        msg = BleDomain.parse(1, aa_disc)
        assert isinstance(msg, AccessAddressDiscovered)

    def test_jam_adv_parsing(self, jam_adv):
        """Check JamAdv message parsing
        """
        msg = BleDomain.parse(1, jam_adv)
        assert isinstance(msg, JamAdv)

    def test_jam_adv_chan_parsing(self, jam_adv_chan):
        """Check JamAdvChan message parsing
        """
        msg = BleDomain.parse(1, jam_adv_chan)
        assert isinstance(msg, JamAdvChan)

    def test_jam_conn_parsing(self, jam_conn):
        """Check JamConn message parsing
        """
        msg = BleDomain.parse(1, jam_conn)
        assert isinstance(msg, JamConn)

    def test_reactive_jam_parsing(self, reactive_jam):
        """Check ReactiveJam message parsing
        """
        msg = BleDomain.parse(1, reactive_jam)
        assert isinstance(msg, ReactiveJam)

    def test_scan_mode_parsing(self, scan_mode):
        """Check ScanMode message parsing
        """
        msg = BleDomain.parse(1, scan_mode)
        assert isinstance(msg, ScanMode)

    def test_adv_mode_parsing(self, adv_mode):
        """Check AdvMode message parsing
        """
        msg = BleDomain.parse(1, adv_mode)
        assert isinstance(msg, AdvMode)

    def test_central_mode_parsing(self, central_mode):
        """Check CentralMode message parsing
        """
        msg = BleDomain.parse(1, central_mode)
        assert isinstance(msg, CentralMode)

    def test_periph_mode_parsing(self, periph_mode):
        """Check PeriphMode message parsing
        """
        msg = BleDomain.parse(1, periph_mode)
        assert isinstance(msg, PeriphMode)

    def test_start_parsing(self, start):
        """Check Start message parsing
        """
        msg = BleDomain.parse(1, start)
        assert isinstance(msg, Start)

    def test_stop_parsing(self, stop):
        """Check Stop message parsing
        """
        msg = BleDomain.parse(1, stop)
        assert isinstance(msg, Stop)

    def test_set_adv_data_parsing(self, set_adv_data):
        """Check SetAdvData message parsing
        """
        msg = BleDomain.parse(1, set_adv_data)
        assert isinstance(msg, SetAdvData)

    def test_send_raw_pdu_parsing(self, send_raw_pdu):
        """Check SendRawPdu message parsing
        """
        msg = BleDomain.parse(1, send_raw_pdu)
        assert isinstance(msg, SendRawPdu)

    def test_send_pdu_parsing(self, send_pdu):
        """Check SendPdu message parsing
        """
        msg = BleDomain.parse(1, send_pdu)
        assert isinstance(msg, SendPdu)

    def test_adv_pdu_parsing(self, adv_pdu):
        """Check AdvPduReceived message parsing
        """
        msg = BleDomain.parse(1, adv_pdu)
        assert isinstance(msg, AdvPduReceived)

    def test_pdu_parsing(self, pdu):
        """Check PduReceived message parsing
        """
        msg = BleDomain.parse(1, pdu)
        assert isinstance(msg, PduReceived)

    def test_raw_pdu_parsing(self, raw_pdu):
        """Check RawPduReceived message parsing
        """
        msg = BleDomain.parse(1, raw_pdu)
        assert isinstance(msg, RawPduReceived)

    def test_connect_parsing(self, connect):
        """Check ConnectTo message parsing
        """
        msg = BleDomain.parse(1, connect)
        assert isinstance(msg, ConnectTo)

    def test_disconnect_parsing(self, disconnect):
        """Check Disconnect message parsing
        """
        msg = BleDomain.parse(1, disconnect)
        assert isinstance(msg, Disconnect)

    def test_connected_parsing(self, connected):
        """Check Connected message parsing
        """
        msg = BleDomain.parse(1, connected)
        assert isinstance(msg, Connected)

    def test_synchronized_parsing(self, synchronized):
        """Check Synchronized message parsing
        """
        msg = BleDomain.parse(1, synchronized)
        assert isinstance(msg, Synchronized)

    def test_disconnected_parsing(self, disconnected):
        """Check Disconnected message parsing
        """
        msg = BleDomain.parse(1, disconnected)
        assert isinstance(msg, Disconnected)

    def test_desynchronized_parsing(self, desynchronized):
        """Check Desynchronized message parsing
        """
        msg = BleDomain.parse(1, desynchronized)
        assert isinstance(msg, Desynchronized)

    def test_hijack_master_parsing(self, hijack_master):
        """Check HijackMaster message parsing
        """
        msg = BleDomain.parse(1, hijack_master)
        assert isinstance(msg, HijackMaster)

    def test_hijack_slave_parsing(self, hijack_slave):
        """Check HijackSlave message parsing
        """
        msg = BleDomain.parse(1, hijack_slave)
        assert isinstance(msg, HijackSlave)

    def test_hijack_both_parsing(self, hijack_both):
        """Check HijackBoth message parsing
        """
        msg = BleDomain.parse(1, hijack_both)
        assert isinstance(msg, HijackBoth)

    def test_hijacked_parsing(self, hijacked):
        """Check Hijacked message parsing
        """
        msg = BleDomain.parse(1, hijacked)
        assert isinstance(msg, Hijacked)

    def test_prep_seq_manual_parsing(self, prep_seq_manual):
        """Check PrepareSequenceManual message parsing
        """
        msg = BleDomain.parse(1, prep_seq_manual)
        assert isinstance(msg, PrepareSequenceManual)

    def test_prep_seq_connevt_parsing(self, prep_seq_connevt):
        """Check PrepareSequenceConnEvt message parsing
        """
        msg = BleDomain.parse(1, prep_seq_connevt)
        assert isinstance(msg, PrepareSequenceConnEvt)

    def test_prep_seq_pattern_parsing(self, prep_seq_reception):
        """Check PrepareSequencePattern message parsing
        """
        msg = BleDomain.parse(1, prep_seq_reception)
        assert isinstance(msg, PrepareSequencePattern)

    def test_injected_parsing(self, injected):
        """Check Injected message parsing
        """
        msg = BleDomain.parse(1, injected)
        assert isinstance(msg, Injected)
