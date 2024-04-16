"""Protocol hub Discovery messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import JamAdvCmd, CentralModeCmd, StartCmd, StopCmd
from whad.protocol.hub.ble import BleDomain, SetBdAddress, SniffAdv, SniffConnReq, \
    SniffAccessAddress, SniffActiveConn, AccessAddressDiscovered, JamAdv, \
    JamAdvChan,JamConn, ScanMode, AdvMode, CentralMode, PeriphMode, SetAdvData, \
    SendRawPdu, Direction, SendPdu, AdvPduReceived, AdvType, Direction, AddressType, \
    PduReceived, RawPduReceived, ConnectTo, Disconnect, Connected, Disconnected, \
    Start, Stop

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
def set_adv_data():
    msg = Message()
    msg.ble.set_adv_data.scan_data = b'TEST'
    msg.ble.set_adv_data.scanrsp_data = b'RESPONSE'
    return msg

class TestSetAdvData(object):
    """Test SetAdvData message parsing/crafting
    """

    def test_parsing(self, set_adv_data):
        """Check SetAdvData parsing
        """
        parsed_obj = SetAdvData.parse(1, set_adv_data)
        assert isinstance(parsed_obj, SetAdvData)
        assert parsed_obj.scan_data == b'TEST'
        assert parsed_obj.scanrsp_data == b'RESPONSE'

    def test_crafting(self):
        """Check SetAdvData crafting
        """
        msg = SetAdvData(
            scan_data=b'HELLOWORLD',
            scanrsp_data=b'FOOBAR'
        )
        assert msg.scan_data == b'HELLOWORLD'
        assert msg.scanrsp_data == b'FOOBAR'

@pytest.fixture
def send_raw_pdu():
    """Create a send_raw_pdu protocol buffer message.
    """
    msg = Message()
    msg.ble.send_raw_pdu.direction = Direction.MASTER_TO_SLAVE
    msg.ble.send_raw_pdu.conn_handle = 1
    msg.ble.send_raw_pdu.access_address = 0x11223344
    msg.ble.send_raw_pdu.pdu = b"HELLOWORLD"
    msg.ble.send_raw_pdu.crc = 0x112233
    msg.ble.send_raw_pdu.encrypt = False
    return msg

class TestSendRawPdu(object):
    """Test SendRawPdu message parsing/crafting
    """

    def test_parsing(self, send_raw_pdu):
        """Check SendRawPdu parsing
        """
        parsed_obj = SendRawPdu.parse(1, send_raw_pdu)
        assert isinstance(parsed_obj, SendRawPdu)
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.conn_handle == 1
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.pdu == b"HELLOWORLD"
        assert parsed_obj.crc == 0x112233
        assert parsed_obj.encrypt == False

    def test_crafting(self):
        """Check SendRawPdu crafting
        """
        msg = SendRawPdu(
            direction=Direction.SLAVE_TO_MASTER,
            conn_handle=2,
            access_address=0x99887766,
            pdu=b"FOOBAR",
            crc=0xAABBCC,
            encrypt=True
        )
        assert msg.direction == Direction.SLAVE_TO_MASTER
        assert msg.conn_handle == 2
        assert msg.access_address == 0x99887766
        assert msg.pdu == b"FOOBAR"
        assert msg.crc == 0xAABBCC
        assert msg.encrypt == True


@pytest.fixture
def send_pdu():
    """Create a send_pdu protocol buffer message.
    """
    msg = Message()
    msg.ble.send_raw_pdu.direction = Direction.MASTER_TO_SLAVE
    msg.ble.send_raw_pdu.conn_handle = 1
    msg.ble.send_raw_pdu.pdu = b"HELLOWORLD"
    msg.ble.send_raw_pdu.encrypt = False
    return msg

class TestSendPdu(object):
    """Test SendPdu message parsing/crafting
    """

    def test_parsing(self, send_pdu):
        """Check SendRawPdu parsing
        """
        parsed_obj = SendPdu.parse(1, send_pdu)
        assert isinstance(parsed_obj, SendPdu)
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.conn_handle == 1
        assert parsed_obj.pdu == b"HELLOWORLD"
        assert parsed_obj.encrypt == False

    def test_crafting(self):
        """Check SendPdu crafting
        """
        msg = SendPdu(
            direction=Direction.SLAVE_TO_MASTER,
            conn_handle=2,
            pdu=b"FOOBAR",
            encrypt=True
        )
        assert msg.direction == Direction.SLAVE_TO_MASTER
        assert msg.conn_handle == 2
        assert msg.pdu == b"FOOBAR"
        assert msg.encrypt == True


@pytest.fixture
def adv_pdu():
    """Create an adv_pdu protocol buffer message
    """
    msg = Message()
    msg.ble.adv_pdu.adv_type = AdvType.ADV_IND
    msg.ble.adv_pdu.rssi = -50
    msg.ble.adv_pdu.bd_address = BD_ADDRESS_DEFAULT
    msg.ble.adv_pdu.adv_data = b"FOOBAR"
    msg.ble.adv_pdu.addr_type = AddressType.PUBLIC
    return msg

class TestAdvPduReceived(object):
    """Test AdvPduReceived message parsing/crafting
    """

    def test_parsing(self, adv_pdu):
        """Check AdvPduReceived parsing
        """
        parsed_obj = AdvPduReceived.parse(1, adv_pdu)
        assert isinstance(parsed_obj, AdvPduReceived)
        assert parsed_obj.adv_type == AdvType.ADV_IND
        assert parsed_obj.rssi == -50
        assert parsed_obj.bd_address == BD_ADDRESS_DEFAULT
        assert parsed_obj.adv_data == b"FOOBAR"
        assert parsed_obj.addr_type == AddressType.PUBLIC

    def test_crafting(self):
        """Check AdvPduReceived crafting
        """
        msg = AdvPduReceived(
            adv_type=AdvType.ADV_NONCONN_IND,
            rssi=30,
            bd_address=BD_ADDRESS_DEFAULT,
            adv_data=b"HELLOWORLD",
            addr_type=AddressType.RANDOM
        )
        assert msg.adv_type == AdvType.ADV_NONCONN_IND
        assert msg.rssi == 30
        assert msg.bd_address == BD_ADDRESS_DEFAULT
        assert msg.adv_data == b"HELLOWORLD"
        assert msg.addr_type == AddressType.RANDOM

 
@pytest.fixture
def pdu():
    """Create a pdu protocol buffer message
    """
    msg = Message()
    msg.ble.pdu.direction = Direction.MASTER_TO_SLAVE
    msg.ble.pdu.conn_handle = 1
    msg.ble.pdu.pdu = b"HELLOWORLD"
    msg.ble.pdu.processed = False
    msg.ble.pdu.decrypted = False
    return msg

class TestPduReceived(object):
    """Test PduReceived message parsing/crafting
    """
    
    def test_parsing(self, pdu):
        """Check PduReceived parsing
        """
        parsed_obj = PduReceived.parse(1, pdu)
        assert isinstance(parsed_obj, PduReceived)
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.conn_handle == 1
        assert parsed_obj.pdu == b"HELLOWORLD"
        assert parsed_obj.processed == False
        assert parsed_obj.decrypted == False

    def test_crafting(self):
        """Check PduReceived crafting
        """
        msg = PduReceived(
            direction=Direction.SLAVE_TO_MASTER,
            conn_handle=3,
            pdu=b"FOOBAR",
            processed=True,
            decrypted=True
        )
        assert msg.direction == Direction.SLAVE_TO_MASTER
        assert msg.conn_handle == 3
        assert msg.pdu == b"FOOBAR"
        assert msg.processed == True
        assert msg.decrypted == True

@pytest.fixture
def raw_pdu():
    """Create a raw_pdu protocol buffer message
    """
    msg = Message()
    msg.ble.raw_pdu.direction = Direction.MASTER_TO_SLAVE
    msg.ble.raw_pdu.channel = 10
    msg.ble.raw_pdu.rssi = -60
    msg.ble.raw_pdu.timestamp = 1234
    msg.ble.raw_pdu.relative_timestamp = 10
    msg.ble.raw_pdu.crc_validity = True
    msg.ble.raw_pdu.access_address = 0x11223344
    msg.ble.raw_pdu.pdu = b"HELLOWORLD"
    msg.ble.raw_pdu.crc = 0xAABBCC
    msg.ble.raw_pdu.conn_handle = 42
    msg.ble.raw_pdu.processed = False
    msg.ble.raw_pdu.decrypted = False
    return msg

class TestRawPduReceived(object):
    """Test RawPduReceived message parsing/crafting
    """

    def test_parsing(self, raw_pdu):
        """Check RawPduReceived parsing
        """
        parsed_obj = RawPduReceived.parse(1, raw_pdu)
        assert isinstance(parsed_obj, RawPduReceived)
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.channel == 10
        assert parsed_obj.rssi == -60
        assert parsed_obj.timestamp == 1234
        assert parsed_obj.relative_timestamp == 10
        assert parsed_obj.crc_validity == True
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.pdu == b"HELLOWORLD"
        assert parsed_obj.crc == 0xAABBCC
        assert parsed_obj.conn_handle == 42
        assert parsed_obj.processed == False
        assert parsed_obj.decrypted == False

    def test_crafting(self):
        """Check RawPduReceived crafting
        """
        msg = RawPduReceived(
            direction=Direction.SLAVE_TO_MASTER,
            channel=22,
            rssi=-10,
            timestamp=5555,
            relative_timestamp=12,
            crc_validity=False,
            access_address=0x99887766,
            pdu=b"FOOBAR",
            crc=0x112233,
            conn_handle=8,
            processed=True,
            decrypted=False
        )
        assert msg.direction == Direction.SLAVE_TO_MASTER
        assert msg.channel == 22
        assert msg.rssi == -10
        assert msg.timestamp == 5555
        assert msg.relative_timestamp == 12
        assert msg.crc_validity == False
        assert msg.access_address == 0x99887766
        assert msg.pdu == b"FOOBAR"
        assert msg.crc == 0x112233
        assert msg.conn_handle == 8
        assert msg.processed == True
        assert msg.decrypted == False

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

