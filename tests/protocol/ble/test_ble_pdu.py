"""Protocol hub BLE PDU messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.hub.ble import SendBleRawPdu, Direction, SendBlePdu, BleAdvPduReceived, \
    AdvType, AddressType, BlePduReceived, BleRawPduReceived, SetAdvData

BD_ADDRESS_DEFAULT = bytes([0x11, 0x22, 0x33, 0x44, 0x55, 0x66])

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
def send_ble_raw_pdu():
    """Create a send_ble_raw_pdu protocol buffer message.
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
    """Test SendBleRawPdu message parsing/crafting
    """

    def test_parsing(self, send_ble_raw_pdu):
        """Check SendBleRawPdu parsing
        """
        parsed_obj = SendBleRawPdu.parse(1, send_ble_raw_pdu)
        assert isinstance(parsed_obj, SendBleRawPdu)
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.conn_handle == 1
        assert parsed_obj.access_address == 0x11223344
        assert parsed_obj.pdu == b"HELLOWORLD"
        assert parsed_obj.crc == 0x112233
        assert parsed_obj.encrypt == False

    def test_crafting(self):
        """Check SendRawPdu crafting
        """
        msg = SendBleRawPdu(
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
def send_ble_pdu():
    """Create a send_ble_pdu protocol buffer message.
    """
    msg = Message()
    msg.ble.send_pdu.direction = Direction.MASTER_TO_SLAVE
    msg.ble.send_pdu.conn_handle = 1
    msg.ble.send_pdu.pdu = b"HELLOWORLD"
    msg.ble.send_pdu.encrypt = False
    return msg

class TestSendPdu(object):
    """Test SendPdu message parsing/crafting
    """

    def test_parsing(self, send_ble_pdu):
        """Check SendBlePdu parsing
        """
        parsed_obj = SendBlePdu.parse(1, send_ble_pdu)
        assert isinstance(parsed_obj, SendBlePdu)
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.conn_handle == 1
        assert parsed_obj.pdu == b"HELLOWORLD"
        assert parsed_obj.encrypt == False

    def test_crafting(self):
        """Check SendPdu crafting
        """
        msg = SendBlePdu(
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
def ble_adv_pdu():
    """Create an ble_adv_pdu protocol buffer message
    """
    msg = Message()
    msg.ble.adv_pdu.adv_type = AdvType.ADV_IND
    msg.ble.adv_pdu.rssi = -50
    msg.ble.adv_pdu.bd_address = BD_ADDRESS_DEFAULT
    msg.ble.adv_pdu.adv_data = b"FOOBAR"
    msg.ble.adv_pdu.addr_type = AddressType.PUBLIC
    return msg

class TestAdvPduReceived(object):
    """Test BleAdvPduReceived message parsing/crafting
    """

    def test_parsing(self, ble_adv_pdu):
        """Check BleAdvPduReceived parsing
        """
        parsed_obj = BleAdvPduReceived.parse(1, ble_adv_pdu)
        assert isinstance(parsed_obj, BleAdvPduReceived)
        assert parsed_obj.adv_type == AdvType.ADV_IND
        assert parsed_obj.rssi == -50
        assert parsed_obj.bd_address == BD_ADDRESS_DEFAULT
        assert parsed_obj.adv_data == b"FOOBAR"
        assert parsed_obj.addr_type == AddressType.PUBLIC

    def test_crafting(self):
        """Check AdvPduReceived crafting
        """
        msg = BleAdvPduReceived(
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
def ble_pdu():
    """Create a ble_pdu protocol buffer message
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
    
    def test_parsing(self, ble_pdu):
        """Check BlePduReceived parsing
        """
        parsed_obj = BlePduReceived.parse(1, ble_pdu)
        print(parsed_obj)
        assert isinstance(parsed_obj, BlePduReceived)
        assert parsed_obj.direction == Direction.MASTER_TO_SLAVE
        assert parsed_obj.conn_handle == 1
        assert parsed_obj.pdu == b"HELLOWORLD"
        assert parsed_obj.processed == False
        assert parsed_obj.decrypted == False

    def test_crafting(self):
        """Check PduReceived crafting
        """
        msg = BlePduReceived(
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
        """Check BleRawPduReceived parsing
        """
        parsed_obj = BleRawPduReceived.parse(1, raw_pdu)
        assert isinstance(parsed_obj, BleRawPduReceived)
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
        """Check BleRawPduReceived crafting
        """
        msg = BleRawPduReceived(
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
