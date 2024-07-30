"""Protocol hub Discovery messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import JamAdvCmd, CentralModeCmd, StartCmd, StopCmd
from whad.hub.ble import BleDomain, SetBdAddress, SniffAdv, SniffConnReq, \
    SniffAccessAddress, SniffActiveConn, AccessAddressDiscovered, JamAdv, \
    JamAdvChan,JamConn, ScanMode, AdvMode, CentralMode, PeriphMode, SetAdvData, \
    SendBleRawPdu, SendBlePdu, BleAdvPduReceived,AddressType, \
    BlePduReceived, BleRawPduReceived, ConnectTo, Disconnect, Connected, Disconnected, \
    BleStart, BleStop, HijackMaster, HijackSlave, HijackBoth, Hijacked, ReactiveJam, \
    Synchronized, Desynchronized, PrepareSequenceManual, PrepareSequenceConnEvt, \
    PrepareSequencePattern, Injected, Direction, AdvType, Triggered, Trigger, DeleteSequence, \
    SetEncryption

from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble.chanmap import DefaultChannelMap

class TestBleDomainFactory(object):
    """Test BleDomain factory
    """

    @pytest.fixture
    def factory(self):
        return BleDomain(1)

    def test_SetBdAddress(self, factory: BleDomain):
        """Test creation of SetBdAddress message
        """
        address = BDAddress(
            '00:11:22:33:44:55', random=False
        )
        obj = factory.create_set_bd_address(address)
        assert isinstance(obj, SetBdAddress)
        assert obj.bd_address == address.value
        assert obj.addr_type == AddressType.PUBLIC

    def test_SniffAdv(self, factory: BleDomain):
        """Test creation of SniffAdv message
        """
        obj = factory.create_sniff_adv(2, BDAddress('00:11:22:33:44:55'))
        assert isinstance(obj, SniffAdv)

    def test_SniffConnReq(self, factory: BleDomain):
        """Test creation of SniffConnReq message
        """
        obj = factory.create_sniff_connreq(3, BDAddress('00:11:22:33:44:55'),
                                         show_empty=True, show_adv=True)
        assert isinstance(obj, SniffConnReq)

    def test_SniffAA(self, factory: BleDomain):
        """Test creation of SniffAccessAddress message
        """
        obj = factory.create_sniff_access_address([0,1,2,3,4])
        assert isinstance(obj, SniffAccessAddress)

    def test_SniffActiveConn(self, factory: BleDomain):
        """Test creation of SniffActiveConn message
        """
        obj = factory.create_sniff_active_conn(
            access_address=0x11223344,
            crc_init=0xaabbcc,
            channel_map=DefaultChannelMap,
            interval=6,
            increment=21,
        )
        assert isinstance(obj, SniffActiveConn)

    def test_AccessAddressDiscovered(self, factory: BleDomain):
        """Test creation of AccessAddressDiscovered message
        """
        obj = factory.create_access_address_discovered(
            access_address=0x11223344,
            rssi=-40,
            timestamp=1234
        )
        assert isinstance(obj, AccessAddressDiscovered)

    def test_JamAdv(self, factory: BleDomain):
        """Test creation of JamAdv message
        """
        obj = factory.create_jam_adv()
        assert isinstance(obj, JamAdv)

    def test_JamAdvChan(self, factory: BleDomain):
        """Test creation of JamAdvChan message
        """
        obj = factory.create_jam_adv_chan(12)
        assert isinstance(obj, JamAdvChan)

    def test_ReactiveJam(self, factory: BleDomain):
        """Test creation of ReactiveJam message
        """
        obj = factory.create_reactive_jam(
            2, b"FOOBAR", 1
        )
        assert isinstance(obj, ReactiveJam)

    def test_ScanMode(self, factory: BleDomain):
        """Test creation of ScanMode message
        """
        obj = factory.create_scan_mode(active=True)
        assert isinstance(obj, ScanMode)

    def test_AdvMode(self, factory: BleDomain):
        """Test creation of AdvMode message
        """
        obj = factory.create_adv_mode(adv_data=b"FOOBAR")
        assert isinstance(obj, AdvMode)

    def test_CentralMode(self, factory: BleDomain):
        """Test creation of CentralMode message
        """
        obj = factory.create_central_mode()
        assert isinstance(obj, CentralMode)

    def test_Periph(self, factory: BleDomain):
        """Test creation of PeriphMode message
        """
        obj = factory.create_periph_mode(adv_data=b"FOOBAR")
        assert isinstance(obj, PeriphMode)

    def test_Start(self, factory: BleDomain):
        """Test creation of BleStart message
        """
        obj = factory.create_start()
        print(BleDomain.VERSIONS)
        assert isinstance(obj, BleStart)

    def test_Stop(self, factory: BleDomain):
        """Test creation of BleStop message
        """
        obj = factory.create_stop()
        assert isinstance(obj, BleStop)

    def test_ConnectTo(self, factory: BleDomain):
        """Test creation of ConnectTo message
        """
        obj = factory.create_connect_to(bd_address=BDAddress(
            address="00:11:22:33:44:55",
            random=False
        ))
        assert isinstance(obj, ConnectTo)

    def test_Disconnect(self, factory: BleDomain):
        """Test creation of Disconnect message
        """
        obj = factory.create_disconnect(conn_handle=1)
        assert isinstance(obj, Disconnect)

    def test_Synchronized(self, factory: BleDomain):
        """Test creation of Synchronized message
        """
        obj = factory.create_synchronized(
            0x11223344,
            6,
            21,
            DefaultChannelMap,
            0xaabbcc
        )   
        assert isinstance(obj, Synchronized)

    def test_Connected(self, factory: BleDomain):
        """Test creation of Connected message
        """
        obj = factory.create_connected(
            BDAddress("00:11:22:33:44:55"),
            BDAddress("99:88:77:66:55:44"),
            0x11223344,
            1
        )   
        assert isinstance(obj, Connected)

    def test_Disconnected(self, factory: BleDomain):
        """Test creation of Disconnected message
        """
        obj = factory.create_disconnected(
            13, 1
        )   
        assert isinstance(obj, Disconnected)

    def test_Desynchronized(self, factory: BleDomain):
        """Test creation of Desynchronized message
        """
        obj = factory.create_desynchronized(0x11223344)   
        assert isinstance(obj, Desynchronized)

    def test_SetAdvData(self, factory: BleDomain):
        """Test creation of SetAdvData message
        """
        obj = factory.create_set_adv_data(adv_data=b"FOOBAR", scan_rsp=b"HELLO")  
        assert isinstance(obj, SetAdvData)

    def test_SendRawPdu(self, factory: BleDomain):
        """Test creation of SendBleRawPdu message
        """
        obj = factory.create_send_raw_pdu(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            conn_handle=1
        )
        assert isinstance(obj, SendBleRawPdu)

    def test_SendPdu(self, factory: BleDomain):
        """Test creation of SendBlePdu message
        """
        obj = factory.create_send_pdu(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            1
        )
        assert isinstance(obj, SendBlePdu)

    def test_AdvPduReceived(self, factory: BleDomain):
        """Test creation of BleAdvPduReceived message
        """
        obj = factory.create_adv_pdu_received(
            AdvType.ADV_IND,
            -40, BDAddress("00:11:22:33:44:55"),
            b"FOOBAR"
        )
        assert isinstance(obj, BleAdvPduReceived)

    def test_PduReceived(self, factory: BleDomain):
        """Test creation of BlePduReceived message
        """
        obj = factory.create_pdu_received(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            1
        )
        assert isinstance(obj, BlePduReceived)

    def test_RawPduReceived(self, factory: BleDomain):
        """Test creation of BleRawPduReceived message
        """
        obj = factory.create_raw_pdu_received(
            Direction.SLAVE_TO_MASTER,
            b"HELLOWORLD",
            access_address=0x11223344,
            timestamp=12345,
            crc=0xaabbcc,
            crc_validity=True,
            channel=12
        )
        assert isinstance(obj, BleRawPduReceived)

    def test_Injected(self, factory: BleDomain):
        """Test creation of Injected message
        """
        obj = factory.create_injected(
            0x11223344,
            True,
            2
        )
        assert isinstance(obj, Injected)

    def test_HijackMaster(self, factory: BleDomain):
        """Test creation of HijackMaster message
        """
        obj = factory.create_hijack_master(0x11223344)
        assert isinstance(obj, HijackMaster)

    def test_HijackSlave(self, factory: BleDomain):
        """Test creation of HijackSlave message
        """
        obj = factory.create_hijack_slave(0x11223344)
        assert isinstance(obj, HijackSlave)

    def test_HijackBoth(self, factory: BleDomain):
        """Test creation of HijackBoth message
        """
        obj = factory.create_hijack_both(0x11223344)
        assert isinstance(obj, HijackBoth)

    def test_Hijacked(self, factory: BleDomain):
        """Test creation of Hijacked message
        """
        obj = factory.create_hijacked(0x11223344, True)
        assert isinstance(obj, Hijacked)

    def test_PrepareSeqManual(self, factory: BleDomain):
        """Test creation of PrepareSequenceManual message
        """
        obj = factory.create_prepare_sequence_manual(
            0, Direction.MASTER_TO_SLAVE,
            [
                b"FOOBAR",
                b"HELLOWORLD"
            ]
        )
        assert isinstance(obj, PrepareSequenceManual)

    def test_PrepareSeqConnEvt(self, factory: BleDomain):
        """Test creation of PrepareSequenceConnEvt message
        """
        obj = factory.create_prepare_sequence_conn_evt(
            0, Direction.MASTER_TO_SLAVE, 10,
            [
                b"FOOBAR",
                b"HELLOWORLD"
            ]
        )
        assert isinstance(obj, PrepareSequenceConnEvt)

    def test_PrepareSeqPattern(self, factory: BleDomain):
        """Test creation of PrepareSequenceConnEvt message
        """
        obj = factory.create_prepare_sequence_pattern(
            0, Direction.MASTER_TO_SLAVE,
            b"\xff\x00",
            b"\xff\xff",
            0,
            [
                b"FOOBAR",
                b"HELLOWORLD"
            ]
        )
        assert isinstance(obj, PrepareSequencePattern)

    def test_Triggered(self, factory: BleDomain):
        """Test creation of Triggered message
        """
        obj = factory.create_triggered(1)
        assert isinstance(obj, Triggered)

    def test_Trigger(self, factory: BleDomain):
        """Test creation of Trigger message
        """
        obj = factory.create_trigger(1)
        assert isinstance(obj, Trigger)
        assert obj.sequence_id == 1

    def test_DeleteSequence(self, factory: BleDomain):
        """Test creation of DeleteSequence message
        """
        obj = factory.create_delete_sequence(10)
        assert isinstance(obj, DeleteSequence)
        assert obj.sequence_id == 10

    def test_SetEncryption(self, factory: BleDomain):
        """Test creation of SetEncryption message
        """
        obj: SetEncryption = factory.create_set_encryption(
            15,
            b"LLKEY",
            b"LLIV",
            b"KEY",
            b"RAND",
            b"EDIV",
            True
        )
        assert isinstance(obj, SetEncryption)
        assert obj.conn_handle == 15
        assert obj.ll_key == b"LLKEY"
        assert obj.ll_iv == b"LLIV"
        assert obj.key == b"KEY"
        assert obj.rand == b"RAND"
        assert obj.ediv == b"EDIV"