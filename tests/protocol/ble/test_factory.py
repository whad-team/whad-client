"""Protocol hub Discovery messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import JamAdvCmd, CentralModeCmd, StartCmd, StopCmd
from whad.protocol.hub.ble import BleDomain, SetBdAddress, SniffAdv, SniffConnReq, \
    SniffAccessAddress, SniffActiveConn, AccessAddressDiscovered, JamAdv, \
    JamAdvChan,JamConn, ScanMode, AdvMode, CentralMode, PeriphMode, SetAdvData, \
    SendRawPdu, SendPdu, AdvPduReceived,AddressType, \
    PduReceived, RawPduReceived, ConnectTo, Disconnect, Connected, Disconnected, \
    Start, Stop, HijackMaster, HijackSlave, HijackBoth, Hijacked, ReactiveJam, \
    Synchronized, Desynchronized, PrepareSequenceManual, PrepareSequenceConnEvt, \
    PrepareSequencePattern, Injected, Direction, AdvType, Triggered

from whad.ble.bdaddr import BDAddress
from whad.ble.chanmap import DefaultChannelMap

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
        obj = factory.createSetBdAddress(address)
        assert isinstance(obj, SetBdAddress)
        assert obj.bd_address == address.value
        assert obj.addr_type == AddressType.PUBLIC

    def test_SniffAdv(self, factory: BleDomain):
        """Test creation of SniffAdv message
        """
        obj = factory.createSniffAdv(2, BDAddress('00:11:22:33:44:55'))
        assert isinstance(obj, SniffAdv)

    def test_SniffConnReq(self, factory: BleDomain):
        """Test creation of SniffConnReq message
        """
        obj = factory.createSniffConnReq(3, BDAddress('00:11:22:33:44:55'),
                                         show_empty=True, show_adv=True)
        assert isinstance(obj, SniffConnReq)

    def test_SniffAA(self, factory: BleDomain):
        """Test creation of SniffAccessAddress message
        """
        obj = factory.createSniffAccessAddress(channels=[0,1,2,3,4])
        assert isinstance(obj, SniffAccessAddress)

    def test_SniffActiveConn(self, factory: BleDomain):
        """Test creation of SniffActiveConn message
        """
        obj = factory.createSniffActiveConn(
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
        obj = factory.createAccessAddressDiscovered(
            access_address=0x11223344,
            rssi=-40,
            timestamp=1234
        )
        assert isinstance(obj, AccessAddressDiscovered)

    def test_JamAdv(self, factory: BleDomain):
        """Test creation of JamAdv message
        """
        obj = factory.createJamAdv()
        assert isinstance(obj, JamAdv)

    def test_JamAdvChan(self, factory: BleDomain):
        """Test creation of JamAdvChan message
        """
        obj = factory.createJamAdvChan(12)
        assert isinstance(obj, JamAdvChan)

    def test_ReactiveJam(self, factory: BleDomain):
        """Test creation of ReactiveJam message
        """
        obj = factory.createReactiveJam(
            2, b"FOOBAR", 1
        )
        assert isinstance(obj, ReactiveJam)

    def test_ScanMode(self, factory: BleDomain):
        """Test creation of ScanMode message
        """
        obj = factory.createScanMode(active=True)
        assert isinstance(obj, ScanMode)

    def test_AdvMode(self, factory: BleDomain):
        """Test creation of AdvMode message
        """
        obj = factory.createAdvMode(adv_data=b"FOOBAR")
        assert isinstance(obj, AdvMode)

    def test_CentralMode(self, factory: BleDomain):
        """Test creation of CentralMode message
        """
        obj = factory.createCentralMode()
        assert isinstance(obj, CentralMode)

    def test_Periph(self, factory: BleDomain):
        """Test creation of PeriphMode message
        """
        obj = factory.createPeriphMode(adv_data=b"FOOBAR")
        assert isinstance(obj, PeriphMode)

    def test_Start(self, factory: BleDomain):
        """Test creation of Start message
        """
        obj = factory.createStart()
        assert isinstance(obj, Start)

    def test_Stop(self, factory: BleDomain):
        """Test creation of Stop message
        """
        obj = factory.createStop()
        assert isinstance(obj, Stop)

    def test_ConnectTo(self, factory: BleDomain):
        """Test creation of ConnectTo message
        """
        obj = factory.createConnectTo(bd_address=BDAddress(
            address="00:11:22:33:44:55",
            random=False
        ))
        assert isinstance(obj, ConnectTo)

    def test_Disconnect(self, factory: BleDomain):
        """Test creation of Disconnect message
        """
        obj = factory.createDisconnect(conn_handle=1)
        assert isinstance(obj, Disconnect)

    def test_Synchronized(self, factory: BleDomain):
        """Test creation of Synchronized message
        """
        obj = factory.createSynchronized(
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
        obj = factory.createConnected(
            BDAddress("00:11:22:33:44:55"),
            BDAddress("99:88:77:66:55:44"),
            0x11223344,
            1
        )   
        assert isinstance(obj, Connected)

    def test_Disconnected(self, factory: BleDomain):
        """Test creation of Disconnected message
        """
        obj = factory.createDisconnected(
            13, 1
        )   
        assert isinstance(obj, Disconnected)

    def test_Desynchronized(self, factory: BleDomain):
        """Test creation of Desynchronized message
        """
        obj = factory.createDesynchronized(0x11223344)   
        assert isinstance(obj, Desynchronized)

    def test_SetAdvData(self, factory: BleDomain):
        """Test creation of SetAdvData message
        """
        obj = factory.createSetAdvData(adv_data=b"FOOBAR", scan_rsp=b"HELLO")  
        assert isinstance(obj, SetAdvData)

    def test_SendRawPdu(self, factory: BleDomain):
        """Test creation of SendRawPdu message
        """
        obj = factory.createSendRawPdu(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            conn_handle=1
        )
        assert isinstance(obj, SendRawPdu)

    def test_SendPdu(self, factory: BleDomain):
        """Test creation of SendPdu message
        """
        obj = factory.createSendPdu(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            1
        )
        assert isinstance(obj, SendPdu)

    def test_AdvPduReceived(self, factory: BleDomain):
        """Test creation of AdvPduReceived message
        """
        obj = factory.createAdvPduReceived(
            AdvType.ADV_IND,
            -40, BDAddress("00:11:22:33:44:55"),
            b"FOOBAR"
        )
        assert isinstance(obj, AdvPduReceived)

    def test_PduReceived(self, factory: BleDomain):
        """Test creation of PduReceived message
        """
        obj = factory.createPduReceived(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            1
        )
        assert isinstance(obj, PduReceived)

    def test_RawPduReceived(self, factory: BleDomain):
        """Test creation of RawPduReceived message
        """
        obj = factory.createRawPduReceived(
            Direction.SLAVE_TO_MASTER,
            b"HELLOWORLD",
            access_address=0x11223344,
            timestamp=12345,
            crc=0xaabbcc,
            crc_validity=True,
            channel=12
        )
        assert isinstance(obj, RawPduReceived)

    def test_Injected(self, factory: BleDomain):
        """Test creation of Injected message
        """
        obj = factory.createInjected(
            0x11223344,
            True,
            2
        )
        assert isinstance(obj, Injected)

    def test_HijackMaster(self, factory: BleDomain):
        """Test creation of HijackMaster message
        """
        obj = factory.createHijackMaster(0x11223344)
        assert isinstance(obj, HijackMaster)

    def test_HijackSlave(self, factory: BleDomain):
        """Test creation of HijackSlave message
        """
        obj = factory.createHijackSlave(0x11223344)
        assert isinstance(obj, HijackSlave)

    def test_HijackBoth(self, factory: BleDomain):
        """Test creation of HijackBoth message
        """
        obj = factory.createHijackBoth(0x11223344)
        assert isinstance(obj, HijackBoth)

    def test_Hijacked(self, factory: BleDomain):
        """Test creation of Hijacked message
        """
        obj = factory.createHijacked(0x11223344, True)
        assert isinstance(obj, Hijacked)

    def test_PrepareSeqManual(self, factory: BleDomain):
        """Test creation of PrepareSequenceManual message
        """
        obj = factory.createPrepareSequenceManual(
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
        obj = factory.createPrepareSequenceConnEvt(
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
        obj = factory.createPrepareSequencePattern(
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
        obj = factory.createTriggered(1)
        assert isinstance(obj, Triggered)