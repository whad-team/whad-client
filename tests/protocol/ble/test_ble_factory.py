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
    SetEncryption, SetPhy, SetTxPowerLevel

from whad.hub.ble import BleCsa, BlePhy, ExtAdvPdu
from whad.hub.ble.bdaddr import BDAddress
from whad.hub.ble.chanmap import DefaultChannelMap, ChannelMap

class TestBleDomainFactory(object):
    """Test BleDomain factory
    """

    @pytest.fixture
    def factory(self):
        """ Create a BleDomain instance with WHAD
        protocol version 1 (and 2)
        """
        return BleDomain(1)

    @pytest.fixture
    def factory_v3(self):
        """ Create a BleDomain class instance with WHAD
        protocol version 3.
        """
        return BleDomain(3)

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

    def test_SetPhy(self, factory_v3: BleDomain):
        """Test creation of SetPhy message."""
        obj = factory_v3.create_set_phy(BlePhy.LE_1M, BlePhy.LE_2M)
        assert isinstance(obj, SetPhy)
        assert obj.tx_phy == BlePhy.LE_1M
        assert obj.rx_phy == BlePhy.LE_2M

    def test_SetTxPowerLevel(self, factory_v3: BleDomain):
        """Test creation of SetTxPowerLevel message."""
        obj = factory_v3.create_set_tx_power_level(4)
        assert isinstance(obj, SetTxPowerLevel)
        assert obj.level == 4

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

    def test_JamConn_v1(self, factory: BleDomain):
        """Test creation of JamAdv message for proto v1, v2
        """
        obj = factory.create_jam_conn(access_address=0x11223344, phy=BlePhy.LE_1M)
        assert isinstance(obj, JamConn)

    def test_JamConn_v3(self, factory_v3: BleDomain):
        """Test creation of JamAdv message for proto v1, v2
        """
        obj = factory_v3.create_jam_conn(access_address=0x11223344, phy=BlePhy.LE_2M)
        assert isinstance(obj, JamConn)

    def test_ReactiveJam(self, factory: BleDomain):
        """Test creation of ReactiveJam message
        """
        obj = factory.create_reactive_jam(
            2, b"FOOBAR", 1
        )
        assert isinstance(obj, ReactiveJam)

    def test_ScanMode_v1(self, factory: BleDomain):
        """Test creation of ScanMode message
        """
        obj = factory.create_scan_mode(active=True)
        assert isinstance(obj, ScanMode)

    def test_ScanMode_v3(self, factory_v3: BleDomain):
        """Test creation of ScanMode message
        """
        obj = factory_v3.create_scan_mode(active=True, use_ext_adv=True)
        assert isinstance(obj, ScanMode)

    def test_AdvMode_v1(self, factory: BleDomain):
        """Test creation of AdvMode message for proto v1
        """
        obj = factory.create_adv_mode(adv_data=b"FOOBAR")
        assert isinstance(obj, AdvMode)

    def test_AdvMode_v3(self, factory_v3: BleDomain):
        """Test creation of AdvMode message for proto v3
        """
        obj = factory_v3.create_adv_mode(adv_data=b"FOOBAR", inter_min=0x40,
                                      inter_max=0x1337, channel_map=ChannelMap([37,38,39]))
        assert isinstance(obj, AdvMode)

    def test_AdvMode_v3_bad_inter_min(self, factory_v3: BleDomain):
        """Test creation of AdvMode message with bad interval minimal value"""
        with pytest.raises(ValueError):
            factory_v3.create_adv_mode(b"FOOBAR", inter_min=0, inter_max=0x4000)

    def test_AdvMode_v3_bad_inter_max(self, factory_v3: BleDomain):
        """Test creation of AdvMode message with bad interval minimal value"""
        with pytest.raises(ValueError):
            factory_v3.create_adv_mode(b"FOOBAR", inter_min=0x20, inter_max=0)

    def test_AdvMode_v3_bad_interval_range(self, factory_v3: BleDomain):
        """Test creation of AdvMode message with bad interval minimal value"""
        with pytest.raises(ValueError):
            factory_v3.create_adv_mode(b"FOOBAR", inter_min=0x1000, inter_max=0x20)

    def test_AdvMode_v3_bad_channel_map(self, factory_v3: BleDomain):
        """Test creation of AdvMode message with bad interval minimal value"""
        with pytest.raises(ValueError):
            factory_v3.create_adv_mode(b"FOOBAR", channel_map=ChannelMap([1,2,3]))

    def test_AdvMode_extended(self, factory_v3: BleDomain):
        """Test creation of ExtAdvMode message for proto v3
        """
        ext_pdus = [
            ExtAdvPdu(0, 3, b'', b'FOOBAR')
        ]
        obj = factory_v3.create_ext_adv_mode(inter_min=0x40, inter_max=0x1337,
                                          channel_map=ChannelMap([37, 38, 39]), pdus=ext_pdus, csa=BleCsa.CSA1)
        assert isinstance(obj, AdvMode)

    def test_ExtAdvMode_ext_pdus(self, factory_v3: BleDomain):
        """Test creation of ExtAdvMode message for proto v3
        """
        ext_pdu = ExtAdvPdu(0, 3, b'', b'FOOBAR')
        obj = factory_v3.create_ext_adv_mode(inter_min=0x40, inter_max=0x1337,
                                          channel_map=ChannelMap([37, 38, 39]), csa=BleCsa.CSA1)
        obj.add_pdu(ext_pdu)
        assert isinstance(obj, AdvMode)
        assert len(list(obj.pdus())) == 1

    def test_ExtAdvMode_bad_csa(self, factory_v3: BleDomain):
        """Test creation of ExtAdvMode message for proto v3 with bad inter max value
        """
        with pytest.raises(ValueError):
            obj = factory_v3.create_ext_adv_mode(inter_min=0x40, inter_max=0,
                                          channel_map=ChannelMap([37, 38, 39]), csa=0xffff)

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
        assert obj.adv_type == AdvType.ADV_IND
        assert obj.channel_map == ChannelMap([37, 38, 39]).value
        assert obj.inter_min == 0x20
        assert obj.inter_max == 0x4000

    def test_Periph_v3(self, factory_v3: BleDomain):
        """Test creation of PeriphMode message
        """
        obj = factory_v3.create_periph_mode(adv_data=b"FOOBAR", inter_min=0x40,
                                            inter_max=0x1337, channel_map=ChannelMap([37,38,39]))
        assert isinstance(obj, PeriphMode)

    def test_Periph_v3_bad_inter_min(self, factory_v3: BleDomain):
        """Test creation of PeriphMode message with bad interval minimal value"""
        with pytest.raises(ValueError):
            factory_v3.create_periph_mode(b"FOOBAR", inter_min=0, inter_max=0x4000)

    def test_Periph_v3_bad_inter_max(self, factory_v3: BleDomain):
        """Test creation of PeriphMode message with bad interval minimal value"""
        with pytest.raises(ValueError):
            factory_v3.create_periph_mode(b"FOOBAR", inter_min=0x20, inter_max=0)

    def test_Periph_v3_bad_interval_range(self, factory_v3: BleDomain):
        """Test creation of PeriphMode message with bad interval minimal value"""
        with pytest.raises(ValueError):
            factory_v3.create_periph_mode(b"FOOBAR", inter_min=0x1000, inter_max=0x20)

    def test_Periph_v3_bad_channel_map(self, factory_v3: BleDomain):
        """Test creation of PeriphMode message with bad interval minimal value"""
        with pytest.raises(ValueError):
            factory_v3.create_periph_mode(b"FOOBAR", channel_map=ChannelMap([1,2,3]))

    def test_Periph_v3_extended(self, factory_v3: BleDomain):
        """Test creation of PeriphMode message with extended PDUs"""
        ext_pdu = ExtAdvPdu(0, 3, b'', b'FOOBAR')
        obj = factory_v3.create_periph_mode(adv_data=b'', inter_min=0x40, inter_max=0x1337, ext_pdus=[ext_pdu])
        assert isinstance(obj, PeriphMode)
        assert obj.adv_type == AdvType.ADV_EXT_IND
        assert len(list(obj.ext_pdus)) == 1

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

    def test_ConnectTo_v3(self, factory_v3: BleDomain):
        """Test creation of ConnectTo message for proto v3
        """
        obj = factory_v3.create_connect_to(bd_address=BDAddress(
            address="00:11:22:33:44:55",
            random=False
        ), csa=BleCsa.CSA2)
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

    def test_SendRawPdu_v1(self, factory: BleDomain):
        """Test creation of SendBleRawPdu message
        """
        obj = factory.create_send_raw_pdu(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            conn_handle=1
        )
        assert isinstance(obj, SendBleRawPdu)

    def test_SendRawPdu_v3(self, factory_v3: BleDomain):
        """Test creation of SendBleRawPdu message
        """
        obj = factory_v3.create_send_raw_pdu(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            conn_handle=1,
            phy=BlePhy.LE_2M
        )
        assert isinstance(obj, SendBleRawPdu)

    def test_SendPdu_v1(self, factory: BleDomain):
        """Test creation of SendBlePdu message
        """
        obj = factory.create_send_pdu(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            1
        )
        assert isinstance(obj, SendBlePdu)

    def test_SendPdu_v3(self, factory_v3: BleDomain):
        """Test creation of SendBlePdu message
        """
        obj = factory_v3.create_send_pdu(
            Direction.MASTER_TO_SLAVE,
            b"HELLOWORLD",
            1,
            phy=BlePhy.LE_2M
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

    def test_RawPduReceived_v1(self, factory: BleDomain):
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

    def test_RawPduReceived_v3(self, factory_v3: BleDomain):
        """Test creation of BleRawPduReceived message
        """
        obj = factory_v3.create_raw_pdu_received(
            Direction.SLAVE_TO_MASTER,
            b"HELLOWORLD",
            access_address=0x11223344,
            timestamp=12345,
            crc=0xaabbcc,
            crc_validity=True,
            channel=12,
            phy=BlePhy.LE_2M
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
