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
    PrepareSequencePattern, Injected

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
