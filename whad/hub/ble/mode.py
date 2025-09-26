"""WHAD Protocol BLE mode messages abstraction layer.
"""
from typing import Optional, Tuple

from whad.protocol.whad_pb2 import Message
from whad.protocol.ble.ble_pb2 import CentralModeCmd, StartCmd as BleStartCmd, StopCmd as BleStopCmd
from whad.hub.message import pb_bind, PbFieldBytes, PbMessageWrapper, PbFieldBool, PbFieldInt, PbFieldArray
from whad.hub.ble import BleDomain, BleAdvType, ChannelMap, BleCsa, AuxPtr, ExtAdvPdu

@pb_bind(BleDomain, 'scan_mode', 1)
class ScanMode(PbMessageWrapper):
    """BLE scan mode message class
    """
    active = PbFieldBool('ble.scan_mode.active_scan')

    # Introduced in v3, not available in versions 1 & 2.
    use_ext_adv = PbFieldBool('ble.scan_mode.use_ext_adv', min_version=3, default=False)

@pb_bind(BleDomain, 'adv_mode', 1)
class AdvMode(PbMessageWrapper):
    """BLE advertising mode message class
    """
    adv_data = PbFieldBytes('ble.adv_mode.adv_data')
    scanrsp_data = PbFieldBytes('ble.adv_mode.scanrsp_data')

    # Protocol version 2 use 0x20 for both min and max values, we reflect this here.
    adv_type = PbFieldInt('ble.adv_mode.adv_type', min_version=3, default=BleAdvType.ADV_IND)
    channel_map = PbFieldBytes('ble.adv_mode.channel_map', min_version=3, default=ChannelMap([37, 38, 39]).value)
    inter_min = PbFieldInt('ble.adv_mode.inter_min', min_version=3, default=0x20)
    inter_max = PbFieldInt('ble.adv_mode.inter_max', min_version=3, default=0x4000)
    csa = PbFieldInt('ble.adv_mode.csa', min_version=3, default=BleCsa.CSA1)
    ext_pdus = PbFieldArray('ble.adv_mode.ext_pdus', min_version=3, default=[])

    def add_pdu(self, pdu: ExtAdvPdu):
        """Add an extended PDU to advertise on secondary channels."""
        ext_pdu = self.message.ble.adv_mode.ext_pdus.add()
        ext_pdu.adv_data = pdu.adv_data
        if pdu.auxptr is not None:
            ext_pdu.aux_ptr.channel = pdu.auxptr.channel
            ext_pdu.aux_ptr.ca = pdu.auxptr.ca
            ext_pdu.aux_ptr.offset_units = pdu.auxptr.units
            ext_pdu.aux_ptr.offset = pdu.auxptr.offset
            ext_pdu.aux_ptr.phy = pdu.auxptr.phy

    def get_pdu(self, index: int) -> Optional[ExtAdvPdu]:
        if index >= 0 and index < len(self.ext_pdus):
            pdu = self.ext_pdus[index]
            if pdu.aux_ptr is not None:
                return ExtAdvPdu(
                    pdu.adv_data,
                    AuxPtr(
                        pdu.aux_ptr.channel,
                        pdu.aux_ptr.ca,
                        pdu.aux_ptr.offset_units,
                        pdu.aux_ptr.offset,
                        pdu.aux_ptr.phy
                    )
                )
            else:
                return ExtAdvPdu(pdu.adv_data)
        return None

    def pdus(self):
        for pdu in self.ext_pdus:
            if pdu.aux_ptr is not None:
                yield ExtAdvPdu(
                    pdu.adv_data,
                    AuxPtr(
                        pdu.aux_ptr.channel,
                        pdu.aux_ptr.ca,
                        pdu.aux_ptr.offset_units,
                        pdu.aux_ptr.offset,
                        pdu.aux_ptr.phy
                    )
                )
            else:
                yield ExtAdvPdu(pdu.adv_data)

@pb_bind(BleDomain, 'central_mode', 1)
class CentralMode(PbMessageWrapper):
    """BLE advertising mode message class
    """

    def __init__(self, version: int, message: Message = None):
        super().__init__(version, message=message)
        self.message.ble.central_mode.CopyFrom(CentralModeCmd())

@pb_bind(BleDomain, 'periph_mode', 1)
class PeriphMode(PbMessageWrapper):
    """BLE advertising mode message class
    """
    adv_data = PbFieldBytes('ble.periph_mode.adv_data')
    scanrsp_data = PbFieldBytes('ble.periph_mode.scanrsp_data')

    # Default fields required by inherited classes (versions greater than 1)
    adv_type = PbFieldInt('ble.periph_mode.adv_type', min_version=3, default=BleAdvType.ADV_IND)
    channel_map = PbFieldBytes('ble.periph_mode.channel_map', min_version=3, default=ChannelMap([37,38,39]).value)
    inter_min = PbFieldInt('ble.periph_mode.inter_min', min_version=3, default=0x20)
    inter_max = PbFieldInt('ble.periph_mode.inter_max', min_version=3, default=0x4000)
    ext_pdus = PbFieldArray('ble.periph_mode.ext_pdus', min_version=3, default=[])

    def add_pdu(self, pdu: ExtAdvPdu):
        """Add an extended PDU to advertise on secondary channels."""
        ext_pdu = self.message.ble.periph_mode.ext_pdus.add()
        ext_pdu.adv_data = pdu.adv_data

        if pdu.auxptr is not None:
            ext_pdu.aux_ptr.channel = pdu.auxptr.channel
            ext_pdu.aux_ptr.ca = pdu.auxptr.ca
            ext_pdu.aux_ptr.offset_units = pdu.auxptr.units
            ext_pdu.aux_ptr.offset = pdu.auxptr.offset
            ext_pdu.aux_ptr.phy = pdu.auxptr.phy

    def get_pdu(self, index: int):
        if index >= 0 and index < len(self.ext_pdus):
            if pdu.aux_ptr is not None:
                return ExtAdvPdu(
                    pdu.adv_data,
                    AuxPtr(
                        pdu.aux_ptr.channel,
                        pdu.aux_ptr.ca,
                        pdu.aux_ptr.offset_units,
                        pdu.aux_ptr.offset,
                        pdu.aux_ptr.phy
                    )
                )
            else:
                return ExtAdvPdu(pdu.adv_data)
        return None

    def pdus(self):
        for pdu in self.ext_pdus:
            if pdu.aux_ptr is not None:
                yield ExtAdvPdu(
                    pdu.adv_data,
                    AuxPtr(
                        pdu.aux_ptr.channel,
                        pdu.aux_ptr.ca,
                        pdu.aux_ptr.offset_units,
                        pdu.aux_ptr.offset,
                        pdu.aux_ptr.phy
                    )
                )
            else:
                yield ExtAdvPdu(pdu.adv_data)

    def get_adv_data(self) -> Optional[bytes]:
        """Retrieve advertising data."""
        return self.get_field_value(PeriphMode.adv_data)

    def get_scan_data(self) -> Optional[bytes]:
        """Retrieve scan response data, if set."""
        return self.get_field_value(PeriphModeV3.scanrsp_data)

    def get_adv_type(self) -> Optional[int]:
        """Retrieve the advertisement type."""
        return self.get_field_value(PeriphModeV3.adv_type)

    def get_channel_map(self) -> Optional[ChannelMap]:
        """Retrieve channel map."""
        # Read value from message
        value = self.get_field_value(PeriphModeV3.channel_map)
        if value is not None and isinstance(value, bytes):
            return ChannelMap.from_bytes(value)
        return None

    def get_interval(self) -> Optional[Tuple[int, int]]:
        """Retrieve advertising interval min/max values."""
        inter_min = self.get_field_value(PeriphModeV3.inter_min)
        inter_max = self.get_field_value(PeriphModeV3.inter_max)
        if inter_min is not None and inter_max is not None:
            if inter_min in range(0x20, 0x4001) and inter_max in range(0x20, 0x4001):
                return (inter_min, inter_max)
        return None

@pb_bind(BleDomain, 'start', 1)
class BleStart(PbMessageWrapper):
    """BLE start mode message class
    """

    def __init__(self, version: int, message: Message = None):
        super().__init__(version, message=message)
        self.message.ble.start.CopyFrom(BleStartCmd())

@pb_bind(BleDomain, 'stop', 1)
class BleStop(PbMessageWrapper):
    """BLE stop mode message class
    """

    def __init__(self, version: int, message: Message = None):
        super().__init__(version, message=message)
        self.message.ble.stop.CopyFrom(BleStopCmd())

@pb_bind(BleDomain, 'encryption', 1)
class SetEncryption(PbMessageWrapper):
    """BLE SetEncryption message class
    """
    conn_handle = PbFieldInt('ble.encryption.conn_handle')
    enabled = PbFieldBool('ble.encryption.enabled')
    ll_key = PbFieldBytes('ble.encryption.ll_key')
    ll_iv = PbFieldBytes('ble.encryption.ll_iv')
    key = PbFieldBytes('ble.encryption.key')
    rand = PbFieldBytes('ble.encryption.rand')
    ediv = PbFieldBytes('ble.encryption.ediv')

@pb_bind(BleDomain, 'set_phy', 3)
class SetPhy(PbMessageWrapper):
    """SetPhy message wrapper, introduced in version 3."""
    tx_phy = PbFieldInt('ble.set_phy.tx_phy')
    rx_phy = PbFieldInt('ble.set_phy.rx_phy')

@pb_bind(BleDomain, 'set_supp_phys', 3)
class SetSupportedPhys(PbMessageWrapper):
    """SetSupportedPhys wrapper, introduced in version 3."""
    tx_phy = PbFieldArray('ble.set_supp_phys.tx_phy')
    rx_phy = PbFieldArray('ble.set_supp_phys.rx_phy')

    def add_tx_phy(self, phy: int):
        """Add a TX PHY to our list of TX PHYs."""
        self.message.ble.set_supp_phys.tx_phy.append(phy)

    def add_rx_phy(self, phy: int):
        """Add a RX PHY to our list of RX PHYs."""
        self.message.ble.set_supp_phys.rx_phy.append(phy)

@pb_bind(BleDomain, 'set_tx_pwr', 3)
class SetTxPowerLevel(PbMessageWrapper):
    """Set BLE TX power."""
    level = PbFieldInt('ble.set_tx_pwr.level')
