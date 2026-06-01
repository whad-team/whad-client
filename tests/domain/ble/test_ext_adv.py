import pytest
from whad.scapy.layers.bluetooth import BTLE_ADV, BTLE_EXT_ADV, AdvDataInfo, bind_layers

bind_layers(BTLE_ADV, BTLE_EXT_ADV, PDU_Type=0x07)

AUX_ADV_IND_PDU = bytes([
    0x07, 0x10, 0x4a, 0x49, 0xae, 0xad, 0xac,
    0xab, 0xaa, 0xa9, 0xbc, 0xea, 0xd6, 0x05,
    0x07, 0x09, 0x0b, 0x0d
])

def test_aux_adv_ind_parsing():
    pkt = BTLE_ADV(AUX_ADV_IND_PDU)
    assert isinstance(pkt, BTLE_ADV)
    assert pkt.haslayer(BTLE_EXT_ADV)
    ext = pkt[BTLE_EXT_ADV]
    assert ext.header_len == 10
    assert ext.adv_mode == 1
    assert ext.AdvA == "a9:aa:ab:ac:ad:ae"
    assert ext.txpower == 0xd6
    assert ext.acad == b''
    assert ext.adi == AdvDataInfo(did=0xabc,sid=0xe)
    assert bytes(ext.payload) == b'\x05\x07\x09\x0b\x0d'

def test_aux_adv_crafting():
    """Craft an extended advertising PDU."""
    pkt = BTLE_EXT_ADV(adv_mode=1)
    pkt.txpower = 0x42
    pkt.adi = AdvDataInfo(did=0xabc, sid=0xe)

    # Force serialization and update of field flags
    _ = bytes(pkt)
    # Check flag field has been correctly computed
    assert pkt.flags =="txpower+adi"
    # Check header_len has been correctly computed
    assert pkt.header_len == 4
