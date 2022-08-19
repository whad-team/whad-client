import pytest
from whad.ble.profile.advdata import AdvDataFieldList, \
    AdvManufacturerSpecificData, AdvFlagsField, AdvCompleteLocalName, \
    AdvDataFieldListOverflow, AdvShortenedLocalName, AdvTxPowerLevel

#######################################
# Test advertising data serialization
#######################################

@pytest.mark.parametrize("test_input, expected", [
(AdvCompleteLocalName(b'TestName'), b'\x09\x09TestName'),
(AdvShortenedLocalName(b'TestName'), b'\x09\x08TestName'),
(AdvTxPowerLevel(1), b'\x02\x0A\x01'),
(AdvManufacturerSpecificData(0x1234, b'TestData'), b'\x0b\xff\x34\x12TestData'),
(AdvFlagsField(), b'\x02\x01\x06'),
(AdvFlagsField(limited_disc=True), b'\x02\x01\x07'),
(AdvFlagsField(
    limited_disc=False,
    general_disc=False,
    bredr_support=False,
    le_bredr_support=False
), b'\x02\x01\x00')
])
def test_adv_serialization(test_input, expected):
    """Test advertising data record serialization.
    """
    assert test_input.to_bytes() == expected

def test_adv_overflow():
    """Test if advertising data building raises an AdvDataFieldListOverflow
    if serialized records are bigger than 31 bytes.
    """
    with pytest.raises(AdvDataFieldListOverflow):
        ad_list = AdvDataFieldList()
        ad_list.add(AdvFlagsField())
        ad_list.add(AdvManufacturerSpecificData(0x1234, b'A'*30))
        ad_records = ad_list.to_bytes()