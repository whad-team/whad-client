"""Test YardStickOne radio configuration structure interface class.
"""
import pytest

from whad.hw.yard.constants import YardRadioStructure

@pytest.fixture
def rcs():
    """Create a fake Radio Configuration Structure object.
    """
    # First, we create a fake configuration structure in memory
    memory = bytearray(YardRadioStructure.MEMORY_SIZE)
    base_addr = YardRadioStructure.BASE_ADDRESS
    offset_max = YardRadioStructure.BASE_ADDRESS + YardRadioStructure.MEMORY_SIZE

    def yard_rcs_poke(offset: int, value: bytes):
        """Write into our fake memory at specific offset
        """
        assert offset >= YardRadioStructure.BASE_ADDRESS
        assert offset < offset_max
        memory[offset - base_addr] = value[0]

    def yard_rcs_peek(offset: int, length: bytes) -> bytes:
        """Read bytes from our fake memory at specific offset.
        """
        assert offset >= YardRadioStructure.BASE_ADDRESS
        assert length > 0
        assert offset + length <= offset_max
        return memory[offset-base_addr:offset-base_addr+length]

    # Then we initialize our radio config structure object
    return YardRadioStructure(yard_rcs_poke, yard_rcs_peek)


def test_yard_rcs_set_get_field(rcs):
    """try to set a field in Yard Radio configuration structure
    """
    # Set a field in configuration memory
    rcs.set("CHIPID", 0x42)

    # Read it back
    assert rcs.get("CHIPID") == 0x42

def test_yard_rcs_get_unknown_field(rcs):
    """Try to access an unknown field
    """
    with pytest.raises(ValueError):
        rcs.get("#NON-EXISTING#")
