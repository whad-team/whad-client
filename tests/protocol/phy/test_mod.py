"""Protocol hub PHY modulation messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.phy.phy_pb2 import SetBPSKModulationCmd, LoRaSpreadingFactor, LoRaCodingRate
from whad.hub.phy import PhyDomain, SetAskMod, SetBpskMod, SetFskMod, SetGfskMod, SetLoRaMod, \
    SetMskMod, SetQpskMod, Set4FskMod


@pytest.fixture
def set_ask_mod():
    """Create a SetAskModulationCmd protobuf message
    """
    msg = Message()
    msg.phy.mod_ask.ook = False
    return msg

@pytest.fixture
def set_fsk_mod():
    """Create a SetFskModulationCmd protobuf message
    """
    msg = Message()
    msg.phy.mod_fsk.deviation = 250000
    return msg

@pytest.fixture
def set_gfsk_mod():
    """Create a SetGfskModulationCmd protobuf message
    """
    msg = Message()
    msg.phy.mod_gfsk.deviation = 250000
    return msg

@pytest.fixture
def set_bpsk_mod():
    """Create a SetGfskModulationCmd protobuf message
    """
    msg = Message()
    msg.phy.mod_bpsk.CopyFrom(SetBPSKModulationCmd())
    return msg

@pytest.fixture
def set_qpsk_mod():
    """Create a SetQpskModulationCmd protobuf message
    """
    msg = Message()
    msg.phy.mod_qpsk.offset_qpsk = False
    return msg

@pytest.fixture
def set_4fsk_mod():
    """Create a Set4FskModulationCmd protobuf message
    """
    msg = Message()
    msg.phy.mod_4fsk.deviation = 250000
    return msg

@pytest.fixture
def set_msk_mod():
    """Create a SetMskModulationCmd protobuf message
    """
    msg = Message()
    msg.phy.mod_msk.deviation = 250000
    return msg

@pytest.fixture
def set_lora_mod():
    """Create a SetLoraModulationCmd protobuf message
    """
    msg = Message()
    msg.phy.mod_lora.bandwidth = 250000
    msg.phy.mod_lora.spreading_factor = LoRaSpreadingFactor.SF7
    msg.phy.mod_lora.coding_rate = LoRaCodingRate.CR48
    msg.phy.mod_lora.preamble_length = 8
    msg.phy.mod_lora.enable_crc = True
    msg.phy.mod_lora.explicit_mode = True
    msg.phy.mod_lora.invert_iq = False
    return msg


class TestModulations(object):
    """Test modulation-related messages.
    """

    def test_ask_parsing(self, set_ask_mod):
        """Check parsing of SetAskMod protobuf message.
        """
        parsed_obj = SetAskMod.parse(1, set_ask_mod)
        assert isinstance(parsed_obj, SetAskMod)
        assert parsed_obj.ook == False

    def test_fsk_parsing(self, set_fsk_mod):
        """Check parsing of SetFskMod protobuf message.
        """
        parsed_obj = SetFskMod.parse(1, set_fsk_mod)
        assert isinstance(parsed_obj, SetFskMod)
        assert parsed_obj.deviation == 250000

    def test_gfsk_parsing(self, set_gfsk_mod):
        """Check parsing of SetGfskMod protobuf message.
        """
        parsed_obj = SetGfskMod.parse(1, set_gfsk_mod)
        assert isinstance(parsed_obj, SetGfskMod)
        assert parsed_obj.deviation == 250000

    def test_bpsk_parsing(self, set_bpsk_mod):
        """Check parsing of SetBpskMod protobuf message.
        """
        parsed_obj = SetBpskMod.parse(1, set_bpsk_mod)
        assert isinstance(parsed_obj, SetBpskMod)

    def test_qpsk_parsing(self, set_qpsk_mod):
        """Check parsing of SetGfskMod protobuf message.
        """
        parsed_obj = SetQpskMod.parse(1, set_qpsk_mod)
        assert isinstance(parsed_obj, SetQpskMod)
        assert parsed_obj.offset == False

    def test_4fsk_parsing(self, set_4fsk_mod):
        """Check parsing of Set4FskMod protobuf message.
        """
        parsed_obj = Set4FskMod.parse(1, set_4fsk_mod)
        assert isinstance(parsed_obj, Set4FskMod)
        assert parsed_obj.deviation == 250000

    def test_msk_parsing(self, set_msk_mod):
        """Check parsing of SetMskMod protobuf message.
        """
        parsed_obj = SetMskMod.parse(1, set_msk_mod)
        assert isinstance(parsed_obj, SetMskMod)
        assert parsed_obj.deviation == 250000

    def test_lora_parsing(self, set_lora_mod):
        """Check parsing of SetLoraMod protobuf message.
        """
        parsed_obj = SetLoRaMod.parse(1, set_lora_mod)
        assert isinstance(parsed_obj, SetLoRaMod)
        assert parsed_obj.bandwidth == 250000
        assert parsed_obj.sf == LoRaSpreadingFactor.SF7
        assert parsed_obj.cr == LoRaCodingRate.CR48
        assert parsed_obj.enable_crc == True
        assert parsed_obj.explicit_mode == True
        assert parsed_obj.invert_iq == False
        assert parsed_obj.preamble_length == 8
