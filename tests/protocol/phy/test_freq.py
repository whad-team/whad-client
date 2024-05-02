"""Protocol hub PHY frequency-related messages unit tests
"""
import pytest

from whad.protocol.whad_pb2 import Message
from whad.protocol.phy.phy_pb2 import SupportedFrequencyRanges, GetSupportedFrequenciesCmd
from whad.hub.phy import PhyDomain, GetSupportedFreqs, SetFreq, SupportedFreqRanges


@pytest.fixture
def get_supp_freqs():
    msg = Message()
    msg.phy.get_supported_freq.CopyFrom(GetSupportedFrequenciesCmd())
    return msg

@pytest.fixture
def set_freq():
    msg = Message()
    msg.phy.set_freq.frequency = 125000
    return msg

@pytest.fixture
def supp_freq_ranges():
    msg = Message()
    range_ = msg.phy.supported_freq.frequency_ranges.add()
    range_.start = 125000
    range_.end = 250000
    return msg

class TestFreqMessages(object):
    """Test parsing frequency-related messages.
    """

    def test_get_supp_freqs(self, get_supp_freqs):
        """Check GetSupportedFrequenciesCmd parsing.
        """
        parsed_obj = GetSupportedFreqs.parse(1, get_supp_freqs)
        assert isinstance(parsed_obj, GetSupportedFreqs)

    def test_set_freq(self, set_freq):
        """Check SetFrequencyCmd parsing.
        """
        parsed_obj = SetFreq.parse(1, set_freq)
        assert isinstance(parsed_obj, SetFreq)
        assert parsed_obj.frequency == 125000

    def test_supp_freq_ranges(self, supp_freq_ranges):
        """Check SetFrequencyCmd parsing.
        """
        parsed_obj = SupportedFreqRanges.parse(1, supp_freq_ranges)
        assert isinstance(parsed_obj, SupportedFreqRanges)
        assert len(parsed_obj.ranges) == 1