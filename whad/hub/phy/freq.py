"""WHAD Protocol PHY modulation messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.phy.phy_pb2 import GetSupportedFrequenciesCmd
from ..message import pb_bind, PbFieldBool, PbMessageWrapper
from . import PhyDomain

@pb_bind(PhyDomain, 'get_supported_freq', 1)
class GetSupportedFreqs(PbMessageWrapper):
    """PHY Get supported frequencies message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.phy.get_supported_freq.CopyFrom(GetSupportedFrequenciesCmd())

@pb_bind(PhyDomain, 'set_freq', 1)
class SetFreq(PbMessageWrapper):
    """PHY SetFreq modulation message
    """

    frequency = PbFieldBool('phy.set_freq.frequency')

@pb_bind(PhyDomain, 'supported_freq', 1)
class SupportedFreqRanges(PbMessageWrapper):
    """PHY SupportedFrequencyRanges message
    """

    ranges = PbFieldBool('phy.supported_freq.frequency_ranges')

    def add(self, start: int, end: int):
        """Add a supported frequency range to this message

        :param start: Start frequency of this range
        :type start: int
        :param end: End frequency of this range
        :type end: int
        """
        range = self.ranges.add()
        range.start = start
        range.end = end