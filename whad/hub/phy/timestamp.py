"""WHAD Protocol PHY timestamp message abstraction layer.
"""
from ..message import PbFieldInt, PbMessageWrapper

class Timestamp(PbMessageWrapper):
    """PHY timestamp message
    """
    sec = PbFieldInt('sec')
    usec = PbFieldInt('usec')