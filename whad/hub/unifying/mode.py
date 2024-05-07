"""WHAD Protocol ESB mode messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.unifying.unifying_pb2 import StartCmd, StopCmd, SniffPairingCmd
from ..message import pb_bind, PbFieldBytes, PbFieldBool, PbFieldInt, PbMessageWrapper
from . import UnifyingDomain

@pb_bind(UnifyingDomain, 'sniff', 1)
class SniffMode(PbMessageWrapper):
    """Logitech Unifying SniffMode message
    """

    channel = PbFieldInt('unifying.sniff.channel')
    address = PbFieldBytes('unifying.sniff.address')
    show_acks = PbFieldBool('unifying.sniff.show_acknowledgements')

@pb_bind(UnifyingDomain, 'jam', 1)
class JamMode(PbMessageWrapper):
    """Logitech Unifying JamMode message
    """

    channel = PbFieldInt('unifying.jam.channel')

@pb_bind(UnifyingDomain, 'jammed', 1)
class Jammed(PbMessageWrapper):
    """Logitech Unifying Jammed notification message
    """

    timestamp = PbFieldInt('unifying.jammed.timestamp')

@pb_bind(UnifyingDomain, 'start', 1)
class UnifyingStart(PbMessageWrapper):
    """Logitech Unifying UnifyingStart message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.unifying.start.CopyFrom(StartCmd())

@pb_bind(UnifyingDomain, 'stop', 1)
class UnifyingStop(PbMessageWrapper):
    """Logitech Unifying UnifyingStop message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.unifying.stop.CopyFrom(StopCmd())

@pb_bind(UnifyingDomain, 'dongle', 1)
class DongleMode(PbMessageWrapper):
    """Logitech Unifying DongleMode message
    """

    channel = PbFieldInt('unifying.dongle.channel')

@pb_bind(UnifyingDomain, 'keyboard', 1)
class KeyboardMode(PbMessageWrapper):
    """Logitech Unifying KeyboardMode message
    """

    channel = PbFieldInt('unifying.keyboard.channel')

@pb_bind(UnifyingDomain, 'mouse', 1)
class MouseMode(PbMessageWrapper):
    """Logitech Unifying MouseMode message
    """

    channel = PbFieldInt('unifying.mouse.channel')

@pb_bind(UnifyingDomain, 'sniff_pairing', 1)
class SniffPairing(PbMessageWrapper):
    """Logitech Unifying SniffPairing message
    """

    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.unifying.sniff_pairing.CopyFrom(SniffPairingCmd())
