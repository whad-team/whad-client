"""WHAD Protocol PHY modulation messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
from whad.protocol.phy.phy_pb2 import SetBPSKModulationCmd
from ..message import pb_bind, PbFieldInt, PbFieldBool, PbMessageWrapper
from . import PhyDomain

@pb_bind(PhyDomain, 'mod_ask', 1)
class SetAskMod(PbMessageWrapper):
    """PHY ASK modulation message
    """

    ook = PbFieldBool('phy.mod_ask.ook')


@pb_bind(PhyDomain, 'mod_fsk', 1)
class SetFskMod(PbMessageWrapper):
    """PHY FSK modulation message
    """

    deviation = PbFieldInt('phy.mod_fsk.deviation')

@pb_bind(PhyDomain, 'mod_gfsk', 1)
class SetGfskMod(PbMessageWrapper):
    """PHY GFSK modulation message
    """

    deviation = PbFieldInt('phy.mod_gfsk.deviation')

@pb_bind(PhyDomain, 'mod_bpsk', 1)
class SetBpskMod(PbMessageWrapper):
    """PHY BPSK modulation message
    """
    
    def __init__(self, message: Message = None):
        super().__init__(message=message)
        self.message.phy.mod_bpsk.CopyFrom(SetBPSKModulationCmd())

@pb_bind(PhyDomain, 'mod_qpsk', 1)
class SetQpskMod(PbMessageWrapper):
    """PHY QPSK modulation message
    """

    offset = PbFieldBool('phy.mod_qpsk.offset_qpsk')

@pb_bind(PhyDomain, 'mod_4fsk', 1)
class Set4FskMod(PbMessageWrapper):
    """PHY 4FSK modulation message
    """

    deviation = PbFieldInt('phy.mod_4fsk.deviation')

@pb_bind(PhyDomain, 'mod_msk', 1)
class SetMskMod(PbMessageWrapper):
    """PHY MSK modulation message
    """

    deviation = PbFieldInt('phy.mod_msk.deviation')

@pb_bind(PhyDomain, 'mod_lora', 1)
class SetLoRaMod(PbMessageWrapper):
    """PHY LoRa modulation message
    """

    bandwidth = PbFieldInt('phy.mod_lora.bandwidth')
    sf = PbFieldInt('phy.mod_lora.spreading_factor')
    cr = PbFieldInt('phy.mod_lora.coding_rate')
    preamble_length = PbFieldInt('phy.mod_lora.preamble_length')
    enable_crc = PbFieldBool('phy.mod_lora.enable_crc')
    explicit_mode = PbFieldBool('phy.mod_lora.explicit_mode')
    invert_iq = PbFieldBool('phy.mod_lora.invert_iq')
