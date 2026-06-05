"""WHAD Protocol Dot15d4 TSCH-related messages abstraction layer.
"""
from whad.protocol.whad_pb2 import Message
#from whad.protocol.dot15d4.dot15d4_pb2 import StartCmd, StopCmd
#from whad.hub.events import JammedEvt
from ..message import pb_bind, PbFieldInt, PbFieldBool, PbMessageWrapper
from . import Dot15d4Domain


@pb_bind(Dot15d4Domain, 'config_tsch', 3)
class ConfigureTSCH(PbMessageWrapper):
    """Dot15d4 configure TSCH mode
    """
    enabled = PbFieldBool('dot15d4.config_tsch.enabled')


@pb_bind(Dot15d4Domain, 'add_link', 3)
class AddLink(PbMessageWrapper):
    """Dot15d4 Link addition in TSCH mode
    """
    superframe_id = PbFieldInt('dot15d4.add_link.superframe_id')
    src = PbFieldInt('dot15d4.add_link.src')
    time_slot = PbFieldInt('dot15d4.add_link.time_slot')
    channel_offset = PbFieldInt('dot15d4.add_link.channel_offset')
    neighbor = PbFieldInt('dot15d4.add_link.neighbor')
    options = PbFieldInt('dot15d4.add_link.options')
    link_type = PbFieldInt('dot15d4.add_link.type')

@pb_bind(Dot15d4Domain, 'delete_link', 3)
class DeleteLink(PbMessageWrapper):
    """Dot15d4 Link deletion in TSCH mode
    """
    superframe_id = PbFieldInt('dot15d4.del_link.superframe_id')
    time_slot = PbFieldInt('dot15d4.del_link.time_slot')
    channel_offset = PbFieldInt('dot15d4.del_link.channel_offset')
    

@pb_bind(Dot15d4Domain, 'update_superframe', 3)
class UpdateSuperframe(PbMessageWrapper):
    """Dot15d4 Superframe addition or update in TSCH mode
    """
    superframe_id = PbFieldInt('dot15d4.update_superframe.superframe_id')
    number_of_slots = PbFieldInt('dot15d4.update_superframe.number_of_slots')
    flags = PbFieldInt('dot15d4.update_superframe.flags')
    asn = PbFieldInt('dot15d4.update_superframe.asn')
    

@pb_bind(Dot15d4Domain, 'delete_superframe', 3)
class DeleteSuperframe(PbMessageWrapper):
    """Dot15d4 Superframe deletion in TSCH mode
    """
    superframe_id = PbFieldInt('dot15d4.del_superframe.superframe_id')


@pb_bind(Dot15d4Domain, 'set_chm', 3)
class SetChannelMap(PbMessageWrapper):
    """Dot15d4 channel map selection in TSCH mode
    """
    channel_map = PbFieldInt('dot15d4.set_chm.channel_map')