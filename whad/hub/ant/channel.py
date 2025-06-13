from whad.protocol.whad_pb2 import Message
from ..message import pb_bind, PbFieldInt, PbFieldBytes, PbFieldBool, PbMessageWrapper
from . import AntDomain


@pb_bind(AntDomain, 'set_device_number', 3)
class SetDeviceNumber(PbMessageWrapper):
    """ANT Set Device Number channel configuration message
    """
    channel_number = PbFieldInt('ant.set_device_number.channel_number')
    device_number = PbFieldInt('ant.set_device_number.device_number')
    


@pb_bind(AntDomain, 'set_device_type', 3)
class SetDeviceType(PbMessageWrapper):
    """ANT Set Device Type channel configuration message
    """
    channel_number = PbFieldInt('ant.set_device_number.channel_number')
    device_type = PbFieldInt('ant.set_device_number.device_type')
    


@pb_bind(AntDomain, 'set_transmission_type', 3)
class SetTransmissionType(PbMessageWrapper):
    """ANT Set Transmission Type channel configuration message
    """
    channel_number = PbFieldInt('ant.set_transmission_type.channel_number')
    transmission_type = PbFieldInt('ant.set_transmission_type.transmission_type')
    

@pb_bind(AntDomain, 'set_channel_period', 3)
class SetChannelPeriod(PbMessageWrapper):
    """ANT Set Channel Period channel configuration message
    """
    channel_number = PbFieldInt('ant.set_channel_period.channel_number')
    channel_period = PbFieldInt('ant.set_channel_period.channel_period')
    



@pb_bind(AntDomain, 'set_network_key', 3)
class SetNetworkKey(PbMessageWrapper):
    """ANT Set Network Key network configuration message
    """
    network_number = PbFieldInt('ant.set_network_key.network_number')
    network_key = PbFieldBytes('ant.set_network_key.network_key')
    


@pb_bind(AntDomain, 'assign_channel', 3)
class AssignChannel(PbMessageWrapper):
    """ANT Assign Channel channel configuration message
    """
    channel_number = PbFieldInt('ant.assign_channel.channel_number')
    network_number = PbFieldInt('ant.assign_channel.network_number')
    channel_type = PbFieldInt('ant.assign_channel.channel_type')
    background_scanning = PbFieldBool('ant.assign_channel.background_scanning', optional=True)
    frequency_agility = PbFieldBool('ant.assign_channel.frequency_agility', optional=True)
    fast_channel_initiation = PbFieldBool('ant.assign_channel.fast_channel_initiation', optional=True)
    asynchronous_transmission = PbFieldBool('ant.assign_channel.asynchronous_transmission', optional=True)


@pb_bind(AntDomain, 'unassign_channel', 3)
class UnassignChannel(PbMessageWrapper):
    """ANT Unassign Channel channel configuration message
    """
    channel_number = PbFieldInt('ant.unassign_channel.channel_number')



@pb_bind(AntDomain, 'open_channel', 3)
class OpenChannel(PbMessageWrapper):
    """ANT Open Channel channel configuration message
    """
    channel_number = PbFieldInt('ant.open_channel.channel_number')



@pb_bind(AntDomain, 'close_channel', 3)
class CloseChannel(PbMessageWrapper):
    """ANT Close Channel channel configuration message
    """
    channel_number = PbFieldInt('ant.close_channel.channel_number')


@pb_bind(AntDomain, 'set_frequency', 3)
class SetFrequency(PbMessageWrapper):
    """ANT Set Frequency channel configuration message
    """
    channel_number = PbFieldInt('ant.set_frequency.channel_number')
    frequency = PbFieldInt('ant.set_frequency.frequency')
    
