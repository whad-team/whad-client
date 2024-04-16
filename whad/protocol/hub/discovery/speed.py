"""WHAD Protocol Discovery speed message abstraction layer.
"""

from whad.protocol.hub import pb_bind, PbFieldInt, PbMessageWrapper
from whad.protocol.hub.discovery import Discovery

@pb_bind(Discovery, 'set_speed', 1)
class SetSpeed(PbMessageWrapper):
    """Device set speed message class
    """
    speed = PbFieldInt('discovery.set_speed.speed')