"""WHAD Protocol Discovery speed message abstraction layer.
"""

from whad.hub.message import pb_bind, PbFieldInt, PbMessageWrapper
from whad.hub.discovery import Discovery

@pb_bind(Discovery, 'set_speed', 1)
class SetSpeed(PbMessageWrapper):
    """Device set speed message class
    """
    speed = PbFieldInt('discovery.set_speed.speed')