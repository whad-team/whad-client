from whad.hub.events import WhadEvent


class DiscoveryEvt(WhadEvent):
    """Discovery event
    
    this event is sent to notify the discovery of a new commmunication on an unknown link in 
    wirelessHart protocol
    """
    def __init__(self, **parameters):
        super().__init__(**parameters)