from whad.ant.channel import ChannelDirection

class AntProfile:
    """
    Generic ANT Profile.

    This class must be inherited to implement a custom profile.
    """
    
    #: Default channel direction when this profile is used
    CHANNEL_DIRECTION:ChannelDirection = None
    #: Default network key when this profile is used
    NETWORK_KEY:bytes = None
    #: Default RF Channel when this profile is used
    DEFAULT_RF_CHANNEL:int = None
    #: Default device type when this profile is used
    DEVICE_TYPE:int = None
    #: Default transmission type when this profile is used
    TRANSMISSION_TYPE:int = None
    #: Default channel period when this profile is used
    CHANNEL_PERIOD:int = None
    #: Default search timeout when this profile is used
    SEARCH_TIMEOUT:int = None

    def __init__(self, application = None):
        """Constructor for a generic profile.

        :param application: ANT Application layer to use
        :type application: `whad.ant.stack.app.AppLayer` 
        """
        self.application = application
        self.__started = False

    def set_application(self, application):
        """Configure the application layer to use.

        :param application: ANT Application layer to use
        :type application: `whad.ant.stack.app.AppLayer` 
        """
        self.application = application

    def is_started(self) -> bool:
        """Indicates if the profile is running.
        """
        return self.__started

    def start(self):
        """Start the profile.
        """
        self.__started = True

    def stop(self):
        """Stop the profile.
        """
        self.__started = False

    def broadcast(self, payload:bytes):
        """Transmit a PDU in broadcast.

        :param payload: payload to transmit
        :type payload: bytes
        """
        if self.__started and self.application is not None:
            self.application.broadcast(payload)
            return True
        return False

    def ack(self, payload:bytes):
        """Transmit a PDU in acked mode.

        :param payload: payload to transmit
        :type payload: bytes
        """
        if self.__started and self.application is not None:
            return self.application.ack(payload)
        return False

    def burst(self, *payloads:bytes):
        """Transmit a PDU (or a set of PDU) in burst mode.

        :param payloads: set of payloads (in bytes) to transmit
        :type payloads: bytes
        """
        if self.__started and self.application is not None:
            return self.application.burst(*payloads)
        return False

    def on_broadcast(self, payload:bytes):
        """Callback called when a broadcast is received.

        :param payload: received payload
        :type payload: bytes
        """
        pass
    
    def on_ack_burst(self, payload:bytes):
        """Callback called when an ack/burst is received.
        
        :param payload: received payload
        :type payload: bytes
        """
        pass