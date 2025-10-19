class AntProfile:
    
    CHANNEL_DIRECTION = None
    NETWORK_KEY = None
    DEFAULT_RF_CHANNEL = None
    DEVICE_TYPE = None
    TRANSMISSION_TYPE = None
    CHANNEL_PERIOD = None
    SEARCH_TIMEOUT = None

    def __init__(self, application = None):
        self.application = application
        self.__started = False

    def set_application(self, application):
        self.application = application

    def is_started(self):
        '''Indicates if the profile is running.
        '''
        return self.__started

    def start(self):
        '''Start the profile.
        '''
        self.__started = True

    def stop(self):
        '''Stop the profile.
        '''
        self.__started = False

    def broadcast(self, payload):
        '''Transmit a PDU in broadcast.
        '''
        if self.__started and self.application is not None:
            self.application.broadcast(payload)
            return True
        return False

    def ack(self, payload):
        '''Transmit a PDU in ack mode.
        '''
        if self.__started and self.application is not None:
            return self.application.ack(payload)
        return False

    def burst(self, *payloads):
        '''Transmit a PDU in burst mode.
        '''
        if self.__started and self.application is not None:
            return self.application.burst(*payloads)
        return False

    def on_broadcast(self, payload):
        '''Callback called when a broadcast is received.
        '''
        pass
    
    def on_ack_burst(self, payload):
        '''Callback called when an ack/burst is received.
        '''
        pass