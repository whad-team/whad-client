from .generic import Generic
from .discovery import Discovery
from .ble import BleDomain

class ProtocolHub(object):
    """Protocol hub
    """

    def __init__(self, version: int):
        """Configure the protocol hub for a specific protocol version
        """
        self.__version = version
        self.__generic = Generic(self.__version)
        self.__discovery = Discovery(self.__version)
        self.__ble = BleDomain(self.__version)

    @property
    def generic(self):
        return self.__generic
    
    @property
    def discovery(self):
        return self.__discovery
    
    @property
    def ble(self):
        return self.__ble

