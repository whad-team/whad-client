from whad.exceptions import RequiredImplementation

class Bearer:
    """
    This class defines a Mesh bearer, abstracting the physical layer out of the the BTMesh connector.
    
    This class must NOT be used directly, but inherited by the concrete implementation of the bearer.

    The child classes should defines at least three main methods:
    - start(): start the bearer (according to the configuration loaded in configuration dictionary stored as attribute)
    - stop(): stop the bearer
    - send(pdu): send a PDU though the bearer
    """
    def __init__(self, connector):
        self.connector = connector
        self.configuration = {}

    def configure(self, **kwargs):
        for name, value in kwargs.items():
            self.configuration[name] = value

    def start(self):
        """Function used to start the bearer.

        This method MUST be overriden by inherited classes.
        """
        logger.error("method `start` must be implemented in inherited classes")
        raise RequiredImplementation()


    def stop(self):
        """Function used to stop the bearer.

        This method MUST be overriden by inherited classes.
        """
        logger.error("method `stop` must be implemented in inherited classes")
        raise RequiredImplementation()

    def send(self, pdu):
        """Function used to start the bearer.

        This method MUST be overriden by inherited classes.

        :param pdu: BLE mesh pdu to send
        :type pdu: bytes 
        """
        logger.error("method `start` must be implemented in inherited classes")
        raise RequiredImplementation()

from .adv import AdvBearer

__all__ = [
    "Bearer",
    "AdvBearer"
]