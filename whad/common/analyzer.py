
"""
WHAD traffic analyzer base module.
"""
from typing import List, Any, Optional, Any, Type

from scapy.packet import Packet

class InvalidParameter(Exception):
    """Invalid parameter specified to a traffic analyzer."""
    def __init__(self, name: str, value: Any):
        """Initialization."""
        super().__init__()
        self.__name = name
        self.__value = value

    @property
    def parameter(self) -> str:
        """Invalid parameter name."""
        return self.__name

    @property
    def value(self) -> Any:
        """Parameter value"""
        return self.__value

    def __str__(self) -> str:
        """String representation of this exception."""
        return f"InvalidParameter(name=\"{self.__name}\", value=\"{self.__value}\")"

    def __repr__(self) -> str:
        """Representation of this exception."""
        return str(self)

class TrafficAnalyzer:
    """
    Traffic analyzer base class.

    This class must be inherited by specialized traffic analyzers
    in order to provide `wanalyze` with extracted and/or computed
    data.
    """

    # Traffic analyzer parameters (no parameters by default),
    # override this class property to define custom parameters.
    PARAMETERS = {}

    @classmethod
    def has_parameter(cls, parameter: str) -> bool:
        """ Check if a given parameter is expected, based on its name. """
        return parameter in cls.PARAMETERS

    @classmethod
    def get_default_parameters(cls) -> dict:
        """ Return the class default parameters. """
        default_params = {}
        for parameter, value in cls.PARAMETERS.items():
            default_params[parameter] = value
        return default_params

    def __init__(self, **kwargs):
        """ Initialize a traffic analyzer and set its associated
        configuration parameters, if provided.
        """
        # Filter parameters to only keep those we expect
        self.__parameters = self.get_default_parameters()
        for parameter,value in kwargs.items():
            if parameter in self.__parameters:
                self.__parameters[parameter] = value

        # Reset this traffic analyzer
        self.reset()

    def get_param(self, param: str) -> Any:
        """ Retrieve a provided parameter value. """
        if param in self.__parameters:
            return self.__parameters[param]

    def set_param(self, param: str, value: Any):
        """ Set traffic analyzer parameter value. """
        if param in self.__parameters:
            self.__parameters[param] = value

    def process_packet(self, packet: Packet):
        """Process a packet.
        """

    def mark_packet(self, packet):
        """Mark a specific packet.
        """
        self.__marked_packets.append(packet)

    def reset(self):
        """Reset traffic analyzer state.
        """
        self.__triggered = False
        self.__completed = False
        self.__marked_packets = []

    def trigger(self):
        """Trigger this traffic analyzer.
        """
        self.__triggered = True

    def complete(self):
        """Mark this analyzer as completed.

        Once a traffic analyzer is completed, its output
        can be queried.
        """
        self.__completed = True

    @property
    def marked_packets(self) -> List[Packet]:
        """Returns marked packets.
        """
        return self.__marked_packets

    @property
    def output(self) -> Optional[Any]:
        """Returns the traffic analyzer output.
        """
        return None

    @property
    def triggered(self) -> bool:
        """Determine if the traffic analyzer has been triggered.

        :rtype: bool
        :return: `True` if triggered, `False` otherwise.
        """
        return self.__triggered

    @property
    def completed(self) -> bool:
        """Determine if the traffic analyzer has completed is
        job.

        :rtype: bool
        :return: `True` if completed, `False` otherwise.
        """
        return self.__completed
