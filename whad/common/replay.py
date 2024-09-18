"""WHAD replay helpers and events.
"""
from whad.exceptions import ReplayInvalidRole

class ReplayRole:
    """Replay role constants
    """
    EMITTER = 1
    RECEIVER = 2
    BOTH = 3

class ReplayInterface:
    """This class provides a template that can be inherited in order to
    implement a replay class.
    """

    def __init__(self, role : int):
        """Initialize a replay interface.

        :param role: Replay role (emitter, receiver or both)
        :type role: int
        """
        # Not connected by default
        self.__connected = False

        # Save replay role
        if role in [ReplayRole.EMITTER, ReplayRole.RECEIVER, ReplayRole.BOTH]:
            self.__role = role
        else:
            raise ReplayInvalidRole

    def is_emitter(self) -> bool:
        """Determine if this replay interface acts as an emitter.
        """
        return self.__role in (ReplayRole.EMITTER, ReplayRole.BOTH)

    def is_receiver(self) -> bool:
        """Determine if this replay interface acts as a receiver.
        """
        return self.__role in (ReplayRole.RECEIVER, ReplayRole.BOTH)

    def prepare(self, **kwargs):
        """Prepare the replay interface.

        This method is called with a set of named parameters depending on the
        parameters declared in the replay configuration.
        """

    def send_packet(self, packet):
        """This method is called to replay a packet from a PCAP file.
        """
