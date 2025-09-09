"""
WHAD Unit Tests Procedures
==========================

This module provides a basic implementation of a test
procedure for mocks through the `Procedure` class. This
class is a simple state-machine that must be extended
to define any testing procedure including a single or
multiple steps.

A procedure has an initial state and three possible terminal
states:
- a state indicating that the procedure has successfully completed
  and returned a result (*DONE* state) or
- a state indicating that an error occurred during the procedure
  (*ERROR* state)
- a state indicating the procedure has been canceled (*CANCELED* state)

"""
import logging

from typing import Optional, Any, Callable, List, Type
from threading import Event

from scapy.packet import Packet

# Default module logger
logger = logging.getLogger(__name__)

def proc_state(state: int):
    """Decorator to specify a method as an handler for a specific state.

    :param state: State associated with the decorated method.
    """
    def _wrapper(f):
        setattr(f, "__state_handler", state)
        return f
    return _wrapper


class UnexpectedProcError(Exception):
    """Unexpected error occurred while executing a test procedure."""

class ProcTimeoutError(Exception):
    """Procedure has not completed in due time."""

class ProcedureState:
    """Default procedure states.

    `INITIAL` state is the default state used in procedures when
    they are instantiated. The `DONE` state corresponds to a procedure
    that has been successfully completed, while the `ERROR` state is used
    to indicate that an error has occurred.

    The `USER` state shall be used to implement any user-defined states.
    """
    UNDEFINED = -1
    INITIAL = 0
    DONE = 1
    ERROR = 2
    CANCELED = 3
    USER = 4



class ProcedureMetaclass(type):
    """Procedure metaclass used to automatically register handlers
    associated with a procedure class.

    This metaclass is used by the `Procedure` class to automatically
    register any method decorated with `proc_state` as an handler
    associated with a specific state.

    A dictionary of registered handlers is injected in the class
    based on this metaclass as `STATE_HANDLERS`, that is then used
    in the `Procedure` class and its derived classes to call these
    the correct handler each time the procedure enters a specific
    state.
    """

    def __new__(cls, name, bases, dct):
        """Look for state handlers and update class's state handlers dictionary."""
        # Iterate over dct to register decorated handlers
        handlers = {}
        for name,obj in dct.items():
            if hasattr(obj, "__state_handler"):
                handlers[getattr(obj, "__state_handler")] = obj

        # Inject handlers dictionnary if not defined
        dct["STATE_HANDLERS"] = handlers

        # Create instance
        return super().__new__(cls, name, bases, dct)

class Procedure(metaclass=ProcedureMetaclass):
    """WHAD generic procedure for mocks.

    This class defines a generic test procedure used in mocks. It is a basic
    state machine able to process incoming and outgoing packets independently
    of a specific protocol. It is designed to be used in mocks to interact with
    any WHAD device in order to implement speciic unit tests.

    Handlers associated with a given state can be declared in this class by using
    the `proc_state` decorator. Such handlers will be called each time the procedure
    enters their associated states.

    Procedure is considered completed when its state is one of the terminal states:
    `ProcedureState.DONE`, `ProcedureState.ERROR` or `ProcedureState.CANCELED`.
    Waiting for procedure completion can be achieved by calling its `wait()` method.

    States associated with the procedure class are defined in a pseudo-enum class
    deriving from `ProcedureState` and set in the procedure class's `StatesEnum`
    property.
    """
    # Handlers for various states
    STATE_HANDLERS = {}

    # Terminal states
    TERMINAL_STATES = (
        ProcedureState.DONE,
        ProcedureState.ERROR,
        ProcedureState.CANCELED
    )

    def __init__(self):
        """Initialize this procedure."""
        # Set default state
        self.__state = ProcedureState.UNDEFINED
        self.__result = None
        self.__completed = Event()

    @classmethod
    def get_states_enum(cls) -> Type[ProcedureState]:
        return ProcedureState

    @property
    def states(self) -> Type[ProcedureState]:
        """Associated procedure state enum."""
        return self.get_states_enum()

    @classmethod
    def get_handler(cls, state: int) -> Optional[Callable[[int, int], None]]:
        """Retrieve the handler associated with a given state, if any."""
        if state in cls.STATE_HANDLERS:
            return cls.STATE_HANDLERS[state]
        return None

    def start(self):
        """Initiate procedure."""
        self.set_state(ProcedureState.INITIAL)

    def call_handler(self, prev:int, state: int) -> bool:
        """Call handler for given state."""
        handler = self.get_handler(state)
        if handler is not None:
            handler(self, prev, state)
            return True
        else:
            return False

    def set_state(self, state: int):
        """Set current state and triggers state handlers if any.

        :param state: Procedure state to set
        :type state: int
        """
        # Update state
        prev_state = self.__state
        self.__state = state

        if state not in Procedure.TERMINAL_STATES:
            # Call handler on state change
            self.call_handler(prev_state, state)
        else:
            # Mark procedure as terminated
            self.__completed.set()

    def get_state(self) -> int:
        """Get current procedure state."""
        return self.__state

    def is_state(self, state: int) -> bool:
        """Check current state."""
        return self.__state == state

    def set_result(self, result: Any):
        """Set result for procedure."""
        self.__result = result

    def get_result(self) -> Any:
        """Procedure result."""
        return self.__result

    def success(self) -> bool:
        """Determine if the procedure has been successful."""
        return self.__state == ProcedureState.DONE

    def error(self) -> bool:
        """Determine if an error occurred during the procedure."""
        return self.__state == ProcedureState.ERROR

    def cancel(self):
        """Cancel current procedure."""
        self.set_result(None)
        self.set_state(ProcedureState.CANCELED)

    def canceled(self) -> bool:
        """Determine if the procedure has been canceled."""
        return self.__state == ProcedureState.CANCELED

    def wait(self, timeout: Optional[float] = None) -> Optional[Any]:
        """Wait for this procedure to terminate.

        :param timeout: Maximum time allowed for the procedure to complete
        :type timeout: float, optional
        :return: Procedure result
        :rtype: object, optional
        """
        if self.__completed.wait(timeout=timeout):
            return self.__result
        else:
            raise ProcTimeoutError()

class StackProcedure(Procedure):
    """
    Test procedure implementation for device mocks.

    This procedure base class allows to define a list of packets to be sent
    when the procedure is initiated, and to process incoming packets through
    its `process` method. Procedure state is updated when `process()` is called,
    until it reaches a final state (*DONE*, *ERROR* or *CANCEL*).
    """

    def __init__(self, packets: Optional[List[Packet]] = None):
        """Initialize stack procedure.

        :param packets: List of initial packets for this procedure
        :type packets: list, optional
        """
        self.__initial_packets = packets or []
        super().__init__()

    def initiate(self) -> List[Packet]:
        """Start stack procedure and return initial packets.

        :return: List of initial packets for this procedure
        :rtype: list
        """
        self.start()
        return self.__initial_packets

    def process(self, packet: Packet) -> List[Packet]:
        """Incoming packet processing callback.

        This callback can be overriden to update the procedure state
        depending on any received packet.

        :param packet: Received packet
        :type packet: Packet
        :return: List of packets to send in response of the received packet, if any
        :rtype: list
        """
        logger.debug("processing packet %s", packet)
        return []

