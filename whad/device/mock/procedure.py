import logging
from re import I
from typing import List, Optional, Any, Callable, Type
from threading import Event
from enum import IntEnum

# Default module logger
logger = logging.getLogger(__name__)

class ProcedureState(IntEnum):
    """Default procedure states.

    `INITIAL` state is the default state used in procedures when
    they are instantiated. The `DONE` state corresponds to a procedure
    that has been successfully completed, while the `ERROR` state is used
    to indicate that an error has occurred.

    The `USER` state shall be used to implement any user-defined states.
    """
    INITIAL = 0
    DONE = 1
    ERROR = 2
    USER = 3


class Procedure:
    """WHAD generic procedure for mocks.

    This class defines a generic test procedure used in mocks. It is a basic
    state machine able to process incoming and outgoing packets independently
    of a specific protocol. It is designed to be used in mocks to interact with
    any WHAD device in order to implement speciic unit tests.
    """

    # State handlers
    __HANDLERS = {}

    @classmethod
    def proc_state(cls, state: Type[ProcedureState]):
        """Decorator to register a method as a handler for a specific state."""
        def proc_state_wrapper(method: Callable[[int, int], None]):
            """Register method as handler for state `state`."""
            cls.__HANDLERS[state] = method
            return method

        # Return wrapper
        return proc_state_wrapper

    def __init__(self):
        """Initialize this procedure."""
        self.set_state(ProcedureState.INITIAL)

    def set_state(self, state: ProcedureState):
        """Set current state and triggers state handlers if any.

        :param state: Procedure state to set
        :type state: ProcedureState
        """
        # Update state
        prev_state = self.__state
        self.__state = state

        # Trigger the associated state callback, if any.
        if state in self.__HANDLERS:
            self.__HANDLERS[state](prev_state, state)

