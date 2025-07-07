"""Bluetooth Low Energy GATT procedure"""
from .att import Error

class Procedure:
    """Generic procedure state machine."""

    # Main states
    STATE_INITIAL = 0
    STATE_DONE = 1
    STATE_ERROR = 2

    # User states
    STATE_USER = 3

    def __init__(self, attributes: list):
        """Initialization."""
        # Initialize state to STATE_INITIAL
        self.__state = Procedure.STATE_INITIAL

        # Save attribute list
        self.__attributes = attributes

    @classmethod
    def trigger(cls, request) -> bool:
        """Trigger or not the procedure."""
        return False

    def set_state(self, state: int):
        """Set procedure state."""
        self.__state = state

    def error(self) -> bool:
        """Determine if procedure is in error state."""
        return self.__state == Procedure.STATE_ERROR

    def done(self) -> bool:
        """Determine if procedure is done."""
        return self.__state == Procedure.STATE_DONE

    def process_request(self, request):
        """Process an ATT request."""
        raise "MustImplement"

