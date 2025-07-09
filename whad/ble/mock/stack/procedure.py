"""Bluetooth Low Energy GATT procedure"""
import logging
from scapy.packet import Packet

from .attribute import Attribute

logger = logging.getLogger(__name__)

class Procedure:
    """Generic procedure state machine."""

    # Main states
    STATE_INITIAL = 0
    STATE_DONE = 1
    STATE_ERROR = 2

    # User states
    STATE_USER = 3

    def __init__(self, attributes: list, mtu: int):
        """Initialization."""
        # Initialize state to STATE_INITIAL
        self.__state = Procedure.STATE_INITIAL

        # Save attribute list
        self.__attributes = attributes

        # Save ATT MTU
        self.__mtu = mtu

    @classmethod
    def trigger(cls, request) -> bool:
        """Trigger or not the procedure."""
        logger.warning("[ble::stack::mock::Procedure] trigger method must be overriden")
        logger.debug("[ble::stack::mock::Procedure] trigger() called with packet %s", bytes(request).hex())
        return False

    @property
    def attributes(self) -> list[Attribute]:
        """GATT attributes dictionary."""
        return self.__attributes

    @property
    def mtu(self) -> int:
        """ATT MTU."""
        return self.__mtu

    def set_state(self, state: int):
        """Set procedure state."""
        self.__state = state

    def error(self) -> bool:
        """Determine if procedure is in error state."""
        return self.__state == Procedure.STATE_ERROR

    def done(self) -> bool:
        """Determine if procedure is done."""
        return self.__state == Procedure.STATE_DONE

    def process_request(self, request: Packet) -> list[Packet]:
        """Process an ATT request."""
        raise Exception(request)

