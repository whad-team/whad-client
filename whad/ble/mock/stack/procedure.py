"""
Bluetooth Low Energy GATT procedure

This class must be inherited to implement a GATT procedure.

# Procedure states

A GATT procedure has 3 predefined internal states:
- STATE_INITIAL: default state for a procedure
- STATE_DONE: state is reached when the GATT procedure has finished without error
- STATE_ERROR: state is reached when an unrecoverable error occurred

User-defined states could be defined starting with the base user state value
STATE_USER.

The `done()` method can be used to check if the procedure has finished and the `error()`
method to assess if the procedure is in error.

# Procedure trigger mechanism

The `trigger()` method must be overriden by inherited classes to provide the caller a
way to check if the procedure needs to be triggered. An ATT read request procedure
will check for ATT ReadRequest packets and would return `True` if such a request is
received. When the `trigger()` method returns `True`, the tiny BLE stack will consider
this procedure active and will call its `process_request()` method each time a packet is
received, until the procedure is over (STATE_DONE).

# Packet processing

Any procedure class that inherits from `Procedure` must implement its own `process_request()`
method that must return a list of packets to be sent back to the requesting peer. Since this
tiny stack has been designed for unit-testing, there is no mechanism to trigger any delayed
packet transmission. Delayed packets must be returned as well in the list of packets, and will
be processed as soon as possible.

"""
import logging
from typing import List, Optional, Any
from threading import Event

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Error_Response

from .attribute import Attribute

logger = logging.getLogger(__name__)

class UnexpectedProcError(Exception):
    """Unexpected procedure error."""

class Procedure:
    """Generic procedure state machine."""

    # Main states
    STATE_INITIAL = 0
    STATE_DONE = 1
    STATE_ERROR = 2

    # User states
    STATE_USER = 3

    # ATT Operation code (0 is invalid)
    OPCODE = 0

    # ATT Error codes
    ERR_INVALID_HANDLE = 0x01
    ERR_READ_NOT_PERMITTED = 0x02
    ERR_WRITE_NOT_PERMITTED = 0x03
    ERR_INVALID_PDU = 0x04
    ERR_INSU_AUTHENT = 0x05
    ERR_REQ_NOT_SUPP = 0x06
    ERR_INVALID_OFFSET = 0x07
    ERR_INSU_AUTHOR = 0x08
    ERR_PREP_QUEUE_FULL = 0x09
    ERR_ATTR_NOT_FOUND = 0x0A
    ERR_ATTR_NOT_LONG = 0x0B
    ERR_ENC_KEY_TOO_SHORT = 0x0C
    ERR_INVALID_ATTR_LEN = 0x0D
    ERR_UNLIKELY_ERROR = 0x0E
    ERR_INSU_ENCRYPT = 0x0F
    ERR_UNSUPP_GROUP_TYPE = 0x10
    ERR_INSU_RESOURCES = 0x11
    ERR_DB_OUT_OF_SYNC = 0x12
    ERR_VALUE_NOT_ALLOWED = 0x13
    ERR_APP_ERROR_BASE = 0x80
    ERR_COMMON_PROF_BASE = 0xE0
    ERR_TIMEOUT = 0xFF

    def __init__(self, attributes: list, mtu: int):
        """Initialization."""
        # Initialize state to STATE_INITIAL
        self.__state = Procedure.STATE_INITIAL

        # Save attribute list
        self.__attributes = attributes

        # Save ATT MTU
        self.__mtu = mtu

        # Procedure terminated event
        self.__terminated = Event()

        # Procedure result
        self.__result = None

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

    def get_state(self) -> int:
        """Return current state."""
        return self.__state

    def set_state(self, state: int):
        """Set procedure state."""
        self.__state = state

        # If procedure state is STATE_DONE or SATE_ERROR, procedure
        # is considered as terminated.
        self.__terminated.set()

    def set_result(self, result: Any):
        """Set procedure result. This result will be returned when the
        procedure has terminated to the caller."""
        self.__result = result

    def att_error_response(self, handle: int, ecode: int) -> list[Packet]:
        """
        Generate an ATT error response.

        :param handle: Attribute handle
        :type handle: int
        :param ecode: ATT error code as defined in Vol 3, Part F, section 3.3.3, Table 3.3
        :type ecode: int
        """
        return [ATT_Error_Response(request=self.OPCODE, handle=handle, ecode=ecode)]

    def error(self) -> bool:
        """Determine if procedure is in error state."""
        return self.__state == Procedure.STATE_ERROR

    def done(self) -> bool:
        """Determine if procedure is done."""
        return self.__state == Procedure.STATE_DONE

    def initiate(self) -> List[Packet]:
        """Generate a list of ATT packets to send when this procedure
        is initiated.

        :return: List of packets (PDUs) to send following the procedure initiation.
        :rtype: List
        """
        return []

    def process_request(self, request: Packet) -> List[Packet]:
        """Process a received ATT request/response.

        :return: List of packets (PDUs) to send once the received PDUs processed.
        :rtype: List
        :raise UnexpectedProcError: An unexpected error occurred while processing incoming packets.
        """
        raise UnexpectedProcError(request)

    def wait(self, timeout: Optional[float] = None) -> Optional[Any]:
        """Wait for this procedure to terminate."""
        if self.__terminated.wait(timeout=timeout):
            return self.__result
        else:
            raise UnexpectedProcError(Procedure.ERR_TIMEOUT)
