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
from typing import List

from scapy.packet import Packet
from scapy.layers.bluetooth import ATT_Error_Response

from whad.device.mock.procedure import StackProcedure, ProcedureState, UnexpectedProcError

from .attribute import Attribute

logger = logging.getLogger(__name__)

class BleClientProcedure(StackProcedure):
    """Bluetooth Low Energy ATT Client procedure."""

    # ATT Operation code (0 is invalid)
    OPCODE = 0

    class States(ProcedureState):
        """BLE ATT Client states."""
        SUB_DONE = ProcedureState.USER

    def __init__(self, packets: List[Packet]):
        super().__init__(packets)

    @property
    def states(self):
        return BleClientProcedure.States

    def done(self) -> bool:
        """
        Determine if the procedure has completed.

        TODO: replace with call to success() in other dependencies."""
        return self.success()

    def att_error_response(self, handle: int, ecode: int) -> list[Packet]:
        """
        Generate an ATT error response.

        :param handle: Attribute handle
        :type handle: int
        :param ecode: ATT error code as defined in Vol 3, Part F, section 3.3.3, Table 3.3
        :type ecode: int
        """
        return [ATT_Error_Response(request=self.OPCODE, handle=handle, ecode=ecode)]

    def process_request(self, request: Packet) -> List[Packet]:
        """Process a received ATT request/response.

        :return: List of packets (PDUs) to send once the received PDUs processed.
        :rtype: List
        :raise UnexpectedProcError: An unexpected error occurred while processing incoming packets.
        """
        raise UnexpectedProcError(request)

class BleServerProcedureState(ProcedureState):
    """States specific to BLE server write procedure. """
    INDICATION_SENT = ProcedureState.USER

class BleServerProcedure(StackProcedure):
    """Bluetooth Low Energy ATT Server procedure."""

    # ATT Operation code (0 is invalid)
    OPCODE = 0

    @classmethod
    def trigger(cls, request) -> bool:
        """Trigger or not the procedure."""
        logger.warning("[ble::stack::mock::Procedure] trigger method must be overriden")
        logger.debug("[ble::stack::mock::Procedure] trigger() called with packet %s", bytes(request).hex())
        return False


    def __init__(self, attributes: list, mtu: int = 23):
        """Initialization.

        :param  attributes: GATT server attributes
        :param  attributes: dict
        :param  mtu: Maximum transmission unit
        :type   mtu: int, optional
        """
        # Call parent init method.
        super().__init__([])

        # Save attribute list
        self.__attributes = attributes

        # Save ATT MTU
        self.__mtu = mtu

    @property
    def attributes(self) -> list[Attribute]:
        """GATT attributes dictionary."""
        return self.__attributes

    @property
    def mtu(self) -> int:
        """ATT MTU."""
        return self.__mtu

    @property
    def states(self):
        """Specify the states enum for this procedure."""
        return BleServerProcedureState

    def done(self) -> bool:
        """
        Determine if the procedure has completed.

        TODO: replace with call to success() in other dependencies."""
        return self.success()

    def att_error_response(self, handle: int, ecode: int) -> list[Packet]:
        """
        Generate an ATT error response.

        :param handle: Attribute handle
        :type handle: int
        :param ecode: ATT error code as defined in Vol 3, Part F, section 3.3.3, Table 3.3
        :type ecode: int
        """
        return [ATT_Error_Response(request=self.OPCODE, handle=handle, ecode=ecode)]

    def process_request(self, request: Packet) -> List[Packet]:
        """Process a received ATT request/response.

        :return: List of packets (PDUs) to send once the received PDUs processed.
        :rtype: List
        :raise UnexpectedProcError: An unexpected error occurred while processing incoming packets.
        """
        raise UnexpectedProcError(request)

