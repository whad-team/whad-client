"""
Unit tests for WHAD's mock basic procedure feature.
"""
import pytest
from enum import Enum
from typing import List

from scapy.packet import Packet, Raw

from whad.device.mock.procedure import (
    Procedure, ProcedureMetaclass, ProcedureState, StackProcedure, proc_state, ProcTimeoutError
)

###
# Test generic Procedure implementation
###

def test_handler_def():
    """Check if proc_state decorator correctly registers an handler."""
    class MyProcedure(Procedure):

        def __init__(self):
            """Initialize custom procedure class object."""
            self.checked = False
            self.prev_state = ProcedureState.UNDEFINED
            self.new_state = ProcedureState.UNDEFINED
            super().__init__()

        @proc_state(ProcedureState.INITIAL)
        def handler(self, prev_state: int, state: int):
            """Custom handler"""
            self.checked = True
            self.prev_state = prev_state
            self.new_state = state

    # Create an instance of our procedure
    proc = MyProcedure()
    proc.start()
    assert proc.checked
    assert proc.prev_state == ProcedureState.UNDEFINED
    assert proc.new_state == ProcedureState.INITIAL

def test_procedure_success():
    """Check procedure success methods."""
    proc = Procedure()
    proc.start()
    proc.set_state(ProcedureState.DONE)
    assert proc.get_state() == ProcedureState.DONE
    assert proc.success()

def test_procedure_error():
    """Check procedure error methods."""
    proc = Procedure()
    proc.start()
    proc.set_state(ProcedureState.ERROR)
    assert proc.get_state() == ProcedureState.ERROR
    assert proc.error()

def test_procedure_success_completed():
    """Check procedure is marked as completed when successful."""
    proc = Procedure()
    proc.start()
    proc.set_result(True)
    proc.set_state(ProcedureState.DONE)
    assert proc.wait(1.0)

def test_procedure_error_completed():
    """Check procedure is marked as completed when in error."""
    proc = Procedure()
    proc.start()
    proc.set_result(True)
    proc.set_state(ProcedureState.ERROR)
    assert proc.wait(1.0)

def test_procedure_cancel_completed():
    """Check procedure is marked as completed when canceled."""
    proc = Procedure()
    proc.start()
    proc.set_result(True)
    proc.cancel()
    proc.wait(1.0)
    assert proc.get_state() == ProcedureState.CANCELED

def test_procedure_user_state():
    """Check procedure correctly handles user-defined states."""
    class MyStates(ProcedureState):
        CUSTOM_STATE = ProcedureState.USER
        CUSTOM_STATE2 = ProcedureState.USER + 1

    class MyProcedure(Procedure):
        """Custom procedure"""

        @proc_state(ProcedureState.INITIAL)
        def on_initial(self, prev, state):
            """Initial state -> custom state."""
            assert prev == MyStates.UNDEFINED
            assert state == MyStates.INITIAL
            self.set_state(MyStates.CUSTOM_STATE)

        @proc_state(MyStates.CUSTOM_STATE)
        def on_custom(self, prev, state):
            """CUSTOM_STATE -> CUSTOM_STATE2."""
            assert prev == MyStates.INITIAL
            assert state == MyStates.CUSTOM_STATE
            self.set_state(MyStates.CUSTOM_STATE2)

        @proc_state(MyStates.CUSTOM_STATE2)
        def on_custom2(self, prev, state):
            """Last step."""
            assert prev == MyStates.CUSTOM_STATE
            assert state == MyStates.CUSTOM_STATE2
            self.set_state(MyStates.DONE)

    proc = MyProcedure()
    proc.start()
    assert proc.success()

def test_procedure_timeout():
    """Check that a ProcTimeoutError is raised when wait() times out."""
    proc = Procedure()
    with pytest.raises(ProcTimeoutError):
        proc.wait(.5)

###
# Test StackProcedure
###

def test_stack_procedure_initial():
    """Check stack procedure generates a list of packet on initial state."""
    proc = StackProcedure([Raw(b"foobar")])
    packets = proc.initiate()
    assert len(packets) == 1
    assert packets[0] == Raw(b"foobar")

