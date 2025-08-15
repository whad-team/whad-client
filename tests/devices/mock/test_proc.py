"""
Unit tests for WHAD's mock basic procedure feature.
"""

from whad.device.mock.procedure import Procedure, ProcedureMetaclass, ProcedureState, proc_state

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
    print(dir(proc))
    assert proc.checked
    assert proc.prev_state == ProcedureState.UNDEFINED
    assert proc.new_state == ProcedureState.INITIAL

