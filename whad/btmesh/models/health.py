"""
Implementation of the Health Server And Client Models
Mesh Protocol Specificiation Section 4.4.3 and 4.4.4
"""

from whad.btmesh.models import (
    ModelServer,
)

from whad.btmesh.models.states import (
    CurrentHealthFaultCompositeState,
    AttentionTimeState,
    HealthFastPeriodDivisorState,
)


from whad.scapy.layers.btmesh import *


# TODO : Implement the actual stuff ...
class HealthModelServer(ModelServer):
    def __init__(self):
        super().__init__(model_id=0x0002, name="Health Server")

        self.__init_states()

    def __init_states(self):
        self.add_state(CurrentHealthFaultCompositeState())
        self.add_state(AttentionTimeState())
        self.add_state(HealthFastPeriodDivisorState())
