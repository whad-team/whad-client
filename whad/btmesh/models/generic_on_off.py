"""
Implementation of the GenericOnOff Server and Clients Models
"""

from whad.btmesh.models import (
    ModelServer,
    Element,
    ModelState,
    ModelClient,
)
from whad.btmesh.stack.utils import MeshMessageContext
from whad.btmesh.models.states import GenericOnOffState


from whad.scapy.layers.btmesh import *


class GenericOnOffServer(ModelServer):
    def __init__(self):
        super().__init__(model_id=0x1000)

        self.rx_handlers[0x8201] = self.on_onoff_get
        self.rx_handlers[0x8202] = self.on_onoff_set
        self.rx_handlers[0x8203] = self.on_onoff_set_unack

        # already to false by default, but for clarity
        self.allows_dev_keys = False

        self.__init_states()

    def __init_states(self):
        generic_onoff_state = GenericOnOffState()
        self.add_state(generic_onoff_state)

    def on_onoff_get(self, message):
        pkt, ctx = message
        onoff = self.get_state("generic_onoff").get_value()
        response = BTMesh_Model_Generic_OnOff_Status(present_onoff=onoff)
        return response

    def on_onoff_set(self, message):
        pkt, ctx = message
        onoff_state = self.get_state("generic_onoff")
        onoff_state: ModelState
        if pkt.transition_time is not None:
            delay = ptk.delay
            present_onoff = onoff_state.get_value()
            response = BTMesh_Model_Generic_OnOff_Status(
                present_onoff=present_onoff,
                delay=delay,
                transition_time=pkt.transition_time,
            )
        else:
            delay = 0
            present_onoff = pkt.onoff
            response = BTMesh_Model_Generic_OnOff_Status(present_onoff=present_onoff)
        onoff_state.set_value(pkt.onoff, delay=delay)
        # print("LED VALUE SET TO " + str(pkt.onoff))
        return response

    def on_onoff_set_unack(self, message):
        pkt, ctx = message
        onoff_state = self.get_state("generic_onoff")
        onoff_state: ModelState
        if pkt.transition_time is not None:
            delay = pkt.delay
        else:
            delay = 0
        onoff_state.set_value(pkt.onoff, delay=delay)
        print("LED VALUE SET TO " + str(pkt.onoff))
        return None


class GenericOnOffClient(ModelClient):
    def __init__(self):
        super().__init__(model_id=0x1001)

        self.rx_handlers[0x8204] = self.rx_on_on_onff_status # BTMesh_Model_Generic_OnOff_Status

        self.tx_handlers[0x8202] = self.tx_on_off_acked
        self.tx_handlers[0x8203] = self.tx_on_off_unacked

        self.tid = 0

    def tx_on_off_unacked(self, message):
        """
        Custom handler to send a GenericOnOff_Set_Unacke message
        """
        pkt, ctx = message
        pkt[1].transaction_id = self.tid + 1
        self.tid += 1
        return None

    def tx_on_off_acked(self, message):
        """
        Custom handler to send a GenericOnOff_Set message
        """
        pkt, ctx = message
        pkt[1].transaction_id = self.tid + 1
        self.tid += 1

        # Set the expected class of the response
        self.expected_response_clazz = BTMesh_Model_Generic_OnOff_Status

        return None

    def rx_on_on_onff_status(self, message):
        """
        Custom handler when waiting to receive an expected BTMesh_Model_Generic_OnOff_Status message
        Useless, but to show custom handlers creation for Rx in ModelClient.
        """
        return None
