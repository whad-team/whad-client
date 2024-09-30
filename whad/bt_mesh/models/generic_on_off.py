"""
Implementation of the GenericOnOff Server and Clients Models
"""

from whad.bt_mesh.models import ModelServer, Element, ModelState, ModelClient
from whad.bt_mesh.stack.utils import MeshMessageContext


from whad.scapy.layers.bt_mesh import *


class GenericOnOffServer(ModelServer):
    def __init__(self, element_addr):
        super().__init__(model_id=0x1000, element_addr=element_addr)

        self.handlers[0x8201] = self.on_onoff_get
        self.handlers[0x8202] = self.on_onoff_set
        self.handlers[0x8203] = self.on_onoff_set_unack

    def on_onoff_get(self, message):
        onoff = self.global_states_manager.get_state(
            "generic_onoff", model_id=self.model_id, element_addr=self.element_addr
        ).get_value()
        response = BTMesh_Model_Generic_OnOff_Status(present_onoff=onoff)
        return response

    def on_onoff_set(self, message):
        onoff_state = self.global_states_manager.get_state(
            "generic_onoff", model_id=self.model_id, element_addr=self.element_addr
        ).get_value()
        onoff_state: ModelState
        if message.transition_time is not None:
            delay = message.delay
            present_onoff = onoff_state.get_value()
            response = BTMesh_Model_Generic_OnOff_Status(
                present_onoff=present_onoff,
                delay=delay,
                transition_time=message.transition_time,
            )
        else:
            delay = 0
            present_onoff = message.onoff
            response = BTMesh_Model_Generic_OnOff_Status(present_onoff=present_onoff)
        onoff_state.set_value(message.onoff, delay=delay)
        print("LED VALUE SET TO " + str(message.onoff))
        return response

    def on_onoff_set_unack(self, message):
        onoff_state = self.global_states_manager.get_state(
            "generic_onoff", model_id=self.model_id, element_addr=self.element_addr
        )
        onoff_state: ModelState
        if message.transition_time is not None:
            delay = message.delay
        else:
            delay = 0
        onoff_state.set_value(message.onoff, delay=delay)
        print("LED VALUE SET TO " + str(message.onoff))
        return None


class GenericOnOffClient(ModelClient):
    def __init__(self, element_addr):
        super().__init__(model_id=0x1001, element_addr=element_addr)

        self.handlers[0x8204] = self.on_onoff_status
        self.tid = 0

    def on_onoff_status(self, message):
        print("RECEIVED ONOFF STATUS")
        message.show()
        return None

    def registered_function_on_keypress(self, key_pressed):
        """
        On keypress, we send an Access message BTMesh_Model_Generic_OnOff_Set_Unacknowldged
        to the all-nodes addr

        :param key_pressed: [TODO:description]
        :type key_pressed: [TODO:type]
        """
        print("IN GenericOnOff CLIENT ON KEYPRESS")
        onoff_state = self.global_states_manager.get_state(
            "generic_onoff", model_id=self.model_id - 1, element_addr=self.element_addr
        )
        # also set our led to the value to synchronize, because why not
        onoff_state.set_value((onoff_state.get_value() + 1) % 2)
        onoff = onoff_state.get_value()

        pkt = BTMesh_Model_Generic_OnOff_Set_Unacknowledged(
            onoff=onoff, transaction_id=self.tid
        )
        self.tid += 1 % 255
        ctx = MeshMessageContext()
        ctx.src_addr = self.element_addr
        ctx.dest_addr = b"\xff\xff"
        ctx.ttl = 1
        return pkt, ctx
