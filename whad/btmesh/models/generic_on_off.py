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
        super().__init__(model_id=0x1000, name="Generic On/Off Server")

        self.handlers[0x8201] = self.on_onoff_get
        self.handlers[0x8202] = self.on_onoff_set
        self.handlers[0x8203] = self.on_onoff_set_unack

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
        #print("LED VALUE SET TO " + str(pkt.onoff))
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
        super().__init__(model_id=0x1001, name="Generic On/Off Client")

        self.handlers[0x8204] = self.on_onoff_status
        self.tid = 0

    def on_onoff_status(self, message):
        pkt, ctx = message
        print("RECEIVED ONOFF STATUS")
        pkt.show()
        return None

    def registered_function_on_keypress(self, key_pressed):
        """
        On keypress, we send an Access message BTMesh_Model_Generic_OnOff_Set_Unacknowldged
        to the all-nodes addr

        :param key_pressed: [TODO:description]
        :type key_pressed: [TODO:type]
        """
        print("IN GenericOnOff CLIENT ON KEYPRESS")
        onoff_state = self.get_state("generic_onoff")
        # also set our led to the value to synchronize, because why not
        onoff_state.set_value((onoff_state.get_value() + 1) % 2)
        onoff = onoff_state.get_value()

        pkt = BTMesh_Model_Generic_OnOff_Set(onoff=onoff, transaction_id=self.tid)
        self.tid += 1 % 255
        ctx = MeshMessageContext()
        # ctx.dest_addr = b"\xff\xff"
        ctx.dest_addr = bytes.fromhex(key_pressed)
        ctx.ttl = 1
        return pkt, ctx
