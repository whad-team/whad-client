from whad.common.stack import LayerState, ContextualLayer, alias, source, state
from whad.scapy.layers.lorawan import MACPayloadUplink, MACPayloadDownlink

class LWMacLayerState(LayerState):

    def __init__(self):
        super().__init__()

        # Default state
        self.up_frame_counter = 0
        self.down_frame_counter = 0

@alias('mac')
@state(LWMacLayerState)
class LWMacLayer(ContextualLayer):
    
    def configure(self, options):
        # Initialize state
        pass

    def set_devaddr(self, dev_addr : int):
        """Save device address for debugging purpose.

        Set device network address (used for debugging).

        :param dev_addr: Device network address
        :type dev_addr: int
        """
        self.dev_addr = dev_addr

    def set_up_counter(self, value: int):
        """Set device uplink frame counter
        """
        self.state.up_frame_counter = value

    def set_down_counter(self, value : int):
        """Set device downlink frame counter

        :param value: Uplink frame counter value
        :type value: int
        """
        self.state.down_frame_counter = value

    def parse_mac_commands(self, commands : bytes):
        """Parse MAC commands, if any.

        Not supported yet, implementation to come.

        :param commands: MAC commands to process
        :type commands: bytes
        """
        pass

    @source('ll')
    def on_mac_frame(self, mac: MACPayloadUplink, confirmed : bool = False):
        """Handles uplink payload sent by link-layer.

        Payload is in clear as our link-layer has already decrypted and checked it.

        :param mac: MAC frame
        :type mac: MACPayloadUplink
        :param confirmed: uplink frame is from a confirmed uplink
        :type confirmed: bool
        """
        # Update our up frame counter
        self.state.up_frame_counter = mac.fcnt

        # Parse MAC commands from FOpts or payload depending
        # on FPort value.
        if mac.fport == 0:
            self.parse_mac_commands(bytes(mac.payload))
        else:
            if len(mac.fopts) > 0:
                self.parse_mac_commands(mac.fopts)
        
        # Notify data to gateway
        response = self.get_layer('ll').on_data_received(
            self.dev_addr,
            bytes(mac.payload),
            self.state.up_frame_counter
        )

        # Build response if required
        if response is not None:
            resp = MACPayloadDownlink(
                dev_addr = self.dev_addr,
                fcnt = self.state.down_frame_counter,
                fport=8 # data
            )/bytes(response)
            
            self.state.down_frame_counter += 1

            # Send back response to link-layer
            self.send('ll', resp)
        else:
            return None

