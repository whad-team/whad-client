"""
Lower Transport Layer

Handles Segmentation/Reassembly of Upper Transport PDU
"""

import logging
from whad.common.stack import Layer, alias, source
from whad.bt_mesh.stack.utils import MeshMessageContext


logger = logging.getLogger(__name__)


@alias("lower_transport")
class LowerTransportLayer(Layer):
    def __init__(self, options={}):
        """
        LowerTransport Layer.

        :param options: [TODO:description], defaults to {}
        :type options: [TODO:type], optional
        """
        super().__init__(options=options)


    @source("network")
    def on_network_layer_message(self, message):
        msg_ctx, lower_transport_pdu = message


