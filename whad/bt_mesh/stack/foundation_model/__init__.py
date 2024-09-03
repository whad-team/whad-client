"""
Foundation Models Layer

Handles all the Foundation Models, dealing with configuration.
"""


import logging
from whad.common.stack import Layer, alias, source
from whad.bt_mesh.stack.utils import MeshMessageContext


logger = logging.getLogger(__name__)


@alias("foundation")
class FoundationModelsLayer(Layer):
    def __init__(self, options={}):
        """
        Foundation Models Layer.
        Handles all the models defined as Foundation Models (Mesh PRT Spec Section 4)
        Is also used locally by other layers to gather device information when needed
        (thus is linked to technically all layers as a Database)
        The foundation models all live in the primary element that lives in the layer

        Other elements with non-foundation models live in the Models layer
        :param options: [TODO:description], defaults to {}
        :type options: [TODO:type], optional
        """
        super().__init__(options=options)
        

