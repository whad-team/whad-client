"""
Implementation of the Health Server And Client Models
Mesh Protocol Specificiation Section 4.4.3 and 4.4.4
"""



from whad.bt_mesh.models import (
    ModelServer,
    Element,
)


from whad.scapy.layers.bt_mesh import *



class HealthModelServer(ModelServer):
    def __init__(self, element_addr):
        super().__init__(model_id=0x0002, element_addr=element_addr)
