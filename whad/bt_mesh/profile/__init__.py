"""
Bluetooth Mesh Profile
"""

from whad.bt_mesh.models import Element


class BaseMeshProfile(object):
    def __init__(self):
        # Elements of the Node
        self.__elements = []

        # List of states not bound to a single Model (global ones)
        self.__states = {}

        # Create primary Element
        primary_element = Element(addr=None, element_idx=0, is_primary=True)
        self.__elements[0] = primary_element

        self.__populate_base_models_and_states()

    def __populate_base_models_and_states(self):
        pass
