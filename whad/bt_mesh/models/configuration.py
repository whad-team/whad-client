"""
Implementation of the Confiruation Server And Client Models
Mesh Protocol Specificiation Section 4.4.1 and 4.4.2
"""

from whad.bt_mesh.models import (
    ModelServer,
    ModelState,
    Element,
    ModelRelationship,
    ModelClient,
)

# Mesh PRT Spec Table 4.10 Section 4.2.2.2
_FIELD_VALUE_TO_ELEMENT_OFFSET = {0: 0, 1: 1, 2: 2, 3: 3, 4: -4, 5: -3, 6: -2, 7: -1}
_ELEMENT_OFFSET_TO_FIELD_VALUE = {
    v: k for k, v in _FIELD_VALUE_TO_ELEMENT_OFFSET.items()
}


class CompositionDataState(object):
    """
    Composition Data state containing the page 0 and page 1 only (for now)
    Should be initialised ONCE and never change until term of node.
    One per sub network (for now not supported)
    """

    def __init__(self):
        pass

    def init_page0(self, cid, pid, vid, crpl, features, elements: list[Element]):
        """
        Initializes the Page 0 of the Comosition Data State.
        Mesh PRT Specificiation Section 4.2.2.1

        :param cid: Company Identifier (2 bytes)
        :type cid: bytes
        :param pid: Product Identifier (2 bytes)
        :type pid: bytes
        :param vid: Vendor assigned product software version Identifier (2 bytes)
        :type vid: bytes
        :param crpl: Minimum number of Replay Protection List entries
        :type crpl: int
        :param features: Bit field of devices features (Mesh PRT spec Section Table 4.3)
        :type features: bytesœ&
        :param elements: List of elements that live on the network
        :type elements: List[Elements]
        """
        # we compute the bytes object of the page to use in the scapy packet directly since it doesnt change
        self.p0_data = cid + pid + vid + crpl + features

        elements_field = b""
        for element in elements:
            self.elements_fields = (
                elements_field
                + element.loc.to_bytes(2, "big")
                + element.model_count.to_bytes(1)
                + element.vnd_model_count.to_bytes(1)
            )
            for model_id in element.models.keys():
                self.elements_fields = elements_field + model_id
            # no vendor models yet so nothing

        self.p0_data = self.p0_data + elements_field

    def get_p0_data(self):
        return self.p0_data

    def __p1_add_model(self, model, fmt):
        """
        Returns the model data for the Composition Page 1
        Mesh PRT Spec Section 4.2.2.2 Table 4.9/4.11

        :param model: Model to add
        :type model: Model
        :param fmt: Format value to use
        :type fmt: int
        """

        if not isinstance(model, ModelServer):
            return int(0).to_bytes(1, "big")
        else:
            model_data = (
                (len(model.relationships) << 2)
                + (fmt << 1)
                + int(model.corresponding_group_id is not None)
            ).to_bytes(1, "big")
            if model.corresponding_group_id is not None:
                model_data += model.corresponding_group_id.to_bytes(1, "big")

            for rel in model.relationships:
                if fmt == 0:
                    offset = _ELEMENT_OFFSET_TO_FIELD_VALUE[
                        rel.elem_ext.element_idx - rel.elem_base.element_idx
                    ]
                    model_data += (
                        (rel.elem_ext.get_index_of_model(rel.mod_ext) << 3)
                        + (offset & 0x07)
                    ).to_bytes(1, "big")
                else:
                    offset = rel.elem_ext.element_idx - rel.elem_base.element_idx
                    model_data = offset.to_bytes(
                        1, "big", signed=True
                    ) + rel.elem_ext.get_index_of_model(rel.mod_ext).to_bytes(1, "big")

                return model_data

    def init_page1(self, elements: list[Element]):
        """
        Inits the Page 1 of the CompositionData State.
        Mesh PRT Spec Section 4.2.2.2

        :param elements: List of elements on the network (in order !!)
        :type elements: List[Elements]
        :param model_relationships: All the model model_relationships on the network
        :type model_relationships: List(ModelRelationship)
        """

        self.p1_data = b""
        # depending on the number of elements, we dont use the same format in model data
        # Mesh PRT Spec Section 4.2.2.2 Table 4.9 or 4.11 (should create a scapy packet)

        if len(elements) > 4:
            fmt = 1
        else:
            fmt = 0

        for element in elements:
            element_data = b""
            element_data = element.model_count.to_bytes(
                1
            ) + element.vnd_model_count.to_bytes(1)

            for model in element.models.values():
                element_data += self.__p1_add_model(model, fmt)

            self.p1_data += element_data

    def get_p1_data(self):
        return self.p1_data


class ConfigurationModelServer(ModelServer):
    def __init__(self):
        super(ModelServer, self).__init__(model_id=0x0000)

        self.handlers[0x00] = self.on_config_app_key_add

        # Set it by hand when configured entirely
        self.states["composition_data"] = None


        self.states[""]

    def on_config_app_key_add(self, message):
        message.show()
