"""
Mesh Model Generic classes.
"""

class State(object):
    """
    This class implements a State that will sit in a Server Model.
    Could techically be shared across Models (?)
    Composite states also use this class
    """

    def __init__(self, default_value=None):
        """
        State init.

        :param default_value: In the cas of a non composite state, the default_value of the state. Should be None otherwise.
        :type default_value: int, optional
        """

        # Stores each value of this state. A non composite state will only have one value.
        # Composite states will have the substates live here as simple values
        self.values = []

        # Dictionary to store human readable name of substates to the corresponding index in the values list.
        # Ex : "PUBLISH_ADDRESS" -> 0x00 if PUBLISH_ADDRESS sub_state is at index 0
        # Non composite states will only use the index 0 of the list
        self.correlation_table = {"NON-COMPOSITE-STATE-VALUE": 0}

        if default_value is not None:
            self.values[0] = default_value


class Model(object):
    """
    This class represents a Model defined in SIG Bluetooth spec (no support for vendor specific models yet).
    Should never be used alone (use ModelClient or ModelServer).
    """

    def __init__(self, model_id):
        self.model_id = model_id

        # List of handlers for incoming messages. Opcode -> handler
        self.handlers = {}

    def handle_message(self, model_message):
        """
        Handles the received message based on the model handlers

        :param model_message: Message received by the Access layer
        :type model_message: BTMesh_Model_Message
        """
        if model_message.opcode in self.handlers.keys():
            self.handlers[model_message.opcode]()

class ModelServer(Model):
    """
    This class implements a generic Server Model.
    """

    def __init__(self, model_id):
        super().__init__(model_id)

        # This Server Model States. 
        self.states = {}


class Element(object):
    """
    This class represents one element of the device. Each element is assigned an address (254 max per device, sub-addr of the Unicast addr of the device).
    """

    def __init__(self, addr, is_primary=False):
        """
        Element init. Creates an element and assigns it an address.

        :param addr: Address of the element (unicast addr sub address)
        :type addr: bytes
        :param is_primary: Is this element primary (only one per device). True if yes., optional defaults to False
        :type is_primary: boolean
        """

        self.addr = addr
        self.is_primary = is_primary

        # Number of models in the element
        self.model_count = 0

        # Number of vendor model count. Not used yet.
        self.vnd_model_count = 0

        # List of models in the Element. List of Model objects (ModelClient or ModelServer).
        # model_id -> Model Object
        self.models = {}

        # Dictionary of opcode to model that handle this message.
        self.opcode_to_model = {}

    def register_model(self, model):
        """
        Adds a model to this element. Associate the opcodes allowed in Rx to this model instance.

        :param model: The Model object to add
        :type model: Model
        """
        if model.model_id not in self.models.keys():
            self.models[model.model_id] = model

        model_opcodes = model.handlers.keys()
        already_registered_opcodes = self.opcode_to_model.key()
        for opcode in model_opcodes:
            if opcode not in already_registered_opcodes:
                self.opcode_to_model[opcode] = model
