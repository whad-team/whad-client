"""
Mesh Model Generic classes.
"""

from threading import Lock, Timer


def lock(f):
    """
    Decorator to lock the State

    :param f: [TODO:description]
    :type f: [TODO:type]
    """

    def _wrapper(self, *args, **kwargs):
        self.lock_tx()
        result = f(self, *args, **kwargs)
        self.unlock_tx()
        return result

    return _wrapper


class ModelState(object):
    """
    This class implements a State that will sit in a Server Model.
    Could techically be shared across Models (?)
    """

    def __init__(self, name="myState", default_value=None):
        """
        ModelState init.

        :param name: Name of the State. Used to access it in bound states and in Models
        :type name: str
        :param default_value: In the case of a non composite state, the default_value of the state. Should be None otherwise.
        :type default_value: int, optional, defaults to None
        """

        self.name = name

        # Dictionary to store human readable name of fields to the corresponding value.
        # If only one field state, then only has one value with name "default"
        self.values = {"default": default_value}

        self.__lock = Lock()

        # Dictionary of bound states (name_state -> state)
        # For composite states, STORES THE SUB STATE DIRECTLY
        self.bound_states = {}

    def add_bound_state(self, state):
        self.bound_states[state.name] = state

    def commit_to_bound_states(self):
        """
        Function called when value set to change the value of bound states.
        """
        pass

    @lock
    def __set_state(self, value, name):
        self.values[name] = value
        self.commit_to_bound_states()

    def set_state(self, value, field_name="default", delay=0, transition_time=0):
        """
        Sets the value of a state's field.
        TRANSITION TIME NOT SUPPORTED

        :param value: Value of the sub State
        :type value: Any
        :param field_name: Name of the field witin the State (if there are fields), defaults to "default"
        :type field_name: str, optional
        :param delay: Delay before initiating the set, in ms, defaults to 0
        :type delay: int, optional
        :param transition_time: transition_time to get to the target value, in ms, defaults to 0
        :type transition_time: int, optional
        """
        t = Timer(delay / 1000, self.__set_state, args=[value, field_name])
        t.start()

    def get_state(self, field_name="default"):
        """
        Gets the value of a State.
        Gets the current value of the State, no Lock in place.

        :param field_name: Name of the field for multiple fields State, defaults to "default"
        :type field_name: str, optional
        :returns: Tuple with boolean (True if field exists, False otherwise) and the field Value (None if no value)
        :rtype: (boolean, Any)
        """
        if field_name in self.values.keys():
            return (True, self.values["name"])
        else:
            return (False, None)

    def get_full_state(self):
        """
        Returns the full list of values.
        """
        return self.values


    def remove_state(self, field_name):
        if field_name ==


class CompositeModelState:
    """
    Helper class to group sub states of a composite State
    Should be inherited to create the classes for the actual Compisite States
    """

    def __init__(self, name, sub_states_cls):
        self.name = name

        # Dict of sub states compositing that composite State
        self.sub_states = {}

        for _cls in sub_states_cls:
            state = _cls()
            self.sub_states[state.name] = state

    def get_sub_state(self, name):
        try:
            return self.sub_states[name]
        except Exception:
            return None


class Model(object):
    """
    This class represents a Model defined in SIG Bluetooth spec (no support for vendor specific models yet).
    Should never be used alone (use ModelClient or ModelServer).
    """

    def __init__(self, model_id, element_id):
        self.model_id = model_id

        # belongs the element_idth element
        self.element_id = element_id

        # List of handlers for incoming messages. Opcode -> handler
        self.handlers = {}

        self.subscription_list = None

    def handle_message(self, model_message):
        """
        Handles the received message based on the model handlers

        :param model_message: Message received by the Access layer
        :type model_message: BTMesh_Model_Message
        """
        if model_message.opcode in self.handlers.keys():
            self.handlers[model_message.opcode](model_message)


class ModelServer(Model):
    """
    This class implements a generic Server Model.
    """

    def __init__(self, model_id, element_id, corresponding_group_id=None):
        super().__init__(model_id, element_id)

        # This Server Model States (the ones that directly belong to the model, not extended ones).
        self.states = {}

        # if model part of a corresponding_group, add its id
        self.corresponding_group_id = corresponding_group_id

        # List of ModelRelationships object where this model is the base model (or any model if corresponding rel)
        self.relationships = []

    def add_relationship(self, model_relationship):
        self.relationships.append(model_relationship)


class ModelClient(Model):
    pass


class Element(object):
    """
    This class represents one element of the device. Each element is assigned an address (254 max per device, sub-addr of the Unicast addr of the device).
    """

    def __init__(self, addr, element_idx, is_primary=False):
        """
        Element init. Creates an element and assigns it an address.

        :param addr: Address of the element (unicast addr sub address)
        :type addr: bytes
        :param element_idx: Element index (in the Composition Data Page 1)
        :type element_idx: int
        :param is_primary: Is this element primary (only one per device). True if yes., optional defaults to False
        :type is_primary: boolean
        """

        self.addr = addr

        self.element_idx = element_idx

        self.is_primary = is_primary

        # Number of models in the element
        self.model_count = 0

        # Number of vendor model count. Not used yet.
        self.vnd_model_count = 0

        # location descriptor, not used except in Composition Data
        self.loc = 0

        # List of models in the Element. List of Model objects (ModelClient or ModelServer).
        # Order after init should never change since we use the index to access Models
        self.models = []

        # Dictionary of opcode to model index (in self.models) that refers to the model that handle this message.
        self.opcode_to_model_index = {}

    def register_model(self, model):
        """
        Adds a model to this element. Associate the opcodes allowed in Rx to this model instance.

        :param model: The Model object to add
        :type model: Model
        """

        self.models.append(model)

        model_index = len(self.models) - 1
        model_opcodes = model.handlers.keys()
        already_registered_opcodes = self.opcode_to_model.key()
        for opcode in model_opcodes:
            if opcode not in already_registered_opcodes:
                self.opcode_to_model[opcode] = model_index

    def get_index_of_model(self, model):
        """
        Returns the index of the model (idnex in the self.models list) or None if not in list

        :param model: Model in question
        :type model: Model
        :returns: The index of the Model or None if not found[TODO:type]
        :rtype: int | None
        """
        try:
            return self.models.index(model)
        except ValueError:
            return None


class ModelRelationship(object):
    def __init__(
        self,
        elem_base=None,
        elem_ext=None,
        mod_base=None,
        mod_ext=None,
    ):
        """
        Model Relationship. Registers the extension relationship that a Model has with another
        Check Mesh Prt Spec Section 4.2.2.2

        :param elem_base: Element where the base model lives, defaults to None
        :type elem_base: Element, optional
        :param elem_ext: Element where the model extending the other lives, defaults to None
        :type elem_ext: Element, optional
        :param mod_id_base: Model object of the base model, defaults to None
        :type mod_id_base: Model, optional
        :param mod_id_ext: Model object of the extending model, defaults to None
        :type mod_id_ext: Model, optional
        """
        self.elem_base = elem_base
        self.elem_ext = elem_ext
        self.mod_base = mod_base
        self.mod_ext = mod_ext
