"""
Mesh Model Generic classes.
"""

import logging
from threading import Lock, Timer
from whad.scapy.layers.btmesh import BTMesh_Model_Message
from whad.btmesh.crypto import compute_virtual_addr_from_label_uuid


logger = logging.getLogger(__name__)


class ModelState(object):
    """
    This class implements a State that will sit in a Server Model or Subnet.

    Is inherited by actual states implementations
    """

    def __init__(self, name="myState", default_value=None):
        """
        ModelState init.
        No lock mechanism since Access layer should maange only ONE MESSAGE AT A TIME

        :param name: Name of the State. Used to access it in bound states and in Models
        :type name: str
        :param default_value: In the case of a non composite state, the default_value of the state. Should be None otherwise.
        :type default_value: int, optional, defaults to None
        """

        self.__name = name

        # Dictionary to store human readable name of fields to the corresponding value.
        # If only one field state, then only has one value with name "default"
        self.values = {"default": default_value}

        # Dictionary of bound states (name_state -> state)
        # For composite states, STORES THE SUB STATE DIRECTLY
        self.bound_states = {}

    @property
    def name(self):
        return self.__name

    def add_bound_state(self, state):
        self.bound_states[state.name] = state

    def commit_to_bound_states(self):
        """
        Function called when value set to change the value of bound states.
        """
        pass

    def __set_value(self, value, name):
        self.values[name] = value
        self.commit_to_bound_states()

    def set_value(self, value, field_name="default", delay=0, transition_time=0):
        """
        Sets the value of a state's field.
        TRANSITION TIME NOT SUPPORTED

        :param value: Value of the sub State
        :type value: Any
        :param field_name: Name of the field witin the State (if there are fields), defaults to "default"
        :type field_name: optional
        :param delay: Delay before initiating the set, in ms, defaults to 0
        :type delay: int, optional
        :param transition_time: transition_time to get to the target value, in ms, defaults to 0
        :type transition_time: int, optional
        """
        t = Timer(delay / 1000, self.__set_value, args=[value, field_name])
        t.start()

    def remove_value(self, field_name):
        """
        Removes the value with field_name from this state and returns it.
        None if the field_name doesnt exist in this state

        :param field_name: The value's field_name to remove
        :type field_name: int
        :returns: The value removed or None if not found
        :rtype: Any
        """
        if field_name in self.values.keys():
            return self.values.pop(field_name)
        else:
            return None

    def get_value(self, field_name="default"):
        """
        Gets the value of a State.
        Gets the current value of the State, no Lock in place.

        :param field_name: Name of the field for multiple fields State, defaults to "default"
        :type field_name: str, optional
        :returns: Return Field value, None if doesnt exist
        """
        if field_name in self.values.keys():
            return self.values[field_name]
        else:
            return None

    def get_all_values(self):
        """
        Returns the full list of values.
        """
        values = list(self.values.values())
        values.remove(
            None
        )  # remove default value if it is None (no state should have None value)
        return values

    def remove_value(self, field_name="default"):
        """
        Removes the State from the values dictionary

        :param field_name: Field name to remove
        :type field_name: Any
        :returns: The removed State or None if doesnt exist
        """
        if field_name in self.values.keys():
            return self.values.pop(field_name)
        else:
            return None


class CompositeModelState:
    """
    Helper class to group sub states of a composite State
    Should be inherited to create the classes for the actual Compisite State

    """

    def __init__(self, name, sub_states_cls):
        """
        Creates a CompositeModelState composed of multiple ModelStates classes
        that will be automatically instanced

        :param name: Name of the composite state
        :type name: str
        :param sub_states_cls: List of the classes of the sub states
        :type sub_states_cls: Any
        :param net_key_index: If state bound to a subnet, net_key_index of the subnet, defaults to None
        :type net_key_index: int, optional
        """
        self.__name = name

        # Dict of sub states compositing that composite State
        self.sub_states = {}

        for _cls in sub_states_cls:
            state = _cls()
            self.sub_states[state.name] = state

    @property
    def name(self):
        return self.__name

    def get_sub_state(self, name):
        try:
            return self.sub_states[name]
        except Exception:
            return None

    def get_all_sub_states(self):
        """
        Returns a list of all the sub states of the CompositeModelState

        :returns: A list of the the substates of the object
        :rtype: List(ModelState)
        """
        return list(self.sub_states.values())


# metaclass to implemenet Singleton
class SingletonMeta(type):
    _instances = {}

    def __call__(cls, *args, **kwargs):
        if cls not in cls._instances:
            instance = super().__call__(*args, **kwargs)
            cls._instances[cls] = instance
        return cls._instances[cls]


def lock(f):
    """
    Decorator to lock the seq_number

    :param f: [TODO:description]
    :type f: [TODO:type]
    """

    def _wrapper(self, *args, **kwargs):
        self.lock_seq()
        result = f(self, *args, **kwargs)
        self.unlock_seq()
        return result

    return _wrapper


class StatesManager:
    """
    Parent class for objects that manage states. (Subnet and ModelServer).
    """

    def __init__(self):
        # States bound to this model. Field Name is the name of the State, value is a ModelState object
        self.states = {}

    def __init_states(self):
        """
        Initializes the states of the object (for models, the ones that belong to the model/subnet directly, not the ones of the base models)
        Called in init
        """
        pass

    def add_state(self, state):
        """
        Adds the state to the list, bound to the object instance

        :param state: State to Add
        :type state: State | CompositeModelState
        """
        self.states[state.name] = state

    def get_state(self, state_name):
        """
        Retrieves the state object that corresponds to the given name.

        :param state_name: Name of the ModelState
        :type state_name: str
        :returns: The state corrsponding to the name on the model. Searches for states in parent models if not found on this one. None if not found
        :rtype: ModelState | CompositeModelState | None
        """
        if (state_name) in self.states.keys():
            return self.states[state_name]
        else:
            for rel in self.relationships:
                # only check base models that this model extends ...
                if rel.mod_ext.model_id == self.model_id:
                    state = rel.mod_ext.get_state(state_name)
                    if state is not None:
                        return state
            return None

    def get_all_states(self):
        """
        Return a list of all ModelState and CompositeModelState of the object

        :returns: List of the states of the object
        :rtype: List(ModelState|CompositeModelState)
        """
        return list(self.states.values())


class Model(object):
    """
    This class represents a Model defined in SIG Bluetooth spec (no support for vendor specific models yet).
    Should never be used alone (use ModelClient or ModelServer).
    """

    def __init__(self, model_id, name):
        self.model_id = model_id

        self.name = name

        # belongs the element at index n (set automatically by the element when model registered)
        self.element_index = None

        # List of handlers for incoming messages. Opcode -> handler
        self.handlers = {}

        # If set to true, need to add corresponding state subscription_list
        self.supports_subscribe = False

        # If this attribute if True, Model will allows sending/receiving with DevKey
        # If Server model, only with our own DevKey. If Client Model, with any DevKey we have
        self.allows_dev_keys = False

    def handle_message(self, message):
        """
        Handles the received message based on the model handlers

        :param message: Message received by the Access layer
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        pkt, ctx = message
        if pkt.opcode in self.handlers.keys():
            response = self.handlers[pkt.opcode]((pkt[1], ctx))
            if response is not None:
                response = BTMesh_Model_Message() / response
            return response
        return None


class ModelServer(StatesManager, Model):
    """
    This class implements a generic Server Model.
    """

    def __init__(self, model_id, name, corresponding_group_id=None):
        super().__init__()
        super(StatesManager, self).__init__(model_id, name)

        # if model part of a corresponding_group, add its id
        self.corresponding_group_id = corresponding_group_id

        # List of ModelRelationships object where this model is the base model (or any model if corresponding rel)
        self.relationships = []

        # Handlers for each type of Access pdus supported by the Model. take as an argument
        self.handlers = {}

    def add_relationship(self, model_relationship):
        self.relationships.append(model_relationship)


class ModelClient(Model):
    def __init__(self, model_id, name):
        super().__init__(model_id, name)

    def handle_user_input(self, key_pressed=""):
        """
        Handle a user key press to use the Client Model to send a message
        (WIP, hardcoded behaviour for tests)

        For now, one key press = one model CLient does one particular thing

        :param key_pressed: The key pressed (if useful ?)
        :type key_pressed: str
        """
        logger.debug("KEY PRESS FOR MODELCLIENT")
        pkt, ctx = self.registered_function_on_keypress(key_pressed)
        return pkt, ctx

    def registered_function_on_keypress(self, key_pressed):
        """
        Function to be overwritten if we send a message on user keypress

        :param key_pressed: [TODO:description]
        :type key_pressed: [TODO:type]
        """
        logger.warn("NO HANDLER FOR MODELCLIENT ON KEYPRESS")
        return None


class Element(object):
    """
    This class represents one element of the device. Each element is assigned an address (254 max per device, sub-addr of the Unicast addr of the device).
    """

    def __init__(self, index, is_primary=False):
        """
        Element init. Creates an element and assigns it an address.

        :param index: Index of the element (in the profile). If index is 1, then its address is primary_unicast_addr + 1
        :type addr: int
        :param is_primary: Is this element primary (only one per device). True if yes., optional defaults to False
        :type is_primary: boolean
        """

        self.is_primary = is_primary

        # Number of models in the element
        self.model_count = 0

        self.index = index

        # Number of vendor model count. Not used yet.
        self.vnd_model_count = 0

        # location descriptor, not used except in Composition Data
        self.loc = 0

        # List of models in the Element. List of Model objects (ModelClient or ModelServer).
        # Order after init should never change since we use the index to access Models
        self.models = []

        # Dictionary of opcode to model index (in self.models) that refers to the model that handle this message.
        self.opcode_to_model_index = {}

        # index of model registred to send a message on key press
        self.keypress_model = None

    def register_model(self, model, is_keypress_model=False):
        """
        Adds a model to this element. Associate the opcodes allowed in Rx to this model instance.

        :param model: The Model object to add
        :type model: Model
        :param is_keypress_model: True if the model is the one registered to send messages on key_press
        """

        # Set the element_index of the model
        model.element_index = self.index

        self.models.append(model)

        # Register the opcodes supported in reception by the model
        model_index = len(self.models) - 1
        model_opcodes = model.handlers.keys()
        already_registered_opcodes = self.opcode_to_model_index.keys()
        self.model_count = len(self.models)
        for opcode in model_opcodes:
            if opcode not in already_registered_opcodes:
                self.opcode_to_model_index[opcode] = model_index

        if is_keypress_model:
            self.keypress_model = model_index

    def get_index_of_model(self, model):
        """
        Returns the index of the model (index in the self.models list) or None if not in list

        :param model: Model in question
        :type model: Model
        :returns: The index of the Model or None if not found[TODO:type]
        :rtype: int | None
        """
        try:
            return self.models.index(model)
        except ValueError:
            return None

    def get_model_by_id(self, model_id):
        """
        Returns the model with the model id in argument that lives in the Element

        :param model_id: Model ID of the model searched
        :type model_id: int
        :returns: The model associated with the model id
        :rtype: Model | None
        """
        for model in self.models:
            if model.model_id == model_id:
                return model
        return None

    def get_model_for_opcode(self, opcode):
        """
        For a received message with an opocode, returns the model in the Element that managed it (if any)

        :param opcode: The opcode of the Access message
        :type opcode: int | None
        :returns: The model instance that will handle the message. None if no model to handle the message
        :rtype: Model | None
        """
        if opcode not in self.opcode_to_model_index:
            logger.debug(
                "NO MODEL IN ELEMENT "
                + str(self.index)
                + " CAN HANDLE OPCODE "
                + str(opcode)
            )
            return None

        return self.models[self.opcode_to_model_index[opcode]]

    """
    def handle_message(self, message):
        pkt, ctx = message
        opcode = pkt.opcode
        if opcode not in self.opcode_to_model_index:
            logger.debug(
                "NO MODEL IN ELEMENT "
                + str(self.index)
                + " CAN HANDLE OPCODE "
                + str(opcode)
            )
            logger.debug(pkt.show(dump=True))
            return None

        model = self.models[self.opcode_to_model_index[opcode]]

        # check if app_key used is bound to the model
        app_key_indexes = self.global_states_manager.get_state(
            "model_to_app_key_list"
        ).get_value(model.model_id)

        # if dev_key used, index is -1 ! (dont forget to add it when creating the model ...)
        if ctx.application_key_index not in app_key_indexes:
            raise Exception
        resp_pkt, resp_ctx = model.handle_message(message)
        resp_ctx.src_addr = self.index
        return (resp_pkt, resp_ctx)
        """

    def check_group_subscription(self, addr):
        """
        Checks if any model server in the element is subscribed to the addr in parameter
        THE ADDR IS A GROUP ADDR IN THIS FUNCTION

        :param addr: Group Addr to check
        :type addr: Bytes
        :returns: True is one model in the Element is subscribed to the addr, False otherwise
        """
        res = False
        for model in self.models:
            if isinstance(model, ModelServer) and model.supports_subscribe:
                sub_list = model.get_state("subscription_list").get_value("group_addrs")
                if addr in sub_list:
                    res = True
                    break
        return res

    def check_virt_subscription(self, addr):
        """
        Checks if any model server in the element is subscribed to the addr in parameter
        THE ADDR IS A VIRTUAL ADDR IN THIS FUNCTION

        :param addr: Virtual Addr to check
        :type addr: Bytes
        :returns: True is one model in the Element is subscribed to the addr, False otherwise
        """
        res = False
        for model in self.models:
            if isinstance(model, ModelServer) and model.supports_subscribe:
                sub_list = model.get_state("subscription_list").get_value("label_uuids")
                for label in sub_list:
                    if compute_virtual_addr_from_label_uuid(label) == addr:
                        res = True
                        break
        return res

    def handle_user_input(self, key_pressed=""):
        """
        Process a keypressed message from the user to send a message from a ModelClient

        :param key_pressed: [TODO:description]
        :type key_pressed: [TODO:type]
        """
        if self.keypress_model is None:
            return
        model = self.models[self.keypress_model]
        pkt, ctx = model.handle_user_input(key_pressed)
        app_key_index = self.global_states_manager.get_state(
            "model_to_app_key_list"
        ).get_value(model.model_id)[0]
        ctx.application_key_index = app_key_index
        aid = (
            self.global_states_manager.get_state("app_key_list")
            .get_value(app_key_index)
            .aid
        )
        ctx.aid = aid
        ctx.net_key_id = 0
        return BTMesh_Model_Message() / pkt, ctx


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
        The ModelRelationship object shoukd live in the extending moddel (the "child") only.
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
