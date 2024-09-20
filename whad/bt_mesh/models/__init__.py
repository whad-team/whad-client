"""
Mesh Model Generic classes.
"""

from threading import Lock, Timer
from whad.scapy.layers.bt_mesh import BTMesh_Model_Message
from whad.bt_mesh.crypto import compute_virtual_addr_from_label_uuid
from whad.bt_mesh.stack.utils import MeshMessageContext


class ModelState(object):
    """
    This class implements a State that will sit in a Server Model.
    Could techically be shared across Models (?)

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

        self.name = name

        # Dictionary to store human readable name of fields to the corresponding value.
        # If only one field state, then only has one value with name "default"
        self.values = {"default": default_value}

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
        return self.values.values()

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
    Should be inherited to create the classes for the actual Compisite States
    """

    def __init__(self, name, sub_states_cls):
        """
        Creates a CompositeModelState composed of multiple ModelStates classes
        that will be automatically instanced

        :param name: Name of the composite state
        :type name: str
        :param sub_states_cls: List of the classes of the sub states
        :type sub_states_cls: Any
        """
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


class GlobalStatesManager(metaclass=SingletonMeta):
    """
    This class manages ALL the states that live in the node
    Need to access them in the different layers of the protocol
    OR in the Configuration Server Model

    ALSO MANAGES THE IV_INDEX ! (not an official state but its included here)
    """

    def __init__(self):
        # Key is a tuple of (state.name, element_addr, model_id, net_key_index) based
        # on the bindings of the state
        # Field is the state that corresponds to this combination
        # For composite models, only the CompositeModelState object is stored (we access the sub state from it)
        self.states = {}

        # address of primary element, used as an offset for the others
        self.primary_element_addr = 0

        self.iv_index = b"\x00\x00\x00\x00"

        # Sequence number of the device for the iv_index
        # used by basically every layer ...
        self.__seq_number = 0

        # lock to access the seq_number
        self.__seq_lock = Lock()

    def lock_seq(self):
        self.__seq_lock.acquire()

    def unlock_seq(self):
        self._seq_lock.release()

    def set_primary_element_addr(self, primary_element_addr):
        self.primary_element_addr = primary_element_addr

    def add_state(self, state, element_addr=None, model_id=None, net_key_index=None):
        """
        Adds the state to the list

        A state can be bound to :

        - Nothing (global, one instance per device, for Configuration usually)
        - A model_id and in an element (model_id and element_addr)
        - A subnet (.i.e a net_key_index)

        Can be bound to model, element and a subnet at the same time !

        There should be only ONE state per combination of values
        And each type of state should always have the same parameters (if StateA is bound to net_key_index only, then all instances must have a different net_key_index and the reste to None)

        :param state: State to Add
        :type state: State | CompositeModelState
        :param element_addr: Element_addr of the model that holds this state, defaults to None
        :type element_addr: int, optional
        :param model_id: model_id of the model that holds this state, defaults to None
        :type model_id: int, optional
        :param net_key_index: net_key_index of the subnet of the state, defaults to None
        :type net_key_index: int, optional
        """
        self.states[
            (
                state.name,
                element_addr,
                model_id,
                net_key_index,
            )
        ] = state

    def get_state(
        self, state_name, element_addr=None, model_id=None, net_key_index=None
    ):
        """
        Retrives the state that corresponds to the given argument.
        Only one state can correspond to one combionation, otherwise logic problem

        :param state_name: Name of the State
        :type state_name: str
        :param element_addr: addr of the element where the model that hold the state lives, defaults to None
        :type element_addr: int, optional
        :param model_id: model id of the model that holds the state, defaults to None
        :type model_id: int, optional
        :param net_key_index: index of the NetKey associated with the subnet that uses this state, defaults to None
        :type net_key_index: int, optional
        """
        if (state_name, element_addr, model_id, net_key_index) in self.states.keys():
            return self.states[(state_name, element_addr, model_id, net_key_index)]
        else:
            return None

    def get_all_states(self, state_name):
        """
        Retrives the list of states that correspond to one State type (based on its name)

        :param state_name: Name of the state type
        :type state_name: str
        """
        return [state for key, state in self.states.items() if key[0] == state_name]

    @lock
    def get_next_seq_number(self):
        seq = self.__seq_number
        self.__seq_number += 1
        return seq


class Model(object):
    """
    This class represents a Model defined in SIG Bluetooth spec (no support for vendor specific models yet).
    Should never be used alone (use ModelClient or ModelServer).
    """

    def __init__(self, model_id, element_addr):
        self.model_id = model_id

        # belongs the element with this addr
        self.element_addr = element_addr

        # List of handlers for incoming messages. Opcode -> handler
        self.handlers = {}

        self.supports_subscribe = False

    def handle_message(self, model_message):
        """
        Handles the received message based on the model handlers

        :param model_message: Message received by the Access layer
        :type model_message: BTMesh_Model_Message
        """
        print("RECEIVED")
        model_message.show()
        if model_message.opcode in self.handlers.keys():
            response = self.handlers[model_message.opcode](model_message[1])
            print("RESPONSE")
            response = BTMesh_Model_Message() / response
            response.show()
            return response
        return None


class ModelServer(Model):
    """
    This class implements a generic Server Model.
    """

    def __init__(self, model_id, element_addr, corresponding_group_id=None):
        super().__init__(model_id, element_addr)

        # if model part of a corresponding_group, add its id
        self.corresponding_group_id = corresponding_group_id

        # List of ModelRelationships object where this model is the base model (or any model if corresponding rel)
        self.relationships = []

        # instance of singleton of GlobalStatesManager
        self.global_states_manager = GlobalStatesManager()

    def add_relationship(self, model_relationship):
        self.relationships.append(model_relationship)


class ModelClient(Model):
    pass


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

        # location descriptor, not used except in Composition Data
        self.loc = 0

        # List of models in the Element. List of Model objects (ModelClient or ModelServer).
        # Order after init should never change since we use the index to access Models
        self.models = []

        # Dictionary of opcode to model index (in self.models) that refers to the model that handle this message.
        self.opcode_to_model_index = {}

        self.global_states_manager = GlobalStatesManager()

    def register_model(self, model):
        """
        Adds a model to this element. Associate the opcodes allowed in Rx to this model instance.

        :param model: The Model object to add
        :type model: Model
        """

        self.models.append(model)

        model_index = len(self.models) - 1
        model_opcodes = model.handlers.keys()
        already_registered_opcodes = self.opcode_to_model_index.keys()
        for opcode in model_opcodes:
            if opcode not in already_registered_opcodes:
                self.opcode_to_model_index[opcode] = model_index

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

    def handle_message(self, message):
        """
        Handles the message received from the Access Layer

        :param message: Message received with its context
        :type message: (BTMesh_Model_Message, MeshMessageContext)
        """
        pkt, ctx = message
        opcode = pkt.opcode
        try:
            model = self.models[self.opcode_to_model_index[opcode]]

            # check if app_key used is bound to the model
            app_key_indexes = self.global_states_manager.get_state(
                "model_to_app_key_list"
            ).get_value(model.model_id)

            # if dev_key used, index is -1 ! (dont forget to add it when creating the model ...)
            if ctx.application_key_id not in app_key_indexes:
                raise Exception
            return model.handle_message(pkt)
        except Exception:
            print("ouch, too lazy to code the error handling")
            return None

    def check_group_subscription(self, addr):
        """
        Checks if any model in the element is subscribed to the addr in parameter
        THE ADDR IS A GROUP ADDR IN THIS FUNCTION

        :param addr: Group Addr to check
        :type addr: Bytes
        :returns: True is one model in the Element is subscribed to the addr, False otherwise
        """
        res = False
        for model in self.models:
            sub_list = self.global_states_manager.get_state(
                "subscription_list", element_addr=self.addr, model_id=model.model_id
            ).get_value("group_addrs")
            if addr in sub_list:
                res = True
                break
        return res

    def check_virt_subscription(self, addr):
        """
        Checks if any model in the element is subscribed to the addr in parameter
        THE ADDR IS A VIRTUAL ADDR IN THIS FUNCTION

        :param addr: Virtual Addr to check
        :type addr: Bytes
        :returns: True is one model in the Element is subscribed to the addr, False otherwise
        """
        res = False
        for model in self.models:
            sub_list = self.global_states_manager.get_state(
                "subscription_list", element_addr=self.addr, model_id=model.model_id
            ).get_value("label_uuids")
            for label in sub_list:
                if compute_virtual_addr_from_label_uuid(label) == addr:
                    res = True
                    break
        return res


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
