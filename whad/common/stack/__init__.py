import json
from .layer import StackEntryLayer, StackLayer, match_source, layer_alias, layer_state, StackLayerState, LayerRegistry,\
    ContextLayer


class Stack(LayerRegistry):
    """Basic protocol stack class.

    A class contains layers that are declared using the `Stack.layer` decorator
    in the class definition. Each layer has an text alias that is used to send
    data to dedicated callbacks.
    """

    def __init__(self, options={}):
        """Stack instanciation.

        We instanciate each layer and register these instances into our object.
        """
        #super().__init__(options=options)
        self.populate(options=options)
        self.options = options


    def __get_layer_method_by_source(self, layer, source, tag='default'):
        """Find the method associated with a source for a given layer.
        """
        layer = self.get_layer(layer)
        methods = [getattr(layer, prop) for prop in dir(layer) if callable(getattr(layer, prop))]
        for method in methods:
            if hasattr(method, 'match_sources') and isinstance(getattr(method, 'match_sources'), dict):
                match_sources = getattr(method, 'match_sources')
                if source in match_sources:
                    if tag in match_sources[source]:
                        return method
        
        # if tag is not default, try again with 'default'
        for method in methods:
            if hasattr(method, 'match_sources') and isinstance(getattr(method, 'match_sources'), dict):
                match_sources = getattr(method, 'match_sources')
                if source in match_sources:
                    if 'default' in match_sources[source]:
                        return method
        return None

    def send(self, source, destination, data, tag='default', **kwargs):
        """Dispatch data from source to destination, with an optional tag
        and arguments.
        """
        # If no context defined, pick up destination layer in our default layers.
        if destination in self.layers:
            # Look for the layer method associated with the specified source
            method = self.__get_layer_method_by_source(destination, source, tag)
            if method is not None:
                method(data, **kwargs)
            else:
                print('[!] Destination %s does not accept packets from %s with tag %s' % (
                    destination, source, tag
                ))

    def feed(self, data, **kwargs):
        """Dispatch data to entry layer.
        """
        entry_layer = self.get_entry_layer()
        if entry_layer is not None:
            entry_layer.on_phy(data, **kwargs)

    def __getitem__(self, name):
        """Array-like behavior to get a specific layer.
        """
        return self.get_layer(name)

    def get_layer(self, name):
        """Retrieve a specific layer based on its name.
        """
        if name in self.layers:
            return self.layers[name]
        else:
            raise IndexError
    
    def save(self):
        """Save stack state.

        Saving the stack state saves all its layer states in a JSON dictionnary.
        """
        state = {}
        nodes = list(self.layers.keys())
        for name in nodes:
            state[name] = self.layers[name].save()
        return json.dumps(state)
        
    def load(self, saved_state: str):
        """Load previously saved state (JSON).
        """
        state = json.loads(saved_state)
        nodes = list(self.layers.keys())
        for name in nodes:
            self.layers[name].load(state[name])


__all__ = [
    'Stack',
    'StackLayer',
    'StackEntryLayer',
    'match_source',
    'layer_name',
    'layer_state',
    'StackLayerState'
]