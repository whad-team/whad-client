import json
from layer import StackEntryLayer, StackLayer

class Stack(object):
    """Basic protocol stack class.

    A class contains layers that are declared using the `Stack.layer` decorator
    in the class definition. Each layer has an text alias that is used to send
    data to dedicated callbacks.
    """

    LAYERS = {}

    @staticmethod
    def layer(clazz):
        """Add a layer class into the stack layer registry.
        """
        if hasattr(clazz, 'alias'):
            if clazz.alias in Stack.LAYERS:
                Stack.LAYERS[clazz.alias] = clazz
            else:
                Stack.LAYERS[clazz.alias] = clazz

    def __init__(self, options={}):
        """Stack instanciation.

        We instanciate each layer and register these instances into our object.
        """
        self.__layers = {}
        for layer in Stack.LAYERS.keys():
            layer_options = options[layer] if layer in options else {}
            self.__layers[layer] = Stack.LAYERS[layer](self, layer, layer_options)

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
    
    @staticmethod
    def get_layer_sources(layer):
        sources = []
        layer = Stack.LAYERS[layer]

        methods = [getattr(layer, prop) for prop in dir(layer) if callable(getattr(layer, prop))]
        for method in methods:
            if hasattr(method, 'match_sources') and isinstance(getattr(method, 'match_sources'), dict):
                match_sources = getattr(method, 'match_sources')
                for _source in match_sources:
                    if _source not in sources:
                        sources.append(_source)
        return sources

    def send(self, source, destination, data, tag='default', **kwargs):
        """Dispatch data from source to destination, with an optional tag
        and arguments.
        """
        if destination in self.__layers:
            # Look for the layer method associated with the specified source
            method = self.__get_layer_method_by_source(destination, source, tag)
            if method is not None:
                method(data, **kwargs)
            else:
                print('[!] Destination %s does not accept packets from %s with tag %s' % (
                    destination, source, tag
                ))

    def feed(self, data):
        """Dispatch data to entry layer.
        """
        entry_layer = self.get_entry_layer()
        if entry_layer is not None:
            entry_layer.on_phy(data)

    def __getitem__(self, name):
        """Array-like behavior to get a specific layer.
        """
        return self.get_layer(name)

    def get_layer(self, name):
        """Retrieve a specific layer based on its name.
        """
        if name in self.__layers:
            return self.__layers[name]
        else:
            raise IndexError
        
    def get_entry_layer(self):
        """Find our entry layer.
        """
        for clazz in self.__layers.values():
            if isinstance(clazz, StackEntryLayer):
                return clazz
        return None

    def save(self):
        """Save stack state.

        Saving the stack state saves all its layer states in a JSON dictionnary.
        """
        state = {}
        nodes = list(self.__layers.keys())
        for name in nodes:
            state[name] = self.__layers[name].save()
        return json.dumps(state)
        
    def load(self, saved_state: str):
        """Load previously saved state (JSON).
        """
        state = json.loads(saved_state)
        nodes = list(self.__layers.keys())
        for name in nodes:
            self.__layers[name].load(state[name])

    @staticmethod
    def export(gv_file):
        """Export our stack model to a grahpviz graph file
        """
        # Build nodes
        nodes = list(Stack.LAYERS.keys())

        # First we need to collect all the interactions
        links = []
        for node_name in nodes:
            sources = Stack.get_layer_sources(node_name)
            for source in sources:
                links.append((source, node_name))
        
        # Then we create our ghrapviz file
        output = 'digraph finite_state_machine {\n'
        output += 'rankdir=LR;\n'

        # We add our nodes
        for node_name in nodes:
            if issubclass(Stack.LAYERS[node_name], StackEntryLayer):
                shape = 'doublecircle'
            else:
                shape = 'circle'    
            output += 'node [shape = %s, label="%s", fontsize=12] %s;\n' % (
                shape,
                node_name,
                node_name
            )

        # We then add our links
        for src,dst in links:
            output += '%s -> %s;\n' % (src, dst)
        
        output += '}'

        open(gv_file,'w').write(output)

__all__ = [
    'Stack',
    'StackLayer',
    'StackEntryLayer'
]