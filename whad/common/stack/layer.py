class match_source(object):
    """Layer method decorator to perform source matching.

    Source matching can be done on layer name and optionally a tag (some
    user-defined text used to represent a specific state or operation).

    This tag is used to dispatch the incoming data to the correct callback,
    each callback accepting additional named arguments as specified by
    the implementer.
    """

    def __init__(self, source, tag='default'):
        self.__source = source
        self.__tag = tag

    def __call__(self, func):
        """Manage source matching.
        """
        if hasattr(func, 'match_sources'):
            sources = getattr(func, 'match_sources')
            if isinstance(sources, dict):
                if self.__source not in sources:
                    # Add source if not already present
                    sources[self.__source] = [self.__tag]
                elif self.__tag not in sources[self.__source]:
                    sources[self.__source].append(self.__tag)
        else:
            func.match_sources = {self.__source: [self.__tag]}
        return func
    
class layer_alias(object):
    """Layer class decorator to specify layer text alias.
    """

    def __init__(self, name):
        self.__name = name

    def __call__(self, clazz):
        clazz.alias = self.__name
        return clazz


class StackLayer(object):
    """
    Basic stack layer.
    """

    def __init__(self, stack=None, layer_name='', options={}):
        self.__stack = stack
        self.__layer_name = layer_name
        self.__properties = {}

        # Call configure to set up options
        self.configure(options)

    def configure(self, options):
        """Configure callback.

        Override this method to configure the layer when the stack is instanciated.
        """
        pass

    def getprop(self, propname):
        """Get a layer property value based on its name.
        """
        if propname in self.__properties:
            return self.__properties[propname]
        else:
            raise IndexError
        
    def setprop(self, propname, propvalue):
        """Set a layer property value based on its name.
        """
        self.__properties[propname] = propvalue

    def send(self, destination, data, tag='default', **kwargs):
        """Send data/packet to another layer.
        """
        self.__stack.send(self.__layer_name, destination, data, tag=tag, **kwargs)

    def get_layer(self, layer):
        """Retrieve a specific layer instance (object) in order to access methods/properties
        that cannot be reached through default messaging mechanism.
        """
        return self.__stack.get_layer(layer)
    

    def save(self):
        """Return this layer properties dictionnary (saves current state).
        """
        return self.__properties
    
    def load(self, properties):
        """Set this layer properties dictionnary (used to load state).
        """
        self.__properties = properties


class StackEntryLayer(StackLayer):
    """Entry layer is defined as a layer interfaced with the PHY layer. There
    must be only one `ProtocolEntryLayer` defined in a protocol stack.
    """

    def __init__(self, stack=None, layer_name='', options={}):
        super().__init__(stack=stack, layer_name=layer_name, options=options)

    def on_phy(self, data):
        pass

    def send_phy(self, data):
        pass