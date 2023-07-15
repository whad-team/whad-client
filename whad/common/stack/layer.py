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

class layer_state(object):
    def __init__(self, state_class):
        self.__state_class = state_class

    def __call__(self, clazz):
        clazz.state_class = self.__state_class
        return clazz

class LayerRegistry(object):

    @classmethod
    def layer(cls, clazz):
        """Add a layer class into the stack layer registry.
        """
        # First we inject a LAYERS attribute into the class
        layers_prop_name = 'LAYERS'
        if not hasattr(cls, layers_prop_name):
            setattr(cls, layers_prop_name, {})
        class_layers = getattr(cls, layers_prop_name)

        # Register a layer based on its alias
        if hasattr(clazz, 'alias'):
            if clazz.alias in cls.LAYERS:
                cls.LAYERS[clazz.alias] = clazz
            else:
                cls.LAYERS[clazz.alias] = clazz

class StackLayerState(object):
    """Stack layer state database

    Define fields names in FIELDS.
    """

    FIELDS = []

    def __init__(self):
        """Populate database.
        """
        self.__db = {}

    def __getattr__(self, property):
        if property in self.__db:
            return self.__db[property]
        else:
            raise AttributeError
        
    def __setattr__(self, property, value):
        if property.startswith('_'):
            super(StackLayerState, self).__setattr__(property, value)
        elif property in self.FIELDS:
            self.__db[property] = value
        else:
            raise AttributeError
            

    def to_dict(self):
        return self.__db

@layer_state(StackLayerState)
class StackLayer(object):
    """
    Basic stack layer.
    """

    def __init__(self, stack=None, layer_name='', options={}):
        self.__stack = stack
        self.__layer_name = layer_name
        self.__state = self.state_class()

        # Call configure to set up options
        self.configure(options)

    @property
    def stack(self):
        return self.__stack
    
    @property
    def  state(self):
        return self.__state

    def configure(self, options):
        """Configure callback.

        Override this method to configure the layer when the stack is instanciated.
        """
        pass

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
        return self.__state.to_dict()
    
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

    def on_phy(self, data, tag=None):
        pass

    def send_phy(self, data, tag=None):
        pass

class ContextLayer(StackLayer, LayerRegistry):
    """ContextLayer offer a way to group some other layers sharing a same context,
    that can be instanciated by another layer on-demand
    """

    @classmethod
    def instanciate(cls, stack, options={}, context={}):
        """Instanciate a context layer and sub-layers with the specificied context.
        """
        # Compute instance number
        if hasattr(cls, 'inst_counter'):
            inst_number = getattr(cls, 'inst_counter') + 1
        else:
            inst_number = 0
        setattr(cls, 'inst_counter', inst_number)
        
        # First, generate a name based on class alias
        inst_name = '%s#%d' % (cls.alias, inst_number)

        # Create this layer and its sub-layers
        instance = cls(stack, inst_name, options=options, context=context)
        
        # Register this instance into our stack


    def __init__(self, stack=None, layer_name='', options={}, context={}):
        super().__init__(stack=stack, layer_name=layer_name, options=options)
        
        # Save shared context
        self.context = context



