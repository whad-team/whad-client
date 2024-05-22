"""Common stack layer

This module provides the `Layer` base class that provides a convenient way
to model a specific layer or group of layers that are part of a protocol stack.
It is the basic block of a protocol stack model used in WHAD.

A protocol layer does generally takes some data coming from its lower layer,
process them and forward it to an upper layer, as well as receiving data
from an upper layer, processing it and forwarding it to a lower layer. More
generally, it receives data from one or many layers, and send data to one or
more other layers. There is also a hierarchy in the stack model.

The `Layer` class
-----------------

The `Layer` class provides a convenient way to implement a protocol layer as
well as a protocol stack in its whole. Each layer defined using this class
can have sub-layers attached to it and act as a group of layers, send and
receive data from and to other layers. A derivative class called `ContextualLayer`
can be used to dynamically create some specific contexts that may be useful
when multiplexing/demultiplexing data.

Let's create a simple layer:

``` python
from whad.common.stack import Layer, alias

@alias('eth')
class EthLayer(Layer):
    pass
```

This `EthLayer` class uses the `alias` decorator to specify a text that will be
associated with this class. Thias alias will be used to reference this layer later.
By default, when a protocol stack is instantiated, an instance of each declared
class is automatically created and referenced by the corresponding alias.

Let's add an IP layer:

``` python
from whad.common.stack import Layer, alias

@alias('eth')
class EthLayer(Layer):
    pass

@alias('ip')
class IpLayer(Layer):
    pass
```

Now we have two layers defined, but they are totally alone and not connected.
Let's add a last layer that will handle the physical link:

``` python
@alias('phy')
class PhyLayer(Layer):
    pass
```

This physical layer will be our main layer for our stack, and will send each
raw packet received to the `EthLayer` class and receive as well packets to
send back on the physical link from the latter.

Layer messaging
---------------

Data flow between layers is managed by the `Layer` class that provides a very
simple communication mechanism. In fact, any declared layer that belongs to
a stack can send data to any other layer by simply using the `send()` method.
To receive data, a specific function decorator `source` allows the user to
specify which method has to be used to process messages coming from a specific
layer.

Let's add our dataflow into our model:

``` python
from whad.common.stack import Layer, alias, source

@alias('eth')
class EthLayer(Layer):

    @source('phy')
    def on_phy_packet_received(self, packet):
        '''Process received packet'''
        # some processing here
        ip_packet = unpack(packet)

        # forward to IP layer at some point
        self.send('ip', ip_packet)

    @source('ip')
    def on_transmit_ip_packet(self, ip_packet):
        '''Process IP packet to send'''
        eth_packet = pack(ip_packet)

        # send back this packet to phy
        self.send('phy', eth_packet)

@alias('ip')
class IpLayer(Layer):

    @source('eth')
    def on_ip_packet_received(self, packet):
        '''Process incoming IP packet'''
        # Process packet ...
        response = process_packet(packet)
        if response is not None:
            # Send back packet if required
            self.send('eth', response)

@alias('phy')
class PhyLayer(Layer):

    @source('eth')
    def on_transmit_eth_packet(self, packet):
        '''Transmit packet on the network'''
        # Some code here to effectively send the packet on the physical link
        pass

    def on_receive_phy_packet(self, packet):
        '''Received packet from the network'''
        # Send packet to our Ethernet layer
        self.send('eth', packet)
```

Using the above code, when the physical layer class `PhyLayer` is sending a
received raw packet to the ethernet layer (`EthLayer`), the data is automatically
routed and the method `on_phy_packet_received()` of the `EthLayer` is called
with the specified data.

Of course, it is possible for a layer to send data to any layer, the dataflow is
totally flexible.


Contextual layers
-----------------

Often, a layer is in charge of decapsulating and encapsulating data based on a
specific context. In our stack model, this type of layer is called a contextual
layer.

In our stack model, a contextual layer must inherit from `ContextualLayer` and
be instantiated to hold its own context. The lower layer must then instantiate
a dedicated contextual layer corresponding to a specific context, and dispatch
the incoming packets/messages to the correct contextual layer, thus performing
the mux/demux operation.
"""

def convert_layer_structure(structure):
    """Convert a layer structure into a GV DOT cluster
    """
    output = ''

    if structure['instanciable']:
        output += 'subgraph cluster_%s {\n' % structure['name']
        output += 'style=filled;\ncolor=lightgrey;\n'

    # Declare root node
    output += 'node [label="%s", fontsize=12] %s;\n' % (
        structure['name'],
        structure['name']
    )

    if len(structure['sublayers']) > 0:
        for sublayer in structure['sublayers']:
            output += convert_layer_structure(sublayer)

    if structure['instanciable']:
        #output += 'label="%s";\n' % structure['name']
        output += '}\n'

    return output

def generate_links(structure):
    """
    """

    links = []

    # Add emitters for current node
    for emitter in structure['emitters']:
        links.append((emitter, structure['name']))

    # Add emitters for all sublayers
    for sublayer in structure['sublayers']:
        links.extend(generate_links(sublayer))

    return links



class source(object):
    """Layer method decorator to perform source matching.

    Source matching can be done on layer name and optionally a tag (some
    user-defined text used to represent a specific state or operation).

    This tag is used to dispatch the incoming data to the correct callback,
    each callback accepting additional named arguments as specified by
    the implementer.
    """

    def __init__(self, source, tag='default', contextual=False):
        self.__source = source
        self.__tag = tag
        self.__contextual = contextual

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
            func.is_contextual = self.__contextual
        return func

class instance(source):
    """Instance has basically the same behavior as the source decorator,
    but forces it to include the instance reference.
    """
    def __init__(self, source, tag='default'):
        super().__init__(source, tag=tag, contextual=True)


class alias(object):
    """Layer class decorator to specify layer text alias.
    """

    def __init__(self, name):
        self.__name = name

    def __call__(self, clazz):
        clazz.alias = self.__name
        return clazz


class state(object):
    def __init__(self, state_class):
        self.__state_class = state_class

    def __call__(self, clazz):
        clazz.state_class = self.__state_class
        return clazz

class LayerState(object):
    """Stack layer state database

    Define fields names in FIELDS.
    """

    def __init__(self):
        """Populate database.
        """
        self.__db = {}
        for prop in dir(self):
            prop_obj = getattr(self, prop)
            if not prop.startswith('_') and not callable(prop_obj):
                self.__db[prop] = prop_obj

    def __getattr__(self, property):
        if property in self.__db:
            return self.__db[property]
        else:
            raise AttributeError

    def __setattr__(self, property, value):
        if property.startswith('_'):
            super(LayerState, self).__setattr__(property, value)
        else:
            self.__db[property] = value

    def to_dict(self):
        return self.__db

    def from_dict(self, values):
        for prop in values:
            self.__db[prop] = values[prop]


@state(LayerState)
class Layer(object):
    """
    Basic stack layer.
    """

    @classmethod
    def instantiable(cls):
        return False

    @classmethod
    def find(cls, alias):
        """Find a sub-layer class based on its alias
        """
        # First look into our sub-layers
        if hasattr(cls, 'LAYERS'):
            if alias in cls.LAYERS:
                return cls.LAYERS[alias]

            # If not found, propagate to our sub-layer classes
            for layer in cls.LAYERS:
                result = cls.LAYERS[layer].find(alias)
                if result is not None:
                    return result
        return None

    @classmethod
    def add(cls, clazz, input=False):
        """Add a sub-layer class.
        """
        # First we inject a LAYERS attribute into the class
        layers_prop_name = 'LAYERS'
        if not hasattr(cls, layers_prop_name):
            setattr(cls, layers_prop_name, {})
        class_layers = getattr(cls, layers_prop_name)

        # Then an input boolean field
        if input:
            setattr(cls, 'ENTRY_LAYER', clazz.alias)

        # Register a layer based on its alias
        if hasattr(clazz, 'alias'):
            if clazz.alias in cls.LAYERS:
                cls.LAYERS[clazz.alias] = clazz
            else:
                cls.LAYERS[clazz.alias] = clazz

    @classmethod
    def remove(cls, clazz):
        """Remove a sub-layer class.
        """
        layers_prop_name = 'LAYERS'
        if hasattr(cls, layers_prop_name):
            class_layers = getattr(cls, layers_prop_name)
            if clazz.alias in class_layers:
                del class_layers[clazz.alias]

    def __init__(self, parent=None, layer_name=None, options={}):
        self.__parent = parent
        self.__layer_name = layer_name
        self.__state = self.state_class()
        self.__layers = {}
        self.__layer_cache = {}
        self.__options = options
        self.__monitor_callbacks = []

        # Cache our message handlers
        self.__handlers = {}
        methods = []
        for prop in dir(self):
            try:
                prop_obj = getattr(self, prop)
                if callable(prop_obj):
                    methods.append(prop_obj)
            except AttributeError as att_err:
                pass

        for method in methods:
            if hasattr(method, 'match_sources') and isinstance(getattr(method, 'match_sources'), dict):
                match_sources = getattr(method, 'match_sources')
                for source in match_sources:
                    tags = match_sources[source]
                    for tag in tags:
                        handler_key = '%s:%s'%(source,tag)
                    self.__handlers[handler_key] = method

        # Call configure to set up options
        self.configure(options)

        # Populate all the sub-layers, if any.
        if hasattr(self, 'LAYERS'):
            self.populate(options)

    def populate(self, options={}):
        """Sub-layers instanciation.

        We instanciate each layer and register these instances into our object.
        """
        self.__options = options

        # Define layers and default context.
        for layer in self.LAYERS.keys():
            if not self.LAYERS[layer].instantiable():
                layer_inst = self.create_layer(self.LAYERS[layer], layer)
                if layer in options:
                    layer_inst.configure(options[layer])

    def instantiate(self, contextual_clazz):
        """Instantiate a contextual layer.
        """
        # Make sure the class inherits from `ContextualLayer` class
        if issubclass(contextual_clazz, ContextualLayer):
            # Build instance number
            if hasattr(contextual_clazz, 'INSTCOUNT'):
                instcount = getattr(contextual_clazz, 'INSTCOUNT')
                instcount += 1
            else:
                setattr(contextual_clazz, 'INSTCOUNT', 0)
                instcount = 0
            instance_name = '%s#%d' % (contextual_clazz.alias, instcount)

            # Create layer with this new instance name.
            return self.create_layer(contextual_clazz, instance_name)
        else:
            return None

    def create_layer(self, layer_class, inst_name):
        """Create a layer and registers it into our list of layers.
        """
        layer_options = self.options[layer_class.alias] if layer_class.alias in self.options else {}
        self.__layers[inst_name] = layer_class(self, inst_name, options=layer_options)
        return self.__layers[inst_name]

    def destroy(self, layer_instance):
        '''Remove an instantiated layer from our known layers.
        '''
        if layer_instance.name in self.__layers:
            del self.__layers[layer_instance.name]

    def register_monitor_callback(self, callback):
        '''Register a callback to monitor messages sent between layers.
        '''
        if callback not in self.__monitor_callbacks:
            self.__monitor_callbacks.append(callback)

    def unregister_monitor_callback(self, callback):
        '''Unregister a previously registered callback.
        '''
        if callback in self.__monitor_callbacks:
            self.__monitor_callbacks.remove(callback)

    def monitor_message(self, source, destination, data, tag='default', **kwargs):
        for monitor in self.__monitor_callbacks:
            monitor(source, destination, data, tag=tag, **kwargs)

    def has_layer(self, name):
        """Check if layer has a specific sublayer.
        """
        # First, we check if it is one of our sublayers
        if name in self.layers:
            return True
        else:
            # Check if one of our sublayer has this layer
            for layer in self.layers:
                if self.layers[layer].has_layer(name):
                    return True
        return False

    def has_handler(self, source, tag='default'):
        """Check if this layer has a registered method to process messages coming from a specific source/tag.
        """
        return (self.get_handler(source, tag=tag) is not None)

    def get_handler(self, source, tag='default'):
        """Retrieve the registered handler for a given source and tag (if any).
        """
        handler_key = '%s:%s'%(source, tag)
        if handler_key in self.__handlers:
            return self.__handlers[handler_key]

        # If not found, fall back on 'default' tag
        handler_key = '%s:%s'%(source, 'default')
        if handler_key in self.__handlers:
            return self.__handlers[handler_key]

        # Not found
        return None

    def get_layer(self, name, children_only=False):
        """Retrieve a specific layer based on its name.
        """
        # Are we the target layer ?
        if name == self.alias:
            # Return ourself :)
            return self

        # Do we have this layer in cache ?
        if name in self.__layer_cache:
            return self.__layer_cache[name]
        else:
            # First, we check if it is one of our sublayers
            if name in self.layers:
                return self.layers[name]
            else:
                # Check if one of our sublayer has this layer (children only)
                for layer in self.layers:
                    if not self.layers[layer].instantiable():
                        result = self.layers[layer].get_layer(name, children_only=True)
                        if result is not None:
                            # Found the layer, save in cache and return it
                            self.__layer_cache[name] = result
                            return result

                # If not, we ask our parent to get it
                if not children_only and self.__parent is not None:
                    layer = self.__parent.get_layer(name)

                    # Save layer in cache
                    if layer is not None:
                        self.__layer_cache[name] = layer

                    # Return layer
                    return layer

            # If anyone has this layer, it does not exist
            return None

    def get_entry_layer(self):
        """Return the group entry layer.
        """
        if hasattr(self, 'ENTRY_LAYER'):
            return getattr(self, 'ENTRY_LAYER')
        else:
            return None

    @property
    def name(self):
        return self.__layer_name if self.__layer_name is not None else self.alias

    @property
    def parent(self):
        return self.__parent

    @property
    def state(self):
        return self.__state

    @property
    def layers(self):
        return self.__layers

    @property
    def options(self):
        return self.__options

    @classmethod
    def list_emitters(cls):
        """Find sublayers that send messages to the specified layer.
        """
        emitters = []

        # First, loop on our own methods to find the sources we are using.
        methods = [getattr(cls, prop) for prop in dir(cls) if callable(getattr(cls, prop))]
        for method in methods:
            if hasattr(method, 'match_sources') and isinstance(getattr(method, 'match_sources'), dict):
                match_sources = getattr(method, 'match_sources')
                for _source in match_sources:
                    if _source not in emitters:
                        emitters.append(_source)

        return emitters

    def get_message_handler(self, source):
        """Find the message handler associated with the source
        """
        methods = [getattr(self, prop) for prop in dir(self) if callable(getattr(self, prop))]
        for method in methods:
            if hasattr(method, 'match_sources') and isinstance(getattr(method, 'match_sources'), dict):
                match_sources = getattr(method, 'match_sources')
                if source in match_sources:
                    if tag in match_sources[source]:
                        return method

    def __get_layer_handler_by_source(self, layer, source, tag='default'):
        """Find the method associated with a source for a given layer.
        """
        layer = self.get_layer(layer)
        if layer is None:
            return None
        else:
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

    def send(self, destination, data, tag='default', **kwargs):
        """Send a message to the corresponding layer.
        """
        return self.send_from(self.name, destination, data, tag=tag, **kwargs)

    def send_from(self, source, destination, data, tag='default', **kwargs):
        """Dispatch data from source to destination, with an optional tag
        and arguments.
        """
        # If source name has a '#' in it, then it is an instance of a
        # contextual layer and we must remove this to route the message.
        if '#' in source:
            idx = source.find('#')
            source_layer = source[:idx]
        else:
            source_layer = source

        # notify monitors
        self.monitor_message(source, destination, data, tag=tag, **kwargs)

        # Find the target layer object
        target_layer = self.get_layer(destination)
        if target_layer is not None:
            # Then we search the corresponding handler for our source
            handler = target_layer.get_handler(source_layer, tag)
            if handler is not None:
                if handler.is_contextual:
                    handler(source, data, **kwargs)
                else:
                    handler(data, **kwargs)
            else:
                print('[oops] No handler found in layer %s to process messages from %s' % (destination, source))
        else:
            print('[oops] layer %s does not exist' % destination)


    def __getitem__(self, name):
        """Array-like behavior to get a specific layer.
        """
        return self.get_layer(name)

    def configure(self, options):
        """Configure callback.

        Override this method to configure the layer when the stack is instanciated.
        """
        pass

    def save(self):
        """Return this layer saved state.
        """
        sublayers = {}
        for layer in self.layers:
            sublayers[layer] = self.layers[layer].save()

        layer_state = {
            'name': self.name,
            'state': self.__state.to_dict(),
            'sublayers': sublayers
        }

        return layer_state

    def load(self, state):
        """Set this layer properties dictionnary (used to load state).
        """
        # First, populate our state
        assert(state['name'] == self.name)
        self.state.from_dict(state['state'])

        # Populate our sublayers, instantiate contextual layers and set their state
        for sublayer in state['sublayers']:
            # If sublayer is not a contextual layer, set its state
            if '#' not in sublayer:
                sublayer_obj = self.get_layer(sublayer)
                sublayer_obj.load(state['sublayers'][sublayer])
            else:
                # sublayer class
                idx = sublayer.index('#')
                sublayer_class = sublayer[:idx]

                # instantiate and initialize
                sublayer_obj = self.create_layer(self.LAYERS[sublayer_class], sublayer)
                sublayer_obj.load(state['sublayers'][sublayer])

    @classmethod
    def get_structure(cls):
        """Retrieve layer structure.
        """


        # Populate sublayer structure
        sublayers_structure = []
        if hasattr(cls, 'LAYERS'):
            # Loop on all sublayers
            for sublayer in cls.LAYERS:
                sublayers_structure.append(cls.LAYERS[sublayer].get_structure())

        # Return our structure
        structure = {
            'name': cls.alias,
            'instanciable': cls.instantiable(),
            'emitters': cls.list_emitters(),
            'sublayers':sublayers_structure,
        }

        return structure

    @classmethod
    def export(cls, output_file=None):
        """Export to graphviz file.
        """
        structure = cls.get_structure()

        output = 'digraph T {\n'
        output += 'rankdir=LR;\n'

        # Walk the structure to extract the nodes/subgraphs
        output += convert_layer_structure(structure)

        # Walk the structure and extract the links
        links = generate_links(structure)

        for source, destination in links:
            output += '%s -> %s;\n' % (source, destination)

        output += '}'

        if output_file is not None:
            # Write to file
            with open(output_file, 'w') as f:
                f.write(output)

        return output


class ContextualLayer(Layer):
    """This layer is not automatically loaded when the stack model is created
    and must be instanciated specifically by another layer.
    """

    @classmethod
    def instantiable(cls):
        return True
