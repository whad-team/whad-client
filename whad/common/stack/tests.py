"""Generic stack testing features
"""

from whad.common.stack import Layer, alias

class contextual(object):

    def __init__(self, value):
        self.__value = value

    def __call__(self, func):
        func.is_contextual = self.__value
        return func

class LayerMessage(object):
    '''This class is used by `Sandbox` to represent a message between two layers,
    keeping track of the source, destination, data, tag and named arguments.
    '''

    def __init__(self, source, destination, data, tag='default', **kwargs):
        self.__source = source
        self.__destination = destination
        self.__data = data
        self.__tag = tag
        self.__args = kwargs

    @property
    def source(self):
        return self.__source
    
    @property
    def destination(self):
        return self.__destination
    
    @property
    def data(self):
        return self.__data
    
    @property
    def tag(self):
        return self.__tag
    
    @property
    def args(self):
        return self.__args

    def __repr__(self):
        return 'LayerMessage(source="%s", destination="%s", data="%s", tag="%s")' % (
            self.source,
            self.destination,
            bytes(self.data),
            self.tag
        )

    def __eq__(self, other):
        # check main properties
        if (self.source != other.source) or (self.destination != other.destination) \
            or (self.data != other.data) or (self.tag != other.tag):
            return False
        
        # check arguments
        for arg in self.args:
            if arg not in other.args:
                print('LayerMessage - comparison failed: missing arg %s' % arg)
                return False
            if self.args[arg] != other.args[arg]:
                print('LayerMessage - comparison failed: arg %s values are different (%s, %s)' % (
                    arg, self.args[arg], other.args[arg])
                )
                return False
            
        # Same.
        print('same')
        return True
        

@alias('sandbox')
class Sandbox(Layer):
    """This layer is used as a container for one or more layers that need
    to be tested.
    """

    def __init__(self, parent=None, layer_name=None, options={}, target=None):
        super().__init__(parent=parent, layer_name=layer_name, options=options)
        self.messages = []
        #self.target = target.alias
        #self.target_class = target

    def populate(self, options={}):
        '''Populate static layers and install a custom message monitor callback
        '''
        super().populate(options=options)

        # Install a monitor callback on all sub-layers
        for layer in self.layers:
            self.layers[layer].register_monitor_callback(self.log_message)

    def instantiate(self, clazz):
        '''Instantiate a layer and install a custom message monitor callback
        '''
        layer = super().instantiate(clazz)
        layer.register_monitor_callback(self.log_message)
        return layer

    def get_layer(self, name: str):
        '''Retrieve a specific layer if one of ours, or this instance if layer
        cannot be found.
        '''
        layer = super().get_layer(name)
        if layer is None:
            self.destination = self
            return self
        else:
            return layer
    
    def get_handler(self, source, tag):
        '''This method is called by our stack message handler search code, and is
        required here to return our dummy message handler.
        '''
        return self.dummy_message_handler

    def log_message(self, source, destination, data, tag='default', **kwargs):
        '''Layer message monitoring.
        '''
        self.messages.append(LayerMessage(
            source,
            destination,
            data,
            tag=tag,
            **kwargs
        ))

    @contextual(True)
    def dummy_message_handler(self, source, data, **kwargs):
        """Dummy message handler, does nothing.
        """
        pass

    def expect(self, messages, strict=False):
        '''Checks if one or more messages have been captured.
        '''
        if isinstance(messages, list):
            if strict and len(self.messages) != len(messages):
                return False
            if len(self.messages) >= len(messages):
                for i in range(len(self.messages)):
                    if messages[i] != self.messages[i]:
                        return False
                return True
            else:
                return False
        elif isinstance(messages, LayerMessage):
            if len(self.messages) == 0:
                print('no message received')
                return False
            # Check if this message has been seen in our monitored messages
            for msg in self.messages:
                if msg == messages:
                    return True
            return False

    




