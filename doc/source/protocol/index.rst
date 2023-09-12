Whad protocol stack model
=========================

*Whad* supports different wireless protocols such as *Bluetooth Low Energy* or
*ZigBee* and provides a protocol stack for both of them. Protocol stacks are an
important component of *Whad* as one may need to alter it in order to modify
the behavior of an emulated device or simply assess the security of a target
protocol stack. This is why *Whad* provides a generic protocol stack model that
can be used to implement any protocol stack with ease, and to make it compatible
with other stack-related tools provided by *Whad*.

Our generic protocol stack model considers any wireless protocol as a graph of
individual stack layer able to communicate one with another. Each layer of a
protocol stack is defined as a Python class inherated from :class:`whad.common.stack.Layer`
and is used to process incoming data (packets or messages) and forward it to
upper layers for further processing. Data/messages are then making their way
through the protocol stack and this latter can react to them and send data back.

Generic stack layer
-------------------

*Whad* provides a layer model class :class:`whad.common.stack.Layer` that provides
some features to ease the implementation of protocol stacks. A protocol is seen
as a graph of various stack layers that is able to process incoming packets
and to output other packets, as shown below:

.. graphviz:: protocol.dot
    :align: center
    :caption: Example of a protocol stack

From an implementation point-of-view, every layer that belongs to an upper layer
is declared as a sub-layer of this upper layer, thus describing a hierarchy. The
above protocol stack does in fact uses this hierarchy:

.. graphviz:: protocol-h.dot
    :align: center
    :caption: Protocol stack with hierarchy


Creating a protocol stack layer
-------------------------------

A protocol stack layer in *Whad* is defined by a class that must inherits from :class:`whad.common.stack.Layer`.
Each stack layer **must have** an alias defined, a textual name that will be used
inside the protocol stack to reference a specific class.

Each layer recieves data from a lower layer, processes it and forwards it to an
upper layer. Data flow is automatically handled by the :class:`whad.common.stack.Layer`
class.

Each layer has its own state structure to maintain, managed by default by :class:`whad.common.stack.Layer`,
allowing snapshots of a layer to be taken at any time.

Declaring a new protocol stack layer
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A new protocol stack layer must inherits from :class:`whad.common.stack.Layer`
and has an alias set thanks to the :class:`whad.common.stack.alias` decorator:

.. code:: python

    from whad.common.stack import Layer, alias

    @alias('ether')
    class Ethernet(Layer):

        def configure(self, options={}):
            if 'something' in options:
                self.state.something = options['something']

The above code declares a new protocol layer class `Ethernet` with an alias
`ether` and overrides the `configure()` method to modify its state property
`something` with the value provided in the `options` dictionary passed in arguments.

This layer cannot process incoming data yet nor send data to another layer, as
it is the only one declared. We need one more layer so let's declare a PHY layer:

.. code:: python

    from whad.common.stack import Layer, alias

    @alias('ether')
    class Ethernet(Layer):

        def configure(self, options={}):
            if 'something' in options:
                self.state.something = options['something']

    @alias('phy')
    class Phy(Layer):

        def configure(self, options={}):
            pass

Allright, now we have two different layers declared, it's time to add some
interaction between them.


Data processing
~~~~~~~~~~~~~~~

A layer processes incoming data by registering one of its method as a handler for
data coming from a specific source layer. This is a core mechanism implemented in
:class:`whad.common.stack.Layer` and the most convenient way to pass data from
one layer to another. Data can be a scapy packet, raw bytes or custom structures,
but mostly Scapy packets.

To register a handler for a specific source, use the :class:`whad.common.stack.source`
decodator as shown below:

.. code:: python

    from whad.common.stack import Layer, alias, source

    @alias('ether')
    class Ethernet(Layer):

        def configure(self, options={}):
            if 'something' in options:
                self.state.something = options['something']

        @source('phy')
        def on_packet_received(self, packet):
            '''Process incoming packets from the PHY layer.
            '''
            pass

    @alias('phy')
    class Phy(Layer):

        def configure(self, options={}):
            pass

    Phy.add(Ethernet)


The `Ethernet` layer class has now a registered handler that will be called every
time the `Phy` layer sends it some data with the :py:meth:`whad.common.stack.Layer.send`
method. The `Ethernet` layer also needs to be added as a sub-layer of the `Phy` layer
for this communication mechanism to work properly (if not, the `Phy` layer won't be
able to find the registered handler in the `Phy` layer). This is how upper layers of
the protocol stack are attached to their lower layers.

Our `Phy` layer needs to expose a method to be notified of the reception of
a packet. This method will be called by some code outside of this protocol stack,
providing every received Scapy packets to the `Phy` layer. Let's call this
method `on_packet_received`:

.. code:: python

    from whad.common.stack import Layer, alias, source
    from scapy.all import *

    @alias('ether')
    class EthernetLayer):

        def configure(self, options={}):
            if 'something' in options:
                self.state.something = options['something']

        @source('phy')
        def on_packet_received(self, packet):
            '''Process incoming packets from the PHY layer.
            '''
            pass

    @alias('phy')
    class Phy(Layer):

        def configure(self, options={}):
            pass
        
        def on_packet_received(self, packet: Packet):
            pass

Now we need to tell the `Phy` layer to forward a packet to the `Ethernet` layer
if it contains an ethernet header. This is done by using scapy `haslayer()`
method combined with the :py:meth:`whad.common.stack.Layer.send`:

.. code:: python

    from whad.common.stack import Layer, alias, source
    from scapy.all import *

    @alias('ether')
    class EthernetLayer):

        def configure(self, options={}):
            if 'something' in options:
                self.state.something = options['something']

        @source('phy')
        def on_packet_received(self, packet):
            '''Process incoming packets from the PHY layer.
            '''
            pass

    @alias('phy')
    class Phy(Layer):

        def configure(self, options={}):
            pass
        
        def on_packet_received(self, packet: Packet):
            if packet.haslayer(Ether):
                self.send('ether', packet.getlayer(Ether))


When a packet is received by the `Phy` layer, it is sent to the `Ethernet` layer
through its registered handler `on_packet_received`. It is then possible to
process it, and send an answer back to the `Phy` layer using the same mechanism:

.. code:: python

    from whad.common.stack import Layer, alias, source
    from scapy.all import *

    @alias('ether')
    class EthernetLayer):

        def configure(self, options={}):
            if 'something' in options:
                self.state.something = options['something']

        @source('phy')
        def on_packet_received(self, packet):
            '''Process incoming packets from the PHY layer.
            '''
            # Send back the packet
            self.send('phy', packet)

    @alias('phy')
    class Phy(Layer):

        def configure(self, options={}):
            pass
        
        def on_packet_received(self, packet: Packet):
            if packet.haslayer(Ether):
                self.send('ether', packet.getlayer(Ether))

        @source('ether')
        def on_ether_packet(self, packet):
            print('Received a packet from Ether layer:')
            packet.show()

Let's try this small protocol stack in a nutshell:

.. code:: python

    from whad.common.stack import Layer, alias, source
    from scapy.all import *

    @alias('ether')
    class Ethernet(Layer):

        def configure(self, options={}):
            if 'something' in options:
                self.state.something = options['something']

        @source('phy')
        def on_packet_received(self, packet):
            '''Process incoming packets from the PHY layer.
            '''
            # Send back the packet
            self.send('phy', packet)

    @alias('phy')
    class Phy(Layer):

        def configure(self, options={}):
            pass
        
        def on_packet_received(self, packet: Packet):
            if packet.haslayer(Ether):
                self.send('ether', packet.getlayer(Ether))

        @source('ether')
        def on_ether_packet(self, packet):
            print('Received a packet from Ether layer:')
            packet.show()

    Phy.add(Ethernet)

    if __name__ == '__main__':

        # Instantiate our protocol stack
        my_stack = Phy()

        # Pass a packet to our stack
        packet = Ether())/IP(src="192.168.1.1", dest="192.168.2.2")/TCP()
        my_stack.on_packet_received(packet)

It produces the following output:

.. code::

    Received a packet from Ether layer:
    ###[ Ethernet ]### 
    dst       = ff:ff:ff:ff:ff:ff
    src       = d4:3b:04:2c:ad:12
    type      = IPv4
    ###[ IP ]### 
        version   = 4
        ihl       = None
        tos       = 0x0
        len       = None
        id        = 1
        flags     = 
        frag      = 0
        ttl       = 64
        proto     = tcp
        chksum    = None
        src       = 192.168.1.1
        dst       = 192.168.1.2
        \options   \
    ###[ TCP ]### 
            sport     = ftp_data
            dport     = http
            seq       = 0
            ack       = 0
            dataofs   = None
            reserved  = 0
            flags     = S
            window    = 8192
            chksum    = None
            urgptr    = 0
            options   = ''

Our `Phy` layer has correctly sent the received packet from the `Ethernet` layer.


.. note::

    A `tag` parameter is also supported by both the `source` decorator and the
    :py:meth:`whad.common.stack.Layer.send` method to allow filtering on the
    source layer *and* a specific tag.

Layer State management
~~~~~~~~~~~~~~~~~~~~~~

Of course, actual protocol stacks implemented on top of :class:`whad.common.stack.Layer`
have to maintain a state while handling incoming and outgoing packets. The stack
state is composed of each sub-layer' state which are maintained by these layers
themselves.

Remember, each layer has its own state exposed in its `state` property. This state
is by default an instance of :class:`whad.common.stack.LayerState` that behaves like
a dictionary with keys mapped as properties. It is possible to create a new state
class in order to provide custom methods to make its manipulation easier, and to
associate this specific class with a specific layer class thanks to the
:class:`whad.common.stack.state` decorator:

.. code:: python


    from whad.common.stack import Layer, LayerState, alias, source, state
    from scapy.all import *

    class EthernetState(LayerState):

        def __init__(self):
            super().__init__()
            self.macs = []

        def clear(self):
            self.macs = []

        def add_mac_address(self, mac):
            if mac not in self.macs:
                self.macs.append(mac)
        
        def has_mac_address(self, mac):
            return mac in self.macs

        def remove_mac_address(self, mac):
            if mac in self.macs:
                self.macs.remove(mac)

    @state(EthernetState)
    @alias('ether')
    class Ethernet(Layer):

        def configure(self, options={}):
            self.state.clear()

        @source('phy')
        def on_packet_received(self, packet):
            '''Process incoming packets from the PHY layer.
            '''
            # Add source mac to our mac address book
            self.state.add_mac_address(packet.getlayer(Ether).src)

            # Send back the packet
            self.send('phy', packet)

A layer state can be retrieved with the :py:meth:`whad.common.stack.Layer.save`
method and loaded with the :py:meth:`whad.common.stack.Layer.load` method.
The example below demonstrates how to save and reload the state of out stack:

.. code:: python

    # Create an instance of our stack and save its state
    my_stack = Phy()
    stack_state = my_stack.save()

    # Reload the state of our stack
    my_stack.load(stack_state)



Protocol stack instantiation
----------------------------

Once a protocol stack implemented using this generic model, it can be
easily instantiated using the root layer class (i.e. the PHY layer), as
shown below:

.. code:: python

    from whad.common.stack import Layer, LayerState, alias, source, state
    from scapy.all import *

    class EthernetState(LayerState):

        def __init__(self):
            super().__init__()
            self.macs = []

        def clear(self):
            self.macs = []

        def add_mac_address(self, mac):
            if mac not in self.macs:
                self.macs.append(mac)
        
        def has_mac_address(self, mac):
            return mac in self.macs

        def remove_mac_address(self, mac):
            if mac in self.macs:
                self.macs.remove(mac)

    @state(EthernetState)
    @alias('ether')
    class Ethernet(Layer):

        def configure(self, options={}):
            # Clear state
            self.state.clear()
            self.log_macs = False

            # Check if we are asked to log mac addresses
            if 'log_macs' in options:
                if options['log_macs'] == True:
                    self.log_macs = True
            

        @source('phy')
        def on_packet_received(self, packet):
            '''Process incoming packets from the PHY layer.
            '''
            if self.log_macs:
                # Add source mac to our mac address book
                self.state.add_mac_address(packet.getlayer(Ether).src)

            # Send back the packet
            self.send('phy', packet)


    @alias('phy')
    class Phy(Layer):

        def configure(self, options={}):
            pass
        
        def on_packet_received(self, packet: Packet):
            if packet.haslayer(Ether):
                self.send('ether', packet.getlayer(Ether))

        @source('ether')
        def on_ether_packet(self, packet):
            print('Received a packet from Ether layer:')
            packet.show()

    Phy.add(Ethernet)

    my_stack = Phy(options={
        'ether': {
            'log_macs': True
        }
    })

When a layer is instantiated, be it a root layer or not, every registered sub-layer
is automatically instantiated as well and configured using the main `options` dictionnary.
This `options` dictionnary may contain a key named the same as a registered sub-layer,
and if so the value corresponding to this key is used as an `options` parameter when
this sub-layer is configured.

.. note::
    
    Each sub-layer is **only instantiated once and only once** in the whole protocol stack
    graph, with the provided options (unless it is a contextual layer).

The protocol stack instantiation shown above can then be feed with a custom packet,
as shown below:

.. code:: python

    my_stack.on_packet_received(Ether()/IP()/TCP())


Contextual layers
-----------------

When it is required to implement a multiplexing/demultiplexing layer, contextual
layers are a great help. Multiplexing/demultiplexing could make your life easier
when you have to deal with multiple links combined in one physical layer, such
as TCP connections for instance.

A `contextual layer` is not automatically instantiated when the protocol stack is
instantiated but when it is required. The layer that instantiates a contextual
layer is generally in charge of multiplexing/demultplexing the incoming/outgoing
data. When a contextual layer is instantiated, it is automatically registered as
a sub-layer but with a generated name. Let's consider the following contextual
layer:

.. code:: python

    from whad.common.stack import ContextualLayer, alias

    @alias('ip')
    class IPLayer(ContextualLayer):

        def configure(self, options={}):
            pass

When instantiated, the instance will be in the form `ip#0`. The next layer
instantiated will be named `ip#1`, and so on.

Let's get back to our example protocol stack and consider using the above
contextual layer. We need to create as many `IPLayer` instances as destination IP
addresses we have to handle. This is done this way:

.. code:: python

    from whad.common.stack import Layer, LayerState, ContextualLayer, alias, source, state, instance
    from scapy.all import *

    @alias('ip')
    class IPLayer(ContextualLayer):

        def configure(self, options={}):
            pass

        @source('ether')
        def on_ip_packet(self, packet):
            '''Simply echoes the packet to the Ethernet layer.
            '''
            self.send('ether', packet)


    class EthernetState(LayerState):
        '''This class implements a custom state for the Ethernet layer.

        This state will keep track of every stream identified by a source
        MAC address and source IP address.
        '''

        def __init__(self):
            super().__init__()
            self.clear()

        def clear(self):
            self.streams = {}

        def has_stream(self, mac, ip):
            '''Check if a stream is already handled by an IPLayer instance.
            '''
            return ((mac,ip) in self.streams.values())
                
        def register_stream(self, mac, ip, layer):
            '''Register a new IPLayer instance for a specified IP/MAC
            '''
            self.streams[layer] = (mac, ip)

        def get_stream(self, mac, ip):
            '''Retrieve the IPLayer instance name associated with the given
            IP/MAC addresses.
            '''
            for layer in self.streams:
                m,i = self.streams[layer]
                if m==mac and i==ip:
                    return layer
            return None

        def get_mac_by_layer(self, layer_name):
            '''Retrieve the MAC address associated with a specific IPLayer
            instance.
            '''
            if layer_name in self.streams:
                return self.streams[layer_name][0]
            else:
                return None


    @state(EthernetState)
    @alias('ether')
    class Ethernet(Layer):

        def configure(self, options={}):
            self.state.clear()

        @source('phy')
        def on_packet_received(self, packet):
            '''Process incoming packets from the PHY layer.
            '''
            if packet.haslayer(IP):
                # get packet source IP and MAC
                packet_ip = packet.getlayer(IP).src
                packet_mac = packet.getlayer(Ether).src

                # If we already know this IP address
                if self.state.has_stream(packet_mac, packet_ip):
                    # Retrieve the associated MAC and instantiated layer name
                    ip_layer = self.state.get_stream(packet_mac, packet_ip)

                    print('IP address already known, forward to %s' % ip_layer)

                    # Send this IP packet to the corresponding layer name
                    self.send(ip_layer, packet.getlayer(IP))
                else:
                    print('New IP address seen: %s' % packet_ip)

                    # Create a new IP layer
                    ip_layer_obj = self.instantiate(IPLayer)
                    print('Instantiated a new layer: %s' % ip_layer_obj.name) 

                    # Register our source MAC and IP address with our new layer name ('ip#0')
                    self.state.register_stream(packet_mac, packet_ip, ip_layer_obj.name)

                    # Send packet to this new sub-layer
                    self.send(ip_layer_obj.name, packet.getlayer(IP))

        @instance('ip')
        def on_ip_packet_received(self, source, packet):
            '''Handling packets sent by an instantiated IPLayer

            It is important to note the use of @instance rather than @source,
            as @instance will provide the handler the source layer that sent
            a message.
            '''
            # Search mac address belonging to this source layer
            src_mac = self.state.get_mac_by_layer(source)
            if src_mac is not None:
                # Mac is known, encapsulate our packet and send to PHY
                self.send('phy', Ether(src=src_mac)/packet)
    @alias('phy')
    class Phy(Layer):

        def configure(self, options={}):
            pass
        
        def on_packet_received(self, packet: Packet):
            if packet.haslayer(Ether):
                self.send('ether', packet.getlayer(Ether))

        @source('ether')
        def on_ether_packet(self, packet):
            print('Received a packet from Ether layer')
            #packet.show()

    # Assemble our stack
    Ethernet.add(IPLayer)
    Phy.add(Ethernet)

    if __name__ == '__main__':

        # Instantiate our protocol stack
        my_stack = Phy()

        # Pass some packets to our stack
        packets = [
            Ether()/IP(src="192.168.1.1", dst="192.168.2.2")/TCP(),
            Ether()/IP(src="192.168.1.1", dst="192.168.2.2")/TCP(),
            Ether()/IP(src="192.168.1.2", dst="192.168.2.2")/TCP()
        ]

        for packet in packets:
            my_stack.on_packet_received(packet)

        # Display the current state of the stack
        print(my_stack.save())


Using contextual layers dynamically adds layer nodes to the stack graph starting
from a layer that performs multiplexing/demultiplexing operations. Thus, the upper
layer don't have to mess with information related to the lower layers and let the
mux/demux layer assembles everything.

Therefore, the number of active layers when the stack is running may vary, and the
stack state reflects this fact.

Visualizing a stack
-------------------

A generic layer can generate a DOT file including all its sub-layers and contextual
layers, using the :py:meth:`whad.common.stack.Layer.export` method, as shown below:

.. code:: python

    Phy.export('mystack.dot')

.. graphviz:: mystack.dot
    :align: center
    :caption: Our example stack


Testing protocol layers
-----------------------

This generic stack model also provides some tools to implement one or more
unit tests for a given layer, such as :class:`whad.common.stack.tests.Sandbox` and
:class:`whad.common.stack.tests.LayerMessage`.

Layer sandboxing
~~~~~~~~~~~~~~~~

:class:`whad.common.stack.tests.Sandbox` is a special class that behaves like
a protocol layer but captures every message sent between any layers, thus
allowing to check if a specific layer is correctly implemented.

This class must be used as a layer container as shown below:

.. code:: python

    import pytest
    from whad.common.stack.tests import Sandbox, LayerMessage
    
    # Import our previously declared protocol layer
    from . import Ether

    @alias('phy')
    class PhyMock(Sandbox):
        pass
    PhyMock.add(Ether)


Pytest-based tests
~~~~~~~~~~~~~~~~~~

We then can implement one or more unit tests using `pytest` and this sandbox:


.. code:: python

    import pytest
    from whad.common.stack.tests import Sandbox, LayerMessage
    
    # Import our previously declared protocol layer
    from . import Ether

    @alias('phy')
    class PhyMock(Sandbox):
        pass
    PhyMock.add(Ether)

    class TestEtherLayer(object):

        @pytest.fixture
        def phy(self):
            return PhyMock()

        def test_packet_processing(self, phy):
            '''This test function relies on the `phy` fixture that will create
            a sandbox containing an instance of the `Ethernet` layer.
            '''
            # We send a test packet to the Ether layer
            packet = Ether(src='00:11:22:33:44:55')/IP(src="192.168.1.1", dst="192.168.2.2")/TCP()
            phy.send('ether', packet)
            
            # Message has been processed, we should have seen a message sent back to
            # the phy layer
            assert phy.expect(LayerMessage(
                'ether',
                'phy',
                packet
            ))

            # We also checks that a new layer has been created
            assert (phy.get_layer('ip#0') is not None)

The :class:`whad.common.stack.tests.LayerMessage` class holds all the information
sent by a layer to another and is used by the :py:meth:`whad.common.stack.tests.Sandbox.expect`
method to check if such a message has been observed during the test. The contained
layers can also be accessed such as the `ip#0` layer in our example to check if some
of their properties match expected values.
