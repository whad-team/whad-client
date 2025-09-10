Profiles
===============

WHAD uses a Bluetooth Mesh profile when creating a node (a Connector object). This profile is always a subclass of `whad.btmesh.profile.BaseMeshProfile`
A profile is namely responsible for handling all the data of a node, whether about itself (keys, addresses, models,...) or about other nodes.

The profile is also responsible of the creation of Elements and Models for the local node.

Create a provisionee node with a specific set of Elements and Models
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

It is possible to create a subclass of `whad.btmesh.profile.BaseMeshProfile` in order to specify the Elements and Models of the local node.
Note that all nodes have the Configuration Server model on their primary element by default.

.. code-block:: python

    from whad.btmesh.models.generic_on_off import GenericOnOffClient, GenericOnOffServer
    from whad.btmesh.models.configuration import ConfigurationModelClient
    from whad.btmesh.profile import BaseMeshProfile

    class CustomProfile(BaseMeshProfile):
        def _populate_elements_and_models(self):
            """
            Populate elements and models for the node (except the ConfigurationModelServer, HealthModelServer and primary element creation, by default)
            """

            # We add a second element, and add a Generic OnOffServer to it
            new_element = self.__local_node.add_element()
            new_element.register_model(GenericOnOffServer())

            # Add a GenericOnOff Server and Client
            primary_element = self.__local_node.get_element(0)
            primary_element.register_model(GenericOnOffServer())
            primary_element.register_model(GenericOnOffClient())
            # for convenience, we add a ConfigurationModelClient to all nodes for testing.
            primary_element.register_model(ConfigurationModelClient())

You can add a new element with `self.__local_node.add_element()`, this will return the element added to the profile.
You can then add models with `element.register_model` by giving in argument the Model object.
The `_populate_elements_and_models` function is the only one the overide in a profile class.


You can then use the profile when creating the connector :

.. code-block:: python

    provisionee = Provisionee(dev, profile=CustomProfile())


Model creation and customization
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Models are defined `whad.btmesh.models`. A model can either inherit from `whad.btmesh.models.ModelServer` or `whad.btmesh.models.ModelClient`
depending on its nature. For now only SIG models are fully supported.


A Model implementes handlers for Model messages. The opcode for each messages are available in the official Bluetooth assigned number specification.
https://www.bluetooth.com/specifications/assigned-numbers/

Here is an example of the `whad.btmesh.models.generic_on_off.GenericOnOffClient` model :

.. code-block:: python

    class GenericOnOffClient(ModelClient):
        def __init__(self):
            super().__init__(model_id=0x1001)

            self.rx_handlers[0x8204] = self.rx_on_on_onff_status # BTMesh_Model_Generic_OnOff_Status

            self.tx_handlers[0x8202] = self.tx_on_off_acked
            self.tx_handlers[0x8203] = self.tx_on_off_unacked

            self.tid = 0

        def tx_on_off_unacked(self, message):
            """
            Custom handler to send a GenericOnOff_Set_Unacke message
            """
            pkt, ctx = message
            pkt[1].transaction_id = self.tid + 1
            self.tid += 1
            return None

        def tx_on_off_acked(self, message):
            """
            Custom handler to send a GenericOnOff_Set message
            """
            pkt, ctx = message
            pkt[1].transaction_id = self.tid + 1
            self.tid += 1

            # Set the expected class of the response
            self.expected_response_clazz = BTMesh_Model_Generic_OnOff_Status

            return None

        def rx_on_on_onff_status(self, message):
            """
            Custom handler when waiting to receive an expected BTMesh_Model_Generic_OnOff_Status message
            Useless, but to show custom handlers creation for Rx in ModelClient.
            """
            pkt, ctx = message
            return None


Opcodes of model messages handled by this model are listed in `rx_handlers` with the associated handler function.
These functions handle the message and do any application level actions (could be printing the message...)
They can return a tuple with a `BTMesh_Model_Message` packet sent to the source of the message received.

The opcodes of messages handled in transmission are listed in `tx_handlers` with the associated handler function (only `ModelClient`).
These functions set some values of the message to be transmitted if necessary.