wbtmesh-provisionee | wbtmesh-provisioner: Bluetooth Mesh interactive shell
===========================================================================

``wbtmesh-provisionee`` and ``wbtmesh-provisioner`` commands launch an interactive shell
allowing the user to create a BTMesh node and use it to interact with the network. This tool must be used with a device
supporting the *Bluetooth Low Energy* domain.

Both commands ``wbtmesh-provisionee`` and ``wbtmesh-provisioner`` share most of the same behaviour. Their only difference
lie in the provisioning commands. ``wbtmesh-provisionee`` is a node that can be provisioner by a provisioner, while ``wbtmesh-provisioner``
can act as a provisioner (but cannot be provisioned by another provisioner).

For simplicity, The ``wbtmesh-provisionee`` command will be used as an example but ``wbtmesh-provisioner`` can be also be used. Sections about
provisioning will differentiate both commands.

.. contents:: Table of Contents
    :local:
    :depth: 2


Usage
-----

.. code-block:: text

    wble-provisionee -i <interface name>

``wbtmesh-provisionee`` command only supports a single mandatory argument with ``--interface`` (``-i``) to specify the 
WHAD interface to use. This command only functions in interactive mode.

When inside the interactive shell, you can type ``help`` to see a list of commands. ``help <command>`` shows a detailed
description of the command in argument.

Quick tutorial
--------------

``wbtmesh-provisionee`` exposes an interactive shell that provides all the required features
to create a BTMesh node. It must be started with the specific interface you want to use (in this case *uart0*):

.. code-block:: text

    $ wbtmesh-provisionee -i uart0
    wbtmesh-provisionee>


This section will introduce the most important commands to use the interactive shell in a basic way.


Elements and models
~~~~~~~~~~~~~~~~~~~

Before provisioning a node, we can change the number of elements within the local node.
After it is provisioned, a node cannot change its Elements (as per specification requirements).
For now, it is not possible to add/remove Models from Elements.
But this feature will be added in a future release.

Here, this code snippet shows how to go into Element mode and check a State value within one of that Element's Model. 
We can also read/write in States within Models.

.. code-block:: text

    wbtmesh-provisionee> element edit 0
    wbtmesh-provisionee | element(0)> model
    |─ Model Configuration Server (0x0)
    |─ Model Generic OnOff Server (0x1000)
    |─ Model Generic OnOff Client (0x1001)
    |─ Model Configuration Client (0x1)
    |─ Model Health Server (0x2)
    wbtmesh-provisionee | element(0)> model read 0x1000 generic_onoff
    In Model 0x1000 :
    |─ generic_onoff:
        |─ default: 0
    wbtmesh-provisionee | element(0)> resume
    wbtmesh-provisionee> resume


Provisioning a node
~~~~~~~~~~~~~~~~~~~

A node needs to be provisioned (that is having a NetKey and DevKey as well as an address within the network).
For that, WHAD allows you to either :

* **Auto provision the node**, that is use a set a provided keys to provision the node without an external provisioner
* **Real provisioning** via an external provisioner (provisionee node only !)

.. _auto-prov:

Auto Provisioning
^^^^^^^^^^^^^^^^^

This feature allows the local node to be provisioned with a preset of keys and address without any exterior device.
A provisioner node using ``wbtmesh-provisioner`` can only be provisioned with this method.


The ``auto-prov`` command allows the user to set the values for the auto-provisioning and launch it.

.. code-block:: text

    wbtmesh-provisionee> auto_prov unicast_addr 0x0008
    Set the auto_provision unicast_addr to 0x8
    wbtmesh-provisionee> auto_prov start
    Node has been successfully auto provisioned
    wbtmesh-provisionee [running]>

The set of commands above sets the address of the node to `0x0008` and auto provisions it.
The options for auto-provisioning are :

* ``unicast_addr`` : the unicast_addr of the node
* ``net_key`` : the net_key of the network to join
* ``dev_key`` : the DevKey of node
* ``app_key`` : an AppKey to add at index 0 of the NetKey

Then, auto-provisioning can be started via ``auto-prov start``.

Normal Provisioning (provisionee perspective)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A provisionee node (launched with ``wbtmesh-provisionee``) can be provisioned via an external provisioner.
The external provisioner can be another WHAD device or a device running the esp-idf/Zephyr OS BTMesh stacks.

For now, only the Advertising bearer is available. This means that apps on phones cannot provision a WHAD node as they
seem to only support nodes using the GATT bearer (to be confirmed).


The provisionee node can first set its capabilities using the ``prov_capabilities`` command.

.. code-block:: text

    wbtmesh-provisionee> prov_capabilities
    Provisioning Capabilities
    |─ algorithms : 3
    |─ public_key_type : 0
    |─ oob_type : 0
    |─ output_oob_size : 0
    |─ output_oob_action : 0
    |─ input_oob_size : 0
    |─ input_oob_action : 0
    wbtmesh-provisionee> prov_capabilities algorithms 1
    Successfully set algorithms to value 1
    wbtmesh-provisionee>

Once all is setup, the ``prov`` command can be used to start sending beacons and process with the provisioning.
Now, if OOB authentication is used and more specifically Input OOB, the provisionee will need to type the authentication
value provided by the provisioner via the ``prov auth`` command :

.. code-block:: text

    wbtmesh-provisionee> prov_capabilities input_oob_size 4
    Successfully set input_oob_size to value 4
    wbtmesh-provisionee> prov_capabilities input_oob_action 0b1100
    Successfully set input_oob_action to value 12
    wbtmesh-provisionee> prov
    /!\ Starting sending Unprovisioned Device Beacons, please wait ...
    /!\ You need to type the authentication value provided by the Provisioner via OOB canal. Use command 'prov auth VALUE' to resume provisioning
    wbtmesh-provisionee> prov auth 2247
    Node is provisioned
    wbtmesh-provisionee [running]>

Normal Provisioning (provisioner perspective)
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

A provisioner can provisioner other nodes. The provisioner itself has to be auto-provisioned such as described in :ref:`auto-prov`.

The following example show how to listen for beacons and provision a node. The authentication and capabilities settings/usages are the same as the previous section.

.. code-block:: text

    wbtmesh-provisioner> auto_prov start
    Node has been successfully auto provisioned
    wbtmesh-provisioner [running]> listen_beacons on
    Successfully started the beacons listening
    wbtmesh-provisioner [running]> list_unprov
    Index | Device UUID
    |─ 0 : ddddaaaa-aaaa-aa01-0000-000000000000
    wbtmesh-provisioner [running]> prov start 0
    Node is provisioned
    wbtmesh-provisioner [running]>

Sending an application message to the network
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

With a provisioned node, we can send a message to the network using our node.

The main parameters of a message can be set using the ``msg_context`` command.
This command allows to see and set the source, destination, ttl, keys,... to use for the message.

For example, to see the current parameters and change the destination address : 

.. code-block:: text

    wbtmesh-provisionee [running]> msg_context
    Message context :
    |─ (src) Source : 0x2
    |─ (dst) Destination : 0xffff
    |─ (net_key_idx) Net Key Index : 0
    |─ (app_key_idx) App Key Index : 0
    |─ (dev_key_addr) Dev Key Address : 0x2
    |─ (seq_num) Sequence Number is intended one for node
    |─ (credentials) Credentials : Managed Flooding (0)
    |─ (ttl) TTL : 0x7f
    wbtmesh-provisionee [running]> msg_context dst 0x0005
    Set message context 'Destination' to value 0x5
    wbtmesh-provisionee [running]>


Now, the command ``send_raw_access`` allows to send a Model message given in argument using the parameters of the message context.


.. code-block:: text

    wbtmesh-provisionee [running]> send_raw_access 04000000010703
    Successfully sent the message below.
    ###[ Bluetooth Mesh Access Message ]###
    opcode    = 4
    ###[ Bluetooth Mesh Model Health Current Status ]###
        test_id   = 0
        company_id= 0x0
        fault_array= b'\x01\x07\x03'

    wbtmesh-provisionee [running]>

As we can see, the node ``0x0002`` has responded with a Status response to our message and this response is displayed.

We can also use, for testing, the `Generic On/Off Model` to send On/Off messages. The destination has to implement the `Generic On/Off Server Model`.


.. code-block:: text

    wbtmesh-provisionee [running]> onoff 1
    /!\ Sending BTMesh_Model_Generic_OnOff_Set message, waiting for response.
    Status reponse received from node.
    ###[ Bluetooth Mesh Access Message ]###
    opcode    = 33284
    ###[ Bluetooth Mesh Model Generic OnOff Status ]###
        present_onoff= on
        target_onoff= None

    wbtmesh-provisionee [running]>

Attacks
^^^^^^^

The interactive shell allows you to configure and run attacks defined in the `whad.btmesh.attacker` directory.
You can go into `Attack` mode by using the `attacks` command :


.. code-block:: text

    wbtmesh-provisionee [running]> attacks
    LinkCloserAttack: Reacts on Provisionning packets to close the link and deny the Provisionning of all nodes.
    SeqNumDesynchAttack: Leverages the RPL of nodes by sending spoofed messages with a very high sequence number to create DoS.
    PathPoisonBidir: Tries to poison DF paths via a bidirectional path poisoned. (A3)
    PathPoisonSolicitation: Tries to poison DF paths via Path Solicitation to force victims to create paths that we poison. (A4)
    PathPoisonHijack: Tries to poison DF paths via hijacking of Path Reply and bypass of DF resilience features (A2)
    wbtmesh-provisionee [running]> attacks SeqNumDesynchAttack
    wbtmesh-provisionee | SeqNumDesynchAttack>


When in attack mode, a specific attack is selected and can be configured using the ``configure`` command.
Without any arguments the ``configure`` command describes the parameters and their description.


.. code-block:: text

    wbtmesh-provisionee | SeqNumDesynchAttack> configure victims 0x0005 0x0006
    Successfully set the parameter victims to value [5, 6]
    wbtmesh-provisionee | SeqNumDesynchAttack>


From that, the ``run`` command allows you to run the attack (can be run asynchronously or asynchronously). If asynchronous attack, ``stop`` to stop the attack.
Finally, we can check the result of the attack using the ``check`` command and quit the attack mode with ``resume``

.. code-block:: text

    wbtmesh-provisionee | SeqNumDesynchAttack> run synch
    /!\ Running the attack...
    The attack is complete.
    Attack performed, nothing to display. Try sending a message from victim to targets.
    wbtmesh-provisionee | SeqNumDesynchAttack> resume
    wbtmesh-provisionee [running]>


Interactive shell
-----------------

.. _periph-interactive-shell:

The interactive shell offers the possibility to dynamically create any BTMesh node.
It supports auto completion for most parameters.

Within the shell, type the ``help`` command to list all commands, and specify a command to get a detailed description.

Be aware that within the shell, the node can be in different modes :

* **NORMAL** : Mode when entering shell, unprovisioned node
* **STARTED** : Node provisioned and running
* **ELEMENT** : When editing an Elements
* **ATTACK** : When running and configuring an attack

The ``resume`` command is used to go from **Element** and **Attack** modes to **Started** mode if provisioned, or **Normal** mode if unprovisioned.

.. code-block:: text

    help <command>

address
^^^^^^^

**Started** mode only.

.. code-block:: text

    address [ADDRESS]

This command allows to change the local node's primary unicast address.
Without any argument, it prints the address of the node.

.. code-block:: text

    wbtmesh-provisionee [running]> address
    The primary unicast address of the node is 0x2
    wbtmesh-provisionee [running]> address 0x0003
    Address of the device is now : 0x3
    wbtmesh-provisionee [running]>

.. _appkeys_command:

app_keys
~~~~~~~~

**Started** mode only.

.. code-block:: text

    app_keys [ACTION] [APP_KEY_IDX] [NET_KEY_IDX] [APP_KEY_VALUE | DISTANT_NODE_ADDR]

This command can add/update, remove and send AppKeys.

To list the AppKeys of the node, we can use the `list` action : 

.. code-block:: text

    wbtmesh-provisionee [running]> app_keys list
    |─ Index : 0 Bounded to NetKey : 0 Key : 63964771734fbd76e3b40519d1d94a48


The `update` action allows to update an AppKey value or create it if not already present.
Below is the update/addition of AppKey bound to NetKey 0 at index 1 : 

.. code-block:: text

    wbtmesh-provisionee [running]> app_keys update 1 0 aab2255e6422d330088e
    09bb015ed707
    Update of app_key successfull

The `remove` action can be used to remove an AppKey : 


.. code-block:: text

    wbtmesh-provisionee [running]> app_keys remove 1 0
    Successfully removed AppKey with index 1 bound to NetKey 0

Finally, to send an AppKey to a distant node (with their DevKey), use the `send` command. See how to list and manage distant nodes in the :ref:`nodes_command`.

.. code-block:: text

    wbtmesh-provisionee [running]> app_keys send 1 0 0x0004
    /!\ Sending appkey to distant node...
    Successfully sent the app_key to the distant node

net_keys
~~~~~~~~

**Started** mode only.

.. code-block:: text

    net_keys [ACTION] [NET_KEY_IDX] [NET_KEY_VALUE]

This command can add/update and remove NetKeys. This command is very similar to the :ref:`appkeys_command`.
The ony differences lie in that the `net_keys` command only needs one key index per command, and that we cannot send a net_key using this command.

.. _nodes_command:

nodes
~~~~~

**Started** mode only.

.. code-block:: text

    nodes [ACTION] [PRIMARY_NODE_ADDR] [VALUES]

This command is used to managed the information stored on the local node about distant node (and itself) within the network.
The information managed by this command include : 

* **Addresses and ranges** of nodes
* **Elements and models** implemented by the nodes
* **The DevKeys** of the nodes

When a Provisioner node provisions a new distant node, its information is automatically added to the database. But we can manually add distant nodes as well using the `add` action :

.. code-block:: text

    wbtmesh-provisionee [running]> nodes add 0x0010
    Addition of new distant node successfull
    wbtmesh-provisionee [running]> nodes
    Address: 0x10 -> 0x10
    DevKey : 63964771734fbd76e3b40519d1d94a48
    No Elements listed. Try `nodes get_composition` command

    Local Node Address: 0x2 -> 0x2
    DevKey : 63964771734fbd76e3b40519d1d94a48
    Element 0:
    |─ Model : Configuration Server (0x0)
    |─ Model : Generic OnOff Server (0x1000)
    |─ Model : Generic OnOff Client (0x1001)
    |─ Model : Configuration Client (0x1)
    |─ Model : Health Server (0x2)

Conversly we can remove a node from the local databse using the `remove` action.

When manually adding a distant node, a default DevKey is added (which would probably not function). To change the value of the DevKey stored in the local database for a given node, use the `dev_key` action : 

.. code-block:: text

    wbtmesh-provisionee [running]> nodes dev_key 0x0010 aabb4771734fbd76e3b40519d1d94a48
    Update of dev_key successfull

If no address is specified with the `dev_key` action, this will change the local node's DevKey : 

.. code-block:: text

    wbtmesh-provisionee [running]> nodes dev_key aabb4771734fbd76e3b40519d1d94a48
    Update of dev_key successfull

Finally, provided that we have the correct DevKey for a node, the `get_composition` action can be used to retrive its Element and Models via a message :

.. code-block:: text

    wbtmesh-provisionee [running]> nodes get_composition 0x0010
    /!\ Fetching CompositionData page 0...
    Successfully fetched CompositionData page 0.
    Element 0:
    |─ Model : Configuration Server (0x0)
    |─ Model : Generic OnOff Server (0x1000)
    |─ Model : Generic OnOff Client (0x1001)
    |─ Model : Configuration Client (0x1)
    |─ Model : Health Server (0x2)


relay
~~~~~

**Started** mode only.

.. code-block:: text

    relay  ["on"|"off"]

This commands activates or deactivates the relay feature of the local node. If activated, the local node will relay packets not intended to it 
if the TTL is greater than 1. By default, this feature is deactivated.

seqnum
~~~~~~

**Started** mode only.

.. code-block:: text

    seqnum [SEQNUM]

Sets the local node's automatically managed sequence number to the given value. If no value given, prints the current value.

whitelist
~~~~~~~~~

**Started** mode only.

.. code-block:: text

    whitelist [ACTION] [BD_ADDR]

WHAD allows the local node to filter out messages based on the BD Address of BLE packets (and thus Bluetooth Mesh packets). 
Since the BD Address is irrelevant for the BTMesh procotol, we use it to simulate topologies for experiments.

By default, the BD address of a WHAD node is based on its primary unicast address and is "AA:AA:AA:AA:AA:addr" (LSB).

To reset the whitlist (and allow all messages), use the `reset` action. (By default, whitelist empty)

.. code-block:: text

    wbtmesh-provisionee [running]> whitelist reset
    Successfully reset the whitelist

To add an address to the whitelist, use `add` : (case not important) 

.. code-block:: text

    wbtmesh-provisionee [running]> whitelist add AA:AA:AA:AA:AA:08
    Successfully added addr aa:aa:aa:aa:aa:08 to the whitelist.

bind_app_keys 
~~~~~~~~~~~~~

**Started** mode only.

.. code-block:: text

    bind_app_keys NODE_PRIMARY_ADDRESS ELEMENT_IDX MODEL_ID APP_KEY_IDX

This command allows the local node to send a Configuration message to a distant node. The distant node needs to be added/present (see :ref:`nodes_command`).
The message sent is a `Config Model App Bind` message sent using the stored DevKey for the destination node.

If a success, we receive a Status message and a success message is displayed.


.. code-block:: text

    wbtmesh-provisionee [running]> bind_app_key 0x05 1 0x1000 1
    Successfully binded the app key to the model.


.. _msg_context_command:

msg_context
~~~~~~~~~~~

**Started** mode only.

.. code-block:: text

    msg_context [PARAM_TYPE] [VALUE]

This command manages the parameters of the messages sent using the `send_raw_access` and `onoff` commands. The parameters in question are :

- **dst** : The destination address (default 0xffff)
- **src** : The source address (default the primary unicast address of the node)
- **net_key_idx** : The net_key_index used (default 0)
- **app_key_idx** : The app_key_index used (default 0). Value is -1 if devkey used.
- **dev_key_addr** : The address of the node we used the devkey of for the message. (default the primary unicast address of the node)
- **seq_num** : The sequence number to use (default is intended sequence number for the node)
- **credentials** : The credentials for the message(default 0, Managed Flooding). 0 for MF, 1 for Friend (not supported yet), 2 for Directed Forwarding (doesnt check/init paths)
- **ttl** : The TTL to use (default : 0x7f)

To set a value, use the name of the parameter followed by its value.

.. code-block:: text

    wbtmesh-provisionee [running]> msg_context dst 0x0009
    Set message context 'Destination' to value 0x9


onoff
~~~~~

**Started** mode only.

.. code-block:: text

    onoff ["1"|"0"]

This command allows to send, using the parameters set with :ref:`msg_context_command`, a `Generic On/Off Set Message`.
The value in parameter is whether we send an `on` or `off` message. Tnis message expects an Status message in response and if received, interface displays it.


.. code-block:: text

    wbtmesh-provisionee [running]> onoff 1
    /!\ Sending BTMesh_Model_Generic_OnOff_Set message, waiting for response.
    Status reponse received from node.
    ###[ Bluetooth Mesh Access Message ]###
    opcode    = 33284
    ###[ Bluetooth Mesh Model Generic OnOff Status ]###
        present_onoff= on
        target_onoff= None

.. important::

    Do not forget to use `msg_context app_key_idx <value>` to set the AppKey index to use ! 
    Should be 0 most of the time for testing ...


secure_network_beacon
~~~~~~~~~~~~~~~~~~~~~

**Started** mode only.

.. code-block:: text

    secure_network_beacon 0|1 0|1

Sends a `Secure Network Beacon` using the NetKey at index 0. The first argument is the key refresh flag, the second the IV update flag.


send_raw_access
~~~~~~~~~~~~~~~

**Started** mode only.

.. code-block:: text

    send_raw_access RAW_MESSAGE

This commands sends an Access message using the parameters set via :ref:`msg_context_command`. The argument is the hex string of the Model message.
In python, in order to get the raw message, you can create it in the interpreter, for example :

.. code-block:: python

    >>> from whad.scapy.layers.btmesh import BTMesh_Model_Generic_OnOff_Set, BTMesh_Model_Message
    >>> from scapy.packet import raw
    >>> pkt = BTMesh_Model_Message() / BTMesh_Model_Generic_OnOff_Set(onoff=1)
    >>> raw(pkt).hex()
    '82020100'

Now, we can send the message :

.. code-block:: text

    wbtmesh-provisionee [running]> send_raw_access 82020100
    Successfully sent the message below.
    ###[ Bluetooth Mesh Access Message ]###
    opcode    = 33282
    ###[ Bluetooth Mesh Model Generic OnOff Set ]###
        onoff     = on
        transaction_id= 0
        transition_time= None


This command does not use any Client Models, and thus cannot interpret any responses.


attacks
~~~~~~~

**Started** or **Normal** modes only (depends on the attack).

.. code-block:: text

    attacks ATTACK_NAME

From the **Normal** or **Started** modes, go into **Attack** mode for the specified attack.
No attack name specified will display available attacks.


.. code-block:: text

    wbtmesh-provisionee [running]> attacks LinkCloserAttack
    wbtmesh-provisionee | LinkCloserAttack>


configure
~~~~~~~~~

**Attack** mode only.

.. code-block:: text

    configure PARAM_NAME [VALUE(S)]


This command manages the parameters of the selected attack. No argument for this command will display a description of the fields.

.. code-block:: text

    wbtmesh-provisionee | LinkCloserAttack> configure
    Parameters for attack LinkCloserAttack
    |─ timeout (int | NoneType) (None) :  Timeout (sec) of the attack before quitting. Infinite if not specified (None).
    wbtmesh-provisionee | LinkCloserAttack> configure timeout 5
    Successfully set the parameter timeout to value 5

run
~~~

**Attack** mode only.

.. code-block:: text

    run [SYNCH|ASYNCH]


Launches and run the attack specified with the configuration in place. Can be run synchronously (interface blocked while waiting) or synchronously.
If not specified, runs in the default mode for the attack (adviced).


stop
~~~~

**Attack** mode only.

.. code-block:: text

    stop

Stops the attack from running (if asynchronous).


check
~~~~~

**Attack** mode only.

.. code-block:: text

    check

Prints the current state of the attack (running, finished, not started...) and potentially results from an attack that was run.


element
~~~~~~~

**Started** and **Normal** modes only.


.. code-block:: text

    element [ACTION [PARAMS]]T


This command manages the elements of the local nodes. The different actions allows to list, add, remove or modify elements.
By default, if no action specified, lists the elements of the local node.


The `add` action adds a new element to the local node. The index of the added Element is the next available.

.. code-block:: text

    wbtmesh-provisionee> element add
    Element 1 successfully added.


The `remove` action allows the removal of added Elements :

.. code-block:: text

    wbtmesh-provisionee> element remove 1
    Successfully removed element at index 1.


Finally, the `edit` action allows to go into the **Element** mode for the specified Element (and manage its Models).

.. code-block:: text

    wbtmesh-provisionee> element edit 0
    wbtmesh-provisionee | element(0)>

.. important::

    Elements and Models can only be added/removed before provisioning of the local node !


model
~~~~~

**Element** mode only.

.. code-block:: text

    model [ACTION] [MODEL_ID] [PARAMS]]

This command allows for the management of Models within the Element we are in edit mode in. No action specified will list the Models of the Element.

The `read` action allows to list the values of the states of the specified model. It is possible to list all states or only one.
If the state is a CompositeState, we can also chosse to only display a substate by using the `composite_state.sub_state` format for the name.

Autocompletion functions for this command and allows to choose the states to show based on the MODEL_ID parameter typed.


.. code-block:: text

    wbtmesh-provisionee | element(0)> model read 0x0 network_transmit
    In Model 0x0 :
    |─ network_transmit:
        |─ network_transmit_count:
            |─ default: 0
        |─ network_transmit_interval_steps:
            |─ default: 0
    wbtmesh-provisionee | element(0)> model read 0x0 network_transmit.network_transmit_count
    In Model 0x0 :
    |─ network_transmit:
    |─ network_transmit.network_transmit_count:
        |─ default: 0


The `write` action permits to write a value in a state.

.. code-block:: text

    wbtmesh-provisionee | element(0)> model write 0x2 current_health.current_health_fault 1
    Successfully set the value for the state.


.. _network_discovery_command:

network_discovery
~~~~~~~~~~~~~~~~~

**Started** mode only.

.. code-block:: text

    network_discovery addr_low addr_low [delay]

This command performs a discovery of the nodes present within the network when the nodes are configured to use Directed Forwarding (DF).
This methods tries to create a DF path for all adresses between the arguments `addr_low` and `addr_high`. Only the nodes that exist will respond.

The result of the discovery will be displayed when using the :ref:`nodes_command`. The `delay` argument is used to customize the delay between the creation of 2 consecutive paths (a longer delay avoids collision of packets/failure of path creation).

.. code-block:: text

    wbtmesh-provisionee [running]> network_discovery 0x02 0x05 1
    Successfully started the network_discovery attack.
    Wait a little to use the `nodes` command, in about 4.0 seconds



get_hops
~~~~~~~~

**Started** mode only.

.. code-block:: text

    get_hops

This command should be used after the usage of :ref:`network_discovery_command`. It uses another set of Directed Forwarding feature to 
estimate the distance (in number of hops) between the local WHAD node and every node discovered via :ref:`network_discovery_command`.

The results are available using the :ref:`nodes_command`.

.. code-block:: text

    wbtmesh-provisionee [running]> get_hops
    Successfully launched distance evaluation of discovered nodes. Launch 'nodes' to see results in about 0.5 seconds.
    wbtmesh-provisionee [running]> nodes
    Address: 0x3 -> 0x3 | 0 hops away
    DevKey : 63964771734fbd76e3b40519d1d94a48
    No Elements listed. Try `nodes get_composition` command


auto_prov
~~~~~~~~~

**Normal** mode only.

.. code-block:: text

    auto_prov ["net_key"|"dev_key"|"app_key"|"unicast_addr"|"start"] VALUE


This command can be used with ``wbtmesh-provisionee`` or ``wbtmesh-provisioner`` commands. In the case of the ``wbtmesh-provisioner``
mode, the `auto_prov` command is the only way to provision the node.

In order to set parameters before performing the auto_provisioning, the `auto_prov <field> <value>` syntax can be used.


.. code-block:: text

    wbtmesh-provisionee> auto_prov unicast_addr 0x05
    Set the auto_provision unicast_addr to 0x5


Then, to perform the auto-provisioning, the `start` action is used.


.. code-block:: text

    wbtmesh-provisionee> auto_prov start
    Node has been successfully auto provisioned
    wbtmesh-provisionee [running]>

prov_capabilities
~~~~~~~~~~~~~~~~~

.. code-block:: text

    prov_capabilities ["algorithms"|"public_key_type"|"oob_type"|"output_oob_size"|"output_oob_action"|"input_oob_size"|"input_oob_action"] VALUE


This command allows to see and set the provisioning capabilities values of the local node. For a provisionee node, this will be
 used once when provisioned. For a provisioner node, this will be used everytime a node is provisioned by it. 


.. code-block:: text

    wbtmesh-provisionee> prov_capabilities
    Provisioning Capabilities
    |─ algorithms : 3
    |─ public_key_type : 0
    |─ oob_type : 0
    |─ output_oob_size : 0
    |─ output_oob_action : 0
    |─ input_oob_size : 0
    |─ input_oob_action : 0
    wbtmesh-provisionee> prov_capabilities algorithms 1
    Successfully set algorithms to value 1


prov
~~~~

**Normal** mode only. ``wbtmesh-provisionee`` only.

.. code-block:: text

    prov ACTION VALUE


This command allows a Provisionee node to be provisioned. 

The `start` action starts the sending of `Unprovisioned Device Beacons` and performs the Provisioning when a Provisioner node initiates it.


.. code-block:: text

    wbtmesh-provisionee> prov start
    /!\ Starting sending Unprovisioned Device Beacons, please wait ...
    Node is provisioned
    wbtmesh-provisionee [running]>

In the case where OOB authentication is used, the provisionee might have to input a pin value. This can be done via the `auth` action.

.. code-block:: text

    wbtmesh-provisionee> prov start
    /!\ Starting sending Unprovisioned Device Beacons, please wait ...
    /!\ You need to type the authentication value provided by the Provisioner via OOB canal. Use command 'prov auth VALUE' to resume provisioning
    wbtmesh-provisionee> prov auth 9557
    Node is provisioned
    wbtmesh-provisionee [running]>


.. _listen_beacons_command:

listen_beacons
~~~~~~~~~~~~~~

**Started** mode only. ``wbtmesh-provisioner`` only.

.. code-block:: text

    listen_beacons ["on"/"off"]

On a provisioned Provisioner node, this command actiavates or deativates the monitoring of `Unprovisioned Device Beacons`.
`Unprovisioned Device Beacon` received will be available with the :ref:`list_unprov_command`.

.. code-block:: text

    wbtmesh-provisioner [running]> listen_beacons on
    Successfully started the beacons listening


.. _list_unprov_command:

list_unprov
~~~~~~~~~~~

**Started** mode only. ``wbtmesh-provisioner`` only.

.. code-block:: text

    list_unprov

This command allows to see the list if devices wainting for a provisioning that we can provision.
A device is added to the list when it sends an `Unprovisioned Device Beacon` and we are listening for beacons (see :ref:`listen_beacons_command`).

.. code-block:: text

    wbtmesh-provisioner [running]> list_unprov
    Index | Device UUID
    |─ 0 : ddddaaaa-aaaa-aa01-0000-000000000000

When a device is provisioned by the WHAD provisioner node, it is removed from the list.


prov_distant
~~~~~~~~~~~~

**Started** mode only. ``wbtmesh-provisioner`` only.

.. code-block:: text

    prov_distant ["start"|"auth"] index|value


This command is used by a Provisoner node to provision a distant node that sent an `Unprovisioned Device Beacon` we received.
Using the :ref:`list_unprov_command`, choose the index of the device to provision t start it with the `start` action.


.. code-block:: text

    wbtmesh-provisioner [running]> prov_distant start 0
    Node is provisioned

The information about the distant provisioned node is available with the :ref:`nodes_command`.

If OOB is used, the Provisioner might need to enter an authentication pin in the console. Use the `auth` action for that.

.. code-block:: text

    wbtmesh-provisioner [running]> prov_distant start 0
    /!\ You need to type the authentication value provided by the Provisioner via OOB canal. Use command 'prov auth VALUE' to resume provisioning
    wbtmesh-provisioner [running]> prov_distant auth Z7Jg
    Distant Node is provisioned