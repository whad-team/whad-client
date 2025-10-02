Getting started
===============

Sniff unciphered BM traffic
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the :class:`whad.btmesh.connector.sniffer.BTMeshSniffer` class to instantiate a sniffer device
and listen to all traffic. By default unciphered.

Use the :class:`whad.btmesh.sniffing.SnifferConfiguration` to configure the sniffer (and add deciphering options).


.. code-block:: python

    from whad.device import WhadDevice
    from whad.btmesh.connector.sniffer import Sniffer

    dev = WhadDevice.create("uart0")
    sniffer = Sniffer(dev)
    sniffer.configure()
    sniffer.start()

    for pkt in sniffer.sniff(timeout=30):
        pkt.show()
        print(pkt.metadata)



Create a provisionee node ("normal" node) with preset keys (auto-provisioned)
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the :class:`whad.btmesh.connector.provisionee.Provisionee` class to create a BM provisionee node.
It will be automacally provisioned with a preset of given keys and default profile for element and models.

.. code-block:: python

    from whad.device import WhadDevice
    from whad.btmesh.connector.provisionee import Provisionee

    dev = WhadDevice.create("uart0")
    provisionee = Provisionee(
        dev,
        net_key=bytes.fromhex("f7a2a44f8e8a8029064f173ddc1e2b00"),
        dev_app_key=bytes.fromhex("63964771734fbd76e3b40519d1d94a48"),
        unicast_addr=0x0002,
    )

    profile = provisionee.profile
    profile.auto_provision()
    provisionee.start()


This device implements the Generic On/Off server on the primary element. 
The `Provisionee` connector can be used to send messages on the network.

Create a provisionee node ("normal" node) and wait for provisioning
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~


Use the :class:`whad.btmesh.connector.provisionee.Provisionee` class to create a BM provisionee node.
We send Unprovisioned Device Beacons until the node is provisioned by a Provisioner node.

.. code-block:: python

    from whad.device import WhadDevice
    from whad.btmesh.connector.provisionee import Provisionee
    from time import sleep

    dev = WhadDevice.create("uart0")

    provisionee = Provisionee(dev)
    provisionee.start_provisioning()

    if provisionee.profile.is_provisioned:
        print("Node is provisioned !")
    else:
        print("Node has not been provisioned")
        dev.close()
        exit(1)

    print("Node is provisioned !")


Create a provisioner node and provision nodes that send beacons
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Use the :class:`whad.btmesh.connector.provisioner.Provisioner` class to create a BM provisioner node.
It needs to be auto provisioned, and then waits for Unprovisioned Device Beacons to arrive in ordrer to provision them.
This code will provision any node sending beacons directly. OOB Authentication is supported but needs to be handled in code.


.. code-block:: python

    from whad.device import WhadDevice
    from whad.btmesh.connector.provisioner import Provisioner
    from time import sleep


    dev = WhadDevice.create("uart0")

    # Auto provision node
    provisioner = Provisioner(dev)
    provisioner.profile.auto_provision()
    provisioner.start()
    print("Provisionner started\n")

    provisioner.start_listening_beacons()

    while True:
        devices = provisioner.get_unprovisioned_devices() 
        if len(devices) > 0:
            print("Provisioning node ...")
            res = provisioner.provision_distant_node(devices[0])
            if res:
                print("Successfully provisioned device\n")
            else:
                print("Failed to provision deviced...\n")
        sleep(0.5)



Send a PDU from a client Model
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Using a provisioned connector (Provisionee/Provisioner), use the `send_model_message()` function to send a message from a client model.
Here, we send a Generic OnOff set message to the broadcast address.

.. code-block:: python

    from whad.exceptions import WhadDeviceNotFound

    from whad.device import WhadDevice
    from whad.btmesh.connector.provisionee import Provisionee
    from time import sleep
    from whad.btmesh.stack.utils import MeshMessageContext
    from whad.scapy.layers.btmesh import BTMesh_Model_Generic_OnOff_Set


    dev = WhadDevice.create("uart0")

    provisionee = Provisionee(dev)
    provisionee.start()

    profile = provisionee.profile
    profile.auto_provision()

    # retrieve generic onoff client of the local node of primary element
    model = provisionee.profile.local_node.get_element(0).get_model_by_id(0x1001)

    if model is None:
        print(
            "this profile does not implement the generic onoff client in primary element, fail."
        )
        dev.close()
        exit(1)

    # Create context of message to send
    ctx = MeshMessageContext()
    ctx.src_addr = provisionee.profile.get_primary_element_addr()
    ctx.dest_addr = 0xFFFF
    ctx.application_key_index = 0
    ctx.net_key_id = 0
    ctx.ttl = 127

    onoff = 0

    while True:
        # the packet to send (we switch between 0 and 1)
        pkt = BTMesh_Model_Generic_OnOff_Set(onoff=onoff)
        print("\nSending message to 0x%x...\n" % ctx.dest_addr)
        response = provisionee.send_model_message(
            model=model, message=(pkt, ctx), is_acked=False
        )
        onoff = int(not onoff)
        sleep(5)


Optionally, you can expect the Status response with the `response` variable. In that case you can specify a timeout for the delay to wait for the Status response.