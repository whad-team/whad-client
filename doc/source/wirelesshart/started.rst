Getting started
===============

WirelessHART protocol is based on IEEE 802.15.4 (TSCH mode) and therefore relies on our Dot15d4 domain.

Sniffing packets
----------------

Sniffing WirelessHART packets is possible thanks to our dedicated :class:`whad.wihart.connector.Sniffer` class. The following code permits to capture WirelessHART packets on a cahnnel 11 :

.. code-block:: python

    from whad.device import WhadDevice
    from whad.wihart.connector import Sniffer

    # Create our whad device object
    device = WhadDevice.create("uart0")

    # Create our WirelessHART sniffer instance
    sniffer = Sniffer(device)

    # Set channel
    sniffer.channel = 11

    # Start sniffer
    sniffer.start()

    # Listen for packets for 30 seconds
    for packet in sniffer.sniff(timeout=30.0):
        packet.show()


As WirelessHART relies on a TSCH (Time Slotted Channel Hopping) mechanism, a
single channel is not enough to capture all traffic unless the network's
channel map is set to one channel. To follow all packets, the sniffer must
first find the network and learn its hopping schedule.

Finding the network is done by scanning: the advertisement frame
(:class:`WirelessHart_DataLink_Advertisement`) may be sent on any channel, so
you listen on each channel in turn until the sniffer reports it is
synchronised. Applying the channel map and the superframe/link configuration,
and enabling TSCH synchronisation, is then done automatically by the sniffer
when it processes that advertisement : you do not configure any of it manually.

Once synchronised, iterating over :meth:`sniff` follows the hopping schedule:


.. code-block:: python

    from time import sleep
    from whad.device import WhadDevice
    from whad.wihart.connector import Sniffer
    from whad.hub.dot15d4 import LinkType, LinkOptions
    from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement


    try:
        # Create our whad device object
        device = WhadDevice.create("uart0")

        # Create our WirelessHART sniffer instance
        sniffer = Sniffer(device)
            
        # Start the sniffer
        sniffer.start()

        # Enable TSCH mode on the sniffer
        sniffer.enable_tsch()

        # Check the sniffer was synchronized otherwise change channel as we consider it to be not operated
        for channel in range(11,26):
            #Set channel on which our sniffer will listen
            sniffer.channel = channel

            for packet in sniffer.sniff(timeout=1.0):
                packet.show()
            if sniffer.is_synchronized():
                break
        
        for pkt in sniffer.sniff():
            if WirelessHart_DataLink_Advertisement not in pkt:
                print(pkt.metadata, repr(pkt))

        # Sniffing must be interrupted by the user
        while True:
            sleep(1)

    except WhadDeviceNotFound:
        print("[e] Device uart0 not found.")
    except (KeyboardInterrupt, SystemExit):
        print("\n[-] Program stopped.")
    
    finally:
        try:
            if sniffer is not None:
                sniffer.stop()
            if dev is not None:
                dev.close()
        except:
            pass



Decrypting packets
------------------
As wirelessHART is an encrypted protocol, sniffed packets are not readable by default. The sniffer must be configured with the network's join key to be able to decrypt packets. 
To enable this feature, simply set the sniffer's ``decrypt`` property to True.

As follows an example of how to enable decryption and provision the join key:

.. code-block:: python

    # Set the network's join key on the sniffer 
    sniffer.add_join_key(b"ABCDABCDABCDABCD")

    # Enable decryption on the sniffer
    sniffer.decrypt = True


The recovered state of the network (join key, network key, session keys and superframes/links) can be saved to a JSON file as follows:

.. code-block:: python

    # Save the network state to a JSON file
    sniffer.save_network_state("filename.json")

The state can also be loaded from a JSON file to restore the sniffer's configuration as follows:

.. code-block:: python

    # Load the network state from a JSON file
    sniffer.load_network_state("filename.json")



Injecting packets
----------------

Injecting WirelessHART packets is possible thanks to our dedicated :class:`whad.wihart.connector.Injector` class. 
Because WirelessHART is secured and time-synchronised, an injector needs both the cryptographic material (keys and nonce counters) and the TSCH state (ASN, superframes and links). 
These are only obtained by listening to the network, so they are shared from a synchronised :class:`Sniffer`: its key store 
(``sniffer.decryptor.get_store()``) and its ``network`` object are passed to the injector, which then sees every key the sniffer discovers and the current ASN.

.. code-block:: python

    from whad.device import WhadDevice
    from whad.wihart.connector import Sniffer, Injector

    device = WhadDevice.create("uart0")

    sniffer = Sniffer(device)
    injector = Injector(
        device,
        store=sniffer.decryptor.get_store(),
        network=sniffer.network,
    )

    sniffer.add_join_key(b"ABCDABCDABCDABCD")
    sniffer.decrypt = True
    sniffer.start()
    sniffer.enable_tsch()

    # ... let the sniffer synchronise on the network (see "Sniffing packets")


A single WHAD device is driven by one connector at a time. When the sniffer and
the injector share the same device, point the device at the injector only for
the duration of an injection, then hand it back so capture resumes:

.. code-block:: python

    device.set_connector(injector)
    try:
        injector.ping_request(dst, graph=0x0001, wait_offset=2200)
    finally:
        device.set_connector(sniffer)



The injector provides the following frames (``dst`` is a device's network address):

**Ping request** probe a device:

.. code-block:: python

    injector.ping_request(dst, graph=0x0001, wait_offset=2200)



**Keep-alive** send a keep-alive from a (spoofed) source to a destination:

.. code-block:: python

    injector.send_keep_alive(0x0001, dst)

**Fake advertisement** advertise a schedule to nearby devices:

.. code-block:: python

    injector.send_fake_advertisement(dst)

**Mass de-authentication** suspend devices for a given duration (in slots),
using the broadcast session key:

.. code-block:: python

    injector.mass_de_authetication_packet(dst, duration=5000)

.. warning::

   These frames spoof legitimate network traffic and can disrupt a live
   WirelessHART network. Use them only against networks you own or are
   authorised to test.
