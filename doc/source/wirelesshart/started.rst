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


As WirelessHART relies on a TSCH (Time Slotted Channel Hopping) mechanism, a single channel is not enough to capture all traffic unless the network's channel map is set to one channel. 
Therefore, the sniffer can be configured to hop between channels in order to follow all packets. It must therefore learn the hopping schedule (superframes and links) advertised by the network's gateway to be able afterwards to hop accordingly. 
To properlyfollow a network, the sniffer must:

1. Hop across all available channels until an advertisement frame
   (:class:`WirelessHart_DataLink_Advertisement`) is captured 
2. Apply the channel map and superframe/link configuration carried by this
   advertisement 
3. Enable TSCH synchronization on the sniffer

.. code-block:: python

    from time import sleep
    from whad.device import WhadDevice
    from whad.wihart.connector import Sniffer
    from whad.hub.dot15d4 import LinkType, LinkOptions
    from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement

    adv = None

    # Callback to capture first advertisement frame and show packets
    def show_packet(packet):
        global adv
        print(packet.metadata, packet.metadata.timestamp - packet.metadata.start_of_slot_timestamp)
        packet.show()
        print()

        if WirelessHart_DataLink_Advertisement in packet:
            adv = packet

    # Create our whad device object
    device = WhadDevice.create("uart0")

    # Create our WirelessHART sniffer instance
    sniffer = Sniffer(device)

    # Start the sniffer
    sniffer.start()

    # Enable TSCH mode on the sniffer
    sniffer.enable_tsch()

    # Attach a callback to capture packets
    sniffer.attach_callback(show_packet)

    try:
        # Set channels to all available channels from 11 to 25 included
        channels = range(11, 26)

        # While we have not captured an advertisement frame, hop across all channels
        while adv is None:
            for channel in channels:
                sniffer.channel = channel
                sleep(1)

        # Set the channel map
        sniffer.set_channel_map(adv.channel_map)
        print("Setting channel map: ", adv.channel_map)

        # Update the superframe and link configuration on the sniffer 
        for superframe in adv.superframes:
            print(sniffer.update_superframe(
                superframe_id=superframe.superframe_id,
                number_of_slots=superframe.superframe_number_of_slots, 
                flags=0,
                asn=0
            ))
            for link in superframe.superframe_links:
                print("\t -> ", link)
                print(sniffer.add_link(
                    superframe_id=superframe.superframe_id, 
                    source=adv.src_addr,
                    time_slot=link.link_join_slot,
                    channel_offset=link.link_channel_offset,
                    neighbor=0xFFFF,
                    options=LinkOptions.RECEIVE,
                    link_type=LinkType.JOIN
                ))
        print("waiting...")
        print("injecting default adv link...")
        
        # Add default advertisement link
        print(sniffer.add_link(
            superframe_id=0,              
            source=adv.src_addr,          
            time_slot=0,                   
            channel_offset=0,              
            neighbor=0xFFFF,               
            options=LinkOptions.RECEIVE,   
            link_type=LinkType.DISCOVERY   
        ))

        # Sniffing must be interrupted by the user
        while True:
            sleep(1)
    except (KeyboardInterrupt, SystemExit):
        device.close()



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
