import sys
from time import sleep
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.common.monitors import WiresharkMonitor
from whad.wirelesshart.connector import Sniffer
from whad.hub.dot15d4 import LinkType, LinkOptions
from whad.scapy.layers.wirelesshart import WirelessHart_DataLink_Advertisement, Superframe, Link
import logging

adv = None
def show_packet(packet):
    global adv
    print(packet.metadata, packet.metadata.timestamp - packet.metadata.start_of_slot_timestamp)
    print(repr(packet))
    if packet.metadata.decrypted:
        packet.decrypted.show()
    print()

    if WirelessHart_DataLink_Advertisement in packet:
        adv = packet

if __name__ == '__main__':

    if len(sys.argv) >= 3:
        # Retrieve target interface

        interface = sys.argv[1]
        channel = sys.argv[2]
        try:
            
            dev = WhadDevice.create(interface)

            m = WiresharkMonitor()
            # Instantiate a sniffer
            sniffer = Sniffer(dev)
            m.attach(sniffer)
            m.start()
            sniffer.channel = int(channel)
            sniffer.add_join_key(b"ABCDABCDABCDABCD")
            sniffer.decrypt = True
            sniffer.start()
            sniffer.enable_tsch()
            
            sniffer.attach_callback(show_packet)

            try:
                channels = range(11, 26)

                while adv is None:
                    for channel in channels:
                        sniffer.channel = channel
                        sleep(1)

                sniffer.set_channel_map(adv.channel_map)
                print("Setting channel map: ", adv.channel_map)
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
                print(sniffer.add_link(
                    superframe_id=0,               # Souvent l'ID 0
                    source=adv.src_addr,           # L'adresse du Master (Gateway)
                    time_slot=0,                   # Le slot 0 est le slot de balise standard
                    channel_offset=0,              # Offset 0 par défaut
                    neighbor=0xFFFF,               # Broadcast
                    options=LinkOptions.RECEIVE,   # On veut écouter
                    link_type=LinkType.DISCOVERY   # Type Discovery (ou NORMAL/JOIN selon ta version de WHAD)
                ))
                while True:
                    sleep(1)
            except (KeyboardInterrupt, SystemExit):
                dev.close()
            

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
