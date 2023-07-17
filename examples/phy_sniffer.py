from whad.phy import Phy, Endianness, OOKModulationScheme, PhysicalLayer, TXPower
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.phy.utils.helpers import get_physical_layers_by_domain
from time import time,sleep
import sys

'''
def deobfuscate(p):
  deobfuscated = [p[0]]
  for i in range(1, len(p)):
    deobfuscated.append(p[i-1] ^ p[i])
  return bytes(deobfuscated)

def checksum(p):
  pinit = bytes([p[0], p[1] & 0xF0]) + p[2:]
  cksum = 0
  for i in pinit:
    cksum = cksum ^ i ^ (i >> 4)
  return cksum & 0xF


def decoding(data, configuration):
    # Convert input data into a sequence of bits
    bitstring = "".join(["{:08b}".format(i) for i in data])

    # Convert symbols into tuple of (symbol, duration)
    splitted_bitstring  = []
    previous_symbol = bitstring[0]
    count = 1
    for i in bitstring[1:]:
      if previous_symbol == i:
        count += 1
      else:
        splitted_bitstring.append((previous_symbol, count))
        previous_symbol = i
        count = 0
    splitted_bitstring.append((previous_symbol, count))

    # identify end of hardware sync / end of frame based on duration

    start = end = None
    for i in range(len(splitted_bitstring)-1):
      if (splitted_bitstring[i][0] == "0" and splitted_bitstring[i][1] >= 10 and splitted_bitstring[i][1] <= 14 and
      splitted_bitstring[i+1][0] == "1" and splitted_bitstring[i+1][1] >= 19 and splitted_bitstring[i+1][1] <= 25):
        start = i+2
      if splitted_bitstring[i][0] == "0" and splitted_bitstring[i][1] >= 7:
        end = i

    if end is None:
        end = len(splitted_bitstring)
    # split merged symbols
    if start is not None:
        symlist = []
        for sym in splitted_bitstring[start:end]:
          if sym[1] > 3:
            symlist.append(sym[0])
            symlist.append(sym[0])
          else:
            symlist.append(sym[0])

        # Crop potentially repeated patterns at the beginning of frame
        i = 0
        while len(symlist) > 2 and symlist[0] == symlist[1]:
            symlist = symlist[1:]

        # Manchester decoding
        manchester_decoded = ""
        for i in range(0, len(symlist)-1, 2):
          if symlist[i:i+2] == ["0", "1"]:
            manchester_decoded += "1"
          elif symlist[i:i+2] == ["1", "0"]:
            manchester_decoded += "0"
          else:
              return None

        if manchester_decoded.startswith("1010"):
            return deobfuscate(bytes(
                [int(manchester_decoded[i:i+8], 2) for i in range(0, 56, 8)]
            ))

somfy = PhysicalLayer(
modulation=OOKModulationScheme(),
datarate=2416*2,
endianness=Endianness.BIG,
frequency_range=(433420000, 433420000),
maximum_packet_size=250,
synchronization_word=b"",
configuration=None,
scapy_layer=None,
frequency_to_channel_function=lambda _:0,
channel_to_frequency_function=lambda _:433420000,
format_address_function=lambda address:pack(">I", address)[3:],
integrity_function=lambda d:checksum(d) == (d[1] & 0xF),
encoding_function=None,
decoding_function=decoding,
)
'''
if __name__ == '__main__':
    # Connect to target device and performs discovery
    try:
        def show_packet(pkt):
            print(repr(pkt.metadata))
            pkt.show()

        dev = WhadDevice.create("yardstickone")
        sniffer1 = Phy(dev)

        sniffer1.attach_callback(show_packet)

        print(sniffer1.get_supported_frequencies())
        '''
        sniffer1.set_frequency(2402000000)
        sniffer1.set_packet_size(250)
        sniffer1.set_datarate(2000000)
        sniffer1.set_gfsk(deviation=500000)
        sniffer1.set_endianness(Endianness.BIG)
        sniffer1.set_sync_word(bytes.fromhex("aa"))
        '''

        # https://fsec404.github.io/blog/Shanon-entropy/
        sniffer1.set_frequency(433920000)
        sniffer1.set_packet_size(250)
        sniffer1.set_datarate(10000)
        sniffer1.set_ask()
        #sniffer1.set_4fsk(1950)
        sniffer1.set_endianness(Endianness.BIG)
        sniffer1.set_sync_word(b"")
        sniffer1.set_tx_power(TXPower.HIGH)
        '''
        sniffer1.set_physical_layer(somfy)
        sniffer1.set_channel(0)
        '''
        sniffer1.sniff_phy()
        sniffer1.start()
        while True:
            input()
            sniffer1.send(bytes.fromhex("f0007fff07fff83e000000000000000001fffe0f80007fff07fff83e0001f0001fffe0f80007c0007c0003e0003fffc1fffe0f8000ffff07fff83fffc3f0001f0000f8000fc0007fff83e0003fffc1fffe0fffe07c0007fff83e0001f0001fffe0ffff07c000000000000000003fffc1f0000fffe0ffff07c0003e0003fffc1f0000f8000f80007c0007fff83fffc1f0001fffe0ffff07fff87e0003e0001f0001f0000fffe0fc0007fff07fff83fffc1f0001fffe0f80007c0007fff83fffc1f000000000000000"))




    except (KeyboardInterrupt, SystemExit):
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)
