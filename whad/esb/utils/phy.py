from whad.phy import PhysicalLayer, GFSKModulationScheme, Endianness

def frequency_to_channel(frequency):
  """
  Converts a frequency (in Hz) to an Enhanced ShockBurst channel.
  """
  return int(frequency/1000000) - 2400

def channel_to_frequency(channel):
  """
  Converts an Enhanced ShockBurst channel into a frequency (in Hz).
  """
  return (2400 + channel) * 1000000

&
PHYS = {
    "ESB-1M": PhysicalLayer(
                modulation=GFSKModulationScheme(deviation=170000),
                datarate=1000000,
                endianness=Endianness.BIG,
                frequency_range=(2400000000, 2500000000),
                maximum_packet_size=128,
                synchronization_word=b"\xAA",
                # an address field, configurable from a similar phy connector API set_address
                frequency_to_channel_function=frequency_to_channel,
                channel_to_frequency_function=channel_to_frequency
                # todo: a validation function ? is the packet really linked to this protocol ?
                # todo: a format function ? defined by default, but can be used to provide a specific scapy layer (both ways)
            ),

    "ESB-2M": PhysicalLayer(
                modulation=GFSKModulationScheme(deviation=500000),
                datarate=2000000,
                endianness=Endianness.BIG,
                frequency_range=(2400000000, 2500000000),
                maximum_packet_size=128,
                synchronization_word=b"\xAA",
                frequency_to_channel_function=frequency_to_channel,
                channel_to_frequency_function=channel_to_frequency
            )
}
