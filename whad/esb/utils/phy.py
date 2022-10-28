from whad.phy import PhysicalLayer, GFSKModulationScheme, Endianness

def frequency_to_channel(frequency):
  """
  Converts a frequency (in MHz) to an Enhanced ShockBurst channel.
  """
  return frequency - 2400

def channel_to_frequency(channel):
  """
  Converts an Enhanced ShockBurst channel into a frequency (in MHz).
  """
  return 2400 + channel


PHYS = {
    "ESB-1M": PhysicalLayer(
                modulation=GFSKModulationScheme(deviation=170000),
                datarate=1000000,
                endianness=Endianness.BIG,
                frequency_range=(2400, 2500),
                maximum_packet_size=128,
                synchronization_word=b"\xAA",
                frequency_to_channel_function=frequency_to_channel,
                channel_to_frequency_function=channel_to_frequency
            ),

    "ESB-2M": PhysicalLayer(
                modulation=GFSKModulationScheme(deviation=500000),
                datarate=2000000,
                endianness=Endianness.BIG,
                frequency_range=(2400, 2500),
                maximum_packet_size=128,
                synchronization_word=b"\xAA",
                frequency_to_channel_function=frequency_to_channel,
                channel_to_frequency_function=channel_to_frequency
            )
}
