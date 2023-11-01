"""LoRaWAN Channel Plan management

LoRaWAN Channel Plan
--------------------

LoRaWAN networks deployed in various regions of the globe don't use the same
frequencies as unlicensed frequencies may vary from one country to another. The
LoRaWAN specification defines a set of default frequencies (known as channels) for
each region of the globe and some associated mechanisms for its RX1 and RX2 receiving
windows that may vary from one region to another.

This module provides some default classes that represent the default channel plans
for different regions but also let the user free to create a new one based on his
needs. 

A channel plan is defined by a set of uplink and downlink channels, a special backup
downlink channel (called RX2), and a mechanism used to deduce the first receiving channel
characteristics. In our implementation, the channel plan also embeds a set of datarates
and the supported datarate for each channel. This deviates from the specification but
since the hardware we are using does not accept different datarates on a single channel,
we don't have any other choice than to assign a single datarate to each channel.

A simple channel plan is defined as follows:

``` python
class MyChannelPlan(ChannelPlan):

    def __init__(self):
        super().__init__(
            channels=[
                Uplink(1, 868100000, 0),
                Downlink(1, 868100000, 1),
            ],
            datarates=[
                DataRate(sf=7, bw=125000),
                DataRate(sf=12, bw=125000)
            ],
            rx2=Downlink(2, 868269000, 1)
        )
```

This channel plan defines a single uplink channel on 868.1 MHz using datarate 0 that is defined
as a spreading factor (sf) of 7 and a bandwidth of 125 kHz (first datarate in our `datarates` parameter).
A downlink channel is also declared using the same frequency than the uplink channel but a different
datarate (spreading factor of 12 and bandwidth of 125 kHz). Last but not least, a backup downlink channel
is defined using the 868.268 MHz frequency and datarate 1 (spreading factor of 12 and bandwidth of 125 kHz).

RX1 selection behavior
----------------------

When a LoRaWAN gateway successfully receives a frame on one of its uplink channels, it then needs to switch
to a downlink channel (if required) to send some data back to the device that sent the frame. This downlink
channel is usually chosen based on the uplink channel characteristicsm therefore the `ChannelPlan` class
provides a `get_rx1()` method that can be overriden to implement a specific RX1 selection behavior.

This method takes the uplink channel number in parameter allowing to perform some computations to determine
the downlink channel to use.

"""
from random import choice

from whad.lorawan.exceptions import ChannelNotFound, InvalidDataRate

class Channel(object):
    """This class represents a LoRaWAN channel that is used in
    a frequency plan.
    """

    def __init__(self, number: int, frequency: int, data_rate: int=0):
        """Initialize the channel information.
        """
        self.__number = number
        self.__frequency = frequency
        self.__dr = data_rate


    def __repr__(self):
        return 'Channel(num=%d, freq=%d, DR%d)' % (
            self.__number,
            self.__frequency,
            self.__dr,
        )

    @property
    def number(self):
        return self.__number

    @property
    def frequency(self):
        """Retrieve the channel frequency.
        """
        return self.__frequency
        
    @property
    def data_rate(self):
        """Retrieve the supported bandwidth
        """
        return self.__dr
    
    @data_rate.setter
    def data_rate(self, value: int=0):
        self.__dr = value


class Downlink(Channel):
    '''Downlink channel
    '''
    def __init__(self, number: int, frequency: int, data_rate: int=0):
        super().__init__(number=number, frequency=frequency, data_rate=data_rate)


class Uplink(Channel):
    '''Uplink channel
    '''
    def __init__(self, number: int, frequency: int, data_rate: int=0):
        super().__init__(number=number, frequency=frequency, data_rate=data_rate)


class ChannelModParams(Channel):
    '''Channel modulation parameters.
    '''
    def __init__(self, frequency: int, data_rate: int=0, sf: int=7, bw: int=125000, number: int=0):
        super().__init__(number=number, frequency=frequency, data_rate=data_rate)
        self.__sf = sf
        self.__bw = bw

    def __repr__(self):
        return 'ChannelModParams(number=%d, freq=%d, DR%d, sf=%d, bw=%d)' % (
            self.number,
            self.frequency,
            self.data_rate,
            self.spreading_factor,
            self.bandwidth
        )

    def __eq__(self, other):
        '''Channels are equivalent if same frequency, spreading factor and bandwidth
        '''
        return (self.frequency == other.frequency) and \
            (self.spreading_factor == other.spreading_factor) and \
            (self.bandwidth == other.bandwidth)

    @property
    def spreading_factor(self):
        return self.__sf
    
    @property
    def bandwidth(self):
        return self.__bw



class DataRate(object):
    '''DataRate model
    '''

    def __init__(self, sf: int = 7, bw: int = 125000):
        self.__sf = sf
        self.__bw = bw

    @property
    def spreading_factor(self):
        return self.__sf
    
    @property
    def bandwidth(self):
        return self.__bw


class ChannelPlan(object):
    '''LoRa Frequency Plan
    '''

    def __init__(self, channels: [Channel], datarates: [DataRate], rx2: Channel = None):
        '''Loop on channel provided in args
        '''
        self.__uplink_channels = {}
        self.__downlink_channels = {}
        self.__datarates = datarates
        self.__rx2 = rx2

        for channel in channels:
            if isinstance(channel, Downlink):
                self.__downlink_channels[channel.number] = channel
            else: 
                self.__uplink_channels[channel.number] = channel

    def get_rx1(self, chan_number: int) -> ChannelModParams:
        '''Retrieve RX1 channel based on TX channel.

        :param chan_number: tx channel number
        :type chan_number: int
        :return: RX1 channel modulation parameters
        '''
        if chan_number in self.__downlink_channels:
            channel = self.__downlink_channels[chan_number]
            return ChannelModParams(
                channel.frequency,
                channel.data_rate,
                self.__datarates[channel.data_rate].spreading_factor,
                self.__datarates[channel.data_rate].bandwidth,
                number=channel.number
            )
        else:
            raise ChannelNotFound
    
    def get_rx2(self) -> ChannelModParams:
        """Retrieve the channel defined for RX2

        :return: RX2 channel
        """
        # Resolve spreading factor and bandwidth from datarate
        if self.__rx2.data_rate < len(self.__datarates):
            return ChannelModParams(
                self.__rx2.frequency,
                self.__rx2.data_rate,
                self.__datarates[self.__rx2.data_rate].spreading_factor,
                self.__datarates[self.__rx2.data_rate].bandwidth,
                number=self.__rx2.number
            )
        else:
            raise InvalidDataRate

    def has_uplink(self, chan_index):
        '''Determine if a channel number is in the uplink channel plan
        '''
        return (chan_index in self.__uplink_channels)

    def has_downlink(self, chan_index):
        '''Determine if a channel number is in the downlink channel plan
        '''
        return (chan_index in self.__uplink_channels)

    def get_uplink(self, chan_index: int):
        '''Retrieve an uplink channel given its index
        '''
        if chan_index in self.__uplink_channels:
            return self.__uplink_channels[chan_index]
        else:
            raise ChannelNotFound
        
    def get_downlink(self, chan_index: int):
        '''Retrieve a downlink channel given its index
        '''
        if chan_index in self.__downlink_channels:
            return self.__downlink_channels[chan_index]
        else:
            raise ChannelNotFound
    
    def channels(self):
        '''Channels iterator (uplink and downlink)
        '''
        for channel in self.__uplink_channels.values():
            yield ChannelModParams(
                channel.frequency,
                channel.data_rate,
                self.__datarates[channel.data_rate].spreading_factor,
                self.__datarates[channel.data_rate].bandwidth,
                channel.number                
            )
        for channel in self.__downlink_channels.values():
            yield ChannelModParams(
                channel.frequency,
                channel.data_rate,
                self.__datarates[channel.data_rate].spreading_factor,
                self.__datarates[channel.data_rate].bandwidth,
                channel.number                
            )

    def pick_channel(self) -> ChannelModParams:
        """Select a channel from our frequency plan, based on our criterias.
        """
        if len(self.__uplink_channels) > 0:
            chan_index = choice(list(self.__uplink_channels.keys()))
            channel = self.__uplink_channels[chan_index]
            if channel.data_rate < len(self.__datarates):
                return ChannelModParams(
                    channel.frequency,
                    channel.data_rate,
                    self.__datarates[channel.data_rate].spreading_factor,
                    self.__datarates[channel.data_rate].bandwidth,
                    channel.number
                )
            else:
                raise InvalidDataRate
        else:
            raise ChannelNotFound


class EU868(ChannelPlan):
    """LoRaWAN Europe 868MHz frequency plan
    """
    def __init__(self):
        super().__init__(
            channels = [
                # Uplink (1-8, DR5)
                Uplink(1, 868100000, 5),
                Uplink(2, 868300000, 5),
                Uplink(3, 868500000, 5),
                Uplink(4, 867100000, 5),
                Uplink(5, 867300000, 5),
                Uplink(6, 867500000, 5),
                Uplink(7, 867700000, 5),
                Uplink(8, 867900000, 5),
                Downlink(1, 868100000, 5),
                Downlink(2, 868300000, 5),
                Downlink(3, 868500000, 5),
                Downlink(4, 867100000, 5),
                Downlink(5, 867300000, 5),
                Downlink(6, 867500000, 5),
                Downlink(7, 867700000, 5),
                Downlink(8, 867900000, 5),
            ],

            datarates = [
                DataRate(12, 125000),
                DataRate(11, 125000),
                DataRate(10, 125000),
                DataRate(9, 125000),
                DataRate(8, 125000),
                DataRate(7, 125000),
            ],

            # Downlink RX2, DR0
            rx2=Downlink(10, 869525000, 0)
        )

