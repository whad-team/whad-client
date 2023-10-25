'''BLE stack ATT layer unit tests.

This module provides different test cases to check that
the ATT layer is working as expected:

- TestGatt: checks that `wait_for_message()` works as expected
- TestAttToL2CAP: checks each ATT method sends the correct packet to L2CAP
- TestAttToGatt: checks ATT incoming packets are correctly forwarded to GATT layer

'''
import pytest

from whad.lorawan.channel import ChannelPlan, Channel, DataRate, ChannelModParams

class TestChannelPlan(object):

    @pytest.fixture
    def channels(self):
        return [
            Channel(868100000, 0),
            Channel(868500000, 1),
            Channel(869250000, 2),
            Channel(868300000, 3),
            Channel(869000000, 4),
        ]
    
    @pytest.fixture
    def rx2(self):
        return Channel(869250000, 0)

    @pytest.fixture
    def datarates(self):
        return [
            DataRate(sf=7, bw=125000),
            DataRate(sf=9, bw=125000),
            DataRate(sf=10, bw=250000),
            DataRate(sf=11, bw=500000),
            DataRate(sf=12, bw=125000),
        ]

    @pytest.fixture
    def channel_plan(self, channels, datarates, rx2):
        return ChannelPlan(
            channels=channels,
            datarates=datarates,
            rx2=rx2
        )
    
    def test_data_rate(self, channel_plan, channels, datarates):
        '''Test data rate conversion to spreading factor / bandwidth
        '''
        # reverse lookup table
        self.__freq2chan = {}
        for channel in channels:
            self.__freq2chan[channel.frequency] = channel
        
        # Test all channels
        for channel_params in channel_plan.channels():
            channel = self.__freq2chan[channel_params.frequency]
            assert channel_params.frequency == channel.frequency
            assert channel_params.spreading_factor == datarates[channel.data_rate].spreading_factor
            assert channel_params.bandwidth == datarates[channel.data_rate].bandwidth

    def test_rx2(self, channel_plan, rx2):
        _rx2 = channel_plan.get_rx2()
        assert _rx2.frequency == rx2.frequency
        assert _rx2.data_rate == rx2.data_rate

