from whad.ant.stack.app.profiles import AntProfile
from whad.ant.crypto import ANT_PLUS_NETWORK_KEY
from whad.ant.channel import ChannelDirection

class AntPlusProfile(AntProfile):
    NETWORK_KEY = ANT_PLUS_NETWORK_KEY
    DEFAULT_RF_CHANNEL = 57

class AntPlusMasterProfile(AntPlusProfile):
    CHANNEL_DIRECTION = ChannelDirection.TX

class AntPlusSlaveProfile(AntPlusProfile):
    CHANNEL_DIRECTION = ChannelDirection.RX    