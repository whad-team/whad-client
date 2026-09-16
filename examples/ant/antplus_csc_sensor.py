from whad.ant import Master
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ant.stack.app.profiles.antplus.bsc import CombinedSpeedAndCadenceSensor
import sys

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        interface = sys.argv[1]

        channel = None
        try:
            dev = WhadDevice.create(interface)
            profile = CombinedSpeedAndCadenceSensor()

            master = Master(dev)
            channel = master.create_channel(
                1234, 121, 1, channel_period=8086
            )
            channel.app.set_profile(profile)
            profile.start()

            print("Combined Speed & Cadence Sensor started. Press Ctrl+C to stop.")
            while True:
                pass

        except (KeyboardInterrupt, SystemExit):
            if channel is not None:
                channel.close()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])