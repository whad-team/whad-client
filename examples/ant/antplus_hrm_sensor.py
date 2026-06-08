#!/usr/bin/env python3
"""ANT+ Heart Rate Monitor Sensor Example.

Usage:
    python3 examples/ant/antplus_hrm_sensor.py <device>
"""

from whad.ant import Master
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ant.stack.app.profiles.antplus.hrm import HeartRateMonitor
import sys,time

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        interface = sys.argv[1]

        channel = None
        try:
            dev = WhadDevice.create(interface)
            profile = HeartRateMonitor()

            master = Master(dev)
            channel = master.create_channel(
                1234, 120, 1, channel_period=8070
            )
            channel.app.set_profile(profile)
            profile.start()

            print("Heart Rate Monitor Sensor started. Press Ctrl+C to stop.")
            while True:
                profile.computed_heart_rate = profile.computed_heart_rate + 1
                time.sleep(1)

        except (KeyboardInterrupt, SystemExit):
            if channel is not None:
                channel.close()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])