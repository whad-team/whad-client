#!/usr/bin/env python3
"""ANT+ Combined Bike Speed & Cadence Display Example.

Usage:
    python3 examples/ant/antplus_combined_speed_cadence_display.py <device>
"""

from whad.ant import Slave
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ant.stack.app.profiles.antplus.bsc import CombinedSpeedAndCadenceDisplay
import sys
from time import sleep

if __name__ == '__main__':
    if len(sys.argv) >= 2:
        interface = sys.argv[1]
        channel = None
        try:
            dev = WhadDevice.create(interface)
            profile = CombinedSpeedAndCadenceDisplay()

            slave = Slave(dev, profile=profile)
            channel = slave.search_channel()
            print("Chan:", channel)

            profile.on_cadence_received = lambda rev_count, evt_time : print(f"Cadence rev count: {rev_count}, event time: {evt_time}")
            profile.on_speed_received = lambda rev_count, evt_time : print(f"Speed rev count: {rev_count}, event time: {evt_time}")
            while True:
                sleep(1)

        except (KeyboardInterrupt, SystemExit):
            if channel is not None:
                channel.close()
            dev.close()

        except WhadDeviceNotFound:
            print('[e] Device not found')
            exit(1)
    else:
        print('Usage: %s [device]' % sys.argv[0])