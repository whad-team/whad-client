#!/usr/bin/env python3
"""ANT+ Display Example.

This example demonstrates how to use the ANT+ Display profile to receive
data from ANT+ sensors (Heart Rate Monitor, Bike Speed & Cadence, etc.).

Usage:
    python3 examples/ant/wantplus_display.py <device> [device_type]

Device types:
    120 (0x78): Heart Rate Monitor
    121 (0x79): Combined Speed and Cadence

Example:
    python3 examples/ant/wantplus_display.py uart:0 120
"""

from whad.ant import Slave
from whad.device import WhadDevice
from whad.exceptions import WhadDeviceNotFound
from whad.ant.stack.app.profiles.antplus.hrm import HeartRateDisplay
from whad.ant.stack.app.profiles.antplus.bsc import CombinedSpeedAndCadenceDisplay
import sys
from time import sleep

DEVICE_TYPES = {
    120: ("Heart Rate Monitor", HeartRateDisplay, lambda p: (
        setattr(p, 'on_heart_rate_received', lambda hr: print(f"Heart Rate: {hr} bpm")),
        setattr(p, 'on_heart_rate_update', lambda hr: print(f"Heart Rate updated: {hr} bpm"))
    )),
    121: ("Combined Speed & Cadence", CombinedSpeedAndCadenceDisplay, lambda p: (
        setattr(p, 'on_cadence_received', lambda rev, evt: print(f"Cadence rev count: {rev}, event time: {evt}")),
        setattr(p, 'on_speed_received', lambda rev, evt: print(f"Speed rev count: {rev}, event time: {evt}"))
    )),
}

def run_display(interface, device_type=120):
    """Run the ANT+ display for the specified device type.
    """
    if device_type not in DEVICE_TYPES:
        print(f"[e] Unsupported device type: {device_type}")
        print("Supported types:", ', '.join([f"{k} ({v[0]})" for k, v in DEVICE_TYPES.items()]))
        return

    type_name, profile_class, setup_callbacks = DEVICE_TYPES[device_type]

    try:
        dev = WhadDevice.create(interface)

        # Create the profile instance
        profile = profile_class()
        
        # Setup callbacks for data reception
        setup_callbacks(profile)

        # Create the slave ANT connector with our profile
        slave = Slave(dev, profile=profile)
        channel = slave.search_channel()
        print(f"Channel: {channel}")
        print(f"Connected to {type_name} (type {hex(device_type)}).")
        print("Listening for data... Press CTL-c to stop.")

        profile.start()

        # Keep running until interrupted
        while True:
            sleep(1)

    except (KeyboardInterrupt, SystemExit):
        print("\nStopping...")
        profile.stop()
        dev.close()

    except WhadDeviceNotFound:
        print('[e] Device not found')
        exit(1)


if __name__ == '__main__':
    if len(sys.argv) >= 2:
        interface = sys.argv[1]
        device_type = 120  # Default to Heart Rate Monitor
        if len(sys.argv) >= 3:
            try:
                if sys.argv[2].startswith("0x"):
                    device_type = int(sys.argv[2], 16)
                else:
                    device_type = int(sys.argv[2])
            except ValueError:
                print(f"[e] Invalid device type: {sys.argv[2]}")
                exit(1)

        run_display(interface, device_type)
    else:
        print(f'Usage: {sys.argv[0]} [device] [device_type]')
        print(f'Default device type: 120 (Heart Rate Monitor)')
        print(f'Supported device types:')
        for dtype, (name, _, _) in DEVICE_TYPES.items():
            print(f'  {dtype} (0x{dtype:02x}): {name}')
        exit(1)