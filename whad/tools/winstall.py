"""
WHAD install tool

This utility is a simple helper facilitating the install of devices.
"""
import logging
import os
import sys
import stat
import shlex
import inspect
from typing import Union
from subprocess import Popen, PIPE
from shutil import copy, which
from pathlib import Path
from grp import getgrall

import usb
import requests
import distro

from serial.tools.list_ports import comports
from prompt_toolkit import print_formatted_text, HTML

import whad
from whad.cli.ui import info, error, warning, success
from whad.cli.app import CommandLineApp, ApplicationError



logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

class WhadInstallApp(CommandLineApp):
    """winstall main CLI application class.
    """

    def __init__(self):
        """Application uses no interface and has no commands.
        """
        super().__init__(
            description='WHAD install tool',
            interface=False,
            commands=False
        )


        self.add_argument(
            '--list',
            '-l',
            dest='list',
            action="store_true",
            default=False,
            help='List existing devices'
        )

        self.add_argument(
            '--rules',
            '-r',
            dest='rules',
            action="store_true",
            default=False,
            help='Install rules for selected devices'
        )


        self.add_argument(
            '--port',
            '-p',
            dest='port',
            default=False,
            help='Provide a specific port to use during flash'
        )

        self.add_argument(
            '--flash',
            '-f',
            dest='flash',
            action="store_true",
            default=False,
            help='Flash latest firmwares for selected devices'
        )

        self.add_argument(
            'device',
            nargs="*",
            default=[],
            help='Select a specific device'
        )

        self.need_reload = False
        self.udev_rules = None

    def check_tools_availability(self, *tools):
        """Check that a list of tools are installed on the system.
        """
        return all([which(tool) is not None for tool in tools])

    def ask_for_privileges(self):
        """Ask user to get root privileges through sudo.
        """
        euid = os.geteuid()
        if euid != 0:
            info("This tool must run as root, let's elevate your privileges !")
            args = ['sudo', sys.executable] + sys.argv + [os.environ]
            # the next line replaces the currently-running process with the sudo
            pypath = ":".join(sys.path)
            args = ['sudo', f"PYTHONPATH={pypath}", sys.executable] + sys.argv
            os.execvpe('sudo', args, os.environ)
        return os.geteuid() == 0

    def get_udev_rule_filename(self, device_name: str) -> str:
        """Return udev rule filepath for given device.

        :param device_name: Device name
        :type device_name: str
        :return: udev rule filepath
        :rtype: str
        """
        return os.path.realpath(
            f"{os.path.dirname(whad.__file__)}/resources/rules/{device_name}.rules"
        )


    def install_udev_rule(self, device_name: str) -> bool:
        """Deploy udev rule for specified device.

        :param device_name: Device name
        :type device_name: str
        :return: `True` if udev rule install has been successful, `False` otherwise.
        :rtype: bool
        """
        matching_rules = [udev_name for udev_name in self.udev_rules if device_name in udev_name]
        if len(matching_rules) == 0:
            rule_filename = self.get_udev_rule_filename(device_name)
            dev_rule = "/usr/lib/udev/rules.d/40-"+device_name+".rules"
            if os.path.exists(rule_filename):
                copy(rule_filename, dev_rule)
                success(f"Rule successfully installed for device '{device_name}': {dev_rule}")
                return True

            # Failed to install rule.
            warning("Rule not found, skipping.")
            return False

        # Already installed.
        dev_rules = ",".join(matching_rules)
        warning(f"Rules detected for device '{device_name}' ({dev_rules}), skipping.")
        return False

    def get_latest_release(self, github_repository: str) -> Union[str, None]:
        """Retrieve the latest release for a given github repository.

        :param github_repository: Target github repository URL
        :type github_repository: str
        :return: URL to latest release if found, `None` otherwise.
        :rtype: str
        """
        g_request = requests.get(f"https://github.com/{github_repository}/releases/latest")
        if g_request.status_code == 200:
            return g_request.url

        # Failed.
        return None

    def install_nrfutil(self):
        """Install nRFutil for Linux.
        """
        info("Downloading 'nrfutil' tool from nordicsemi.com...")
        nrfutil_url = (
            "https://files.nordicsemi.com/ui/api/v1/download?repoKey=swtools"
            "&path=external/nrfutil/executables/x86_64-unknown-linux-gnu/nrfutil"
        )
        n_request = requests.get(nrfutil_url, allow_redirects=True)
        if n_request.status_code == 200:
            # Remove if already existing
            if os.path.exists("/tmp/nrfutil"):
                os.unlink("/tmp/nrfutil")

            # Save nrfutil to temporary file
            with open("/tmp/nrfutil", "wb") as nrfutil:
                nrfutil.write(n_request.content)

            # Change permissions to allow execution
            f = Path("/tmp/nrfutil")
            f.chmod(f.stat().st_mode | stat.S_IEXEC)

            # Use nrfutil to install nRF SDK and tools
            _, _, e = self.run_command('/tmp/nrfutil install nrf5sdk-tools --force')
            if len(e) > 0:
                return False
            return True

        # Cannot download nrfutil
        return False

    def download_latest_butterfly_release(self):
        """Download latest ButteRFly release from github.
        """
        latest_release_url = self.get_latest_release("whad-team/butterfly")
        try:
            release = latest_release_url.split("/tag/")[1]
            success(f"Latest butterfly release: {release}")
            zip_url = (
                f"https://github.com/whad-team/butterfly/releases/download/"
                f"{release}"
                f"/butterfly-fwupgrade.zip"
            )

            # Download latest release from github
            z_request = requests.get(zip_url, allow_redirects=True)
            if z_request.status_code == 200:
                latest_release_filename = f"/tmp/butterfly-{release}.zip"

                # Remove if previously downloaded
                if os.path.exists(latest_release_filename):
                    os.unlink(latest_release_filename)

                # Save to temporary file
                with open(latest_release_filename, "wb") as fw:
                    fw.write(z_request.content)

                # Return file path
                return latest_release_filename

        except IndexError:
            error("Release not found, exiting...")

        # Fail downloading and installing ButteRFly.
        return None

    def flash_firmware_with_nrfutil(self, firmware, serial_port="/dev/ttyACM0",
                                    nrfutil_exec="/tmp/nrfutil") -> bool:
        """Flash a compatible nRF device with a specified firmware thanks to nrfutil.

        :param firmware: Firmware to flash
        :type firmware: str
        :param serial_port: Target device port
        :type serial_port: str
        :param nrfutil_exec: Path to nrfutil binary
        :type nrfutil_exec: str
        :return: `True` if device has been successfully flashed with specified firmware,
                 `False` otherwise.
        :rtype: bool
        """
        _, o, _  = self.run_command(
            f"{nrfutil_exec} dfu usb-serial -pkg {firmware}  -p {serial_port} -b 115200"
        )

        return b"Device programmed" in o

    def flash_butterfly(self, port="/dev/ttyACM0"):
        """Flash ButteRFly on a compatible device.
        """
        if not self.install_nrfutil():
            error("Failure during 'nrfutil' installation.")
            return False

        latest_release_filename = self.download_latest_butterfly_release()
        if latest_release_filename is None:
            error("Failure during 'butterfly' release download")
            return False

        result = self.flash_firmware_with_nrfutil(
            latest_release_filename, serial_port=port, nrfutil_exec="/tmp/nrfutil"
        )
        return result

    def run_command(self, cmd: str, shell: bool = False, force_env: dict = None,
                    cwd: str = None, added_path: str = None):
        """Run the specified command and return its output.

        :param cmd: Command to execute
        :type cmd: str
        :param shell: Execute command in shell if set to `True`
        :type shell: bool, optional
        :param force_env: Specify a custom environment to use
        :type force_env: dict, optional
        :param cwd: Specify the current working directory
        :type cwd: str, optional
        :param added_path: Add specific string to PATH
        :type added_path: str, optional
        :rtype: tuple
        :return: A tuple containing the return code and the textual output
        """
        info("Running command: " + cmd)

        if added_path is not None:
            env  = os.environ.copy()
            env["PATH"] = f"{env['PATH']}:/" + added_path
        elif force_env is not None:
            env = force_env
        else:
            env = os.environ

        with Popen(shlex.split(cmd) if not shell else cmd,  stderr=PIPE,
                        stdout=PIPE, shell=shell, cwd=cwd, env=env) as process:
            stdout, stderr = process.communicate()

            if process.returncode != 0:
                error("Standard output:" + stdout.decode())
                error("Standard error:" + stderr.decode())

            return process.returncode , stdout, stderr


    def install_ubertooth_host(self):
        """Install Ubertooth tools and libraries.
        """
        if self.check_tools_availability('ubertooth-dfu'):
            return True

        distribution = distro.id()

        if distribution == 'fedora':
            r, _, _ = self.run_command('dnf install -y ubertooth')
            if r != 0:
                return False

        elif distribution in ('debian', 'ubuntu', 'raspbian'):
            r, _, _ = self.run_command('apt install -y ubertooth')
            if r != 0:
                return False

        else:
            error("Platform not supported, exiting.")
            return False

        return True


    def download_latest_ubertooth_release(self) -> Union[str, None]:
        """Download latest version of Ubertooth firmware.
        
        :return: Firmware file path
        :rtype: str
        """
        latest_release_url = self.get_latest_release("greatscottgadgets/ubertooth")
        try:
            release = latest_release_url.split("/tag/")[1]
            success(f"Latest ubertooth release: {release}")
            zip_url = (
                f"https://github.com/greatscottgadgets/ubertooth/releases/download/"
                f"{release}/ubertooth-{release}.tar.xz"
            )
            z_request = requests.get(zip_url, allow_redirects=True)
            if z_request.status_code == 200:
                latest_release_filename = "/tmp/ubertooth-{release}.tar.xz"

                # Remove previously downloaded firmware if any
                if os.path.exists(latest_release_filename):
                    os.unlink(latest_release_filename)

                # Save latest release in file
                with open(latest_release_filename, "wb") as fw:
                    fw.write(z_request.content)

                # Return firmware file path
                return latest_release_filename
        except IndexError:
            error("Release not found, exiting...")

        # Failed to download latest release
        return None

    def flash_ubertooth(self, port=None):
        """Flash an Ubertooth device with the latest Ubertooth firmware.
        """
        if not self.install_ubertooth_host():
            error("Failure during 'ubertooth-dfu' installation.")
            return False

        latest_release_filename = self.download_latest_ubertooth_release()
        r, _, _ = self.run_command(f"tar -xf {latest_release_filename}", cwd="/tmp")
        if r != 0:
            return False

        port_option = f"-U {port}" if port is not None else ""
        r, _, _ = self.run_command(
            f"ubertooth-dfu -d bluetooth_rxtx.dfu -r {port_option}",
            cwd=latest_release_filename.replace(".tar.xz","/ubertooth-one-firmware-bin/")
        )
        if r != 0:
            return False
        return True


    def flash_yardstickone(self, port="/dev/RFCAT_BL_YS1"):
        """Flash a YardStickOne with the latest firmware release.
        """
        r, _, _ = self.run_command("rm -rf /tmp/rfcat")
        if r != 0:
            return False

        r, _, _ = self.run_command("git clone https://github.com/atlas0fd00m/rfcat", cwd="/tmp")
        if r != 0:
            return False

        r, _, _ = self.run_command("pip install future")
        if r != 0:
            return False


        warning((
            "For some reason, latest build from rfcat repo crashes the dongle, "
            "let's get the latest functional build."
        ))

        r, _, _ = self.run_command((
            "wget https://gist.githubusercontent.com/mossmann/7b816680df2ac513df3835f3cb9eaa1b"
            "/raw/2f33a76a86c8f6ee71dacb385537386486fe633a/RfCatYS1CCBootloader.hex -O /tmp/ys1.hex"
        ))
        if r != 0:
            return False

        if not os.path.exists(port):
            r, _, _ = self.run_command("/tmp/rfcat/rfcat --bootloader --force")
            if r != 0:
                return False
        r, _, _ = self.run_command(
            f"/tmp/rfcat/CC-Bootloader/rfcat_bootloader {port} erase_all"
        )
        if r != 0:
            return False
        r, _, _ = self.run_command(
            f"/tmp/rfcat/CC-Bootloader/rfcat_bootloader {port} download /tmp/ys1.hex"
        )
        if r != 0:
            return False
        r, _, _  = self.run_command(
            f"/tmp/rfcat/CC-Bootloader/rfcat_bootloader {port} verify /tmp/ys1.hex"
        )
        if r != 0:
            return False
        r, _, _ = self.run_command(
            f"/tmp/rfcat/CC-Bootloader/rfcat_bootloader {port} run"
        )
        if r != 0:
            return False
        return True

    def install_sdcc(self):
        """Install SDCC.
        """
        if self.check_tools_availability("sdcc"):
            return True

        distribution = distro.id()

        if distribution == "fedora":

            r, _, _ = self.run_command("rm -rf /usr/bin/packihx /usr/bin/sdcc")
            if r != 0:
                return False

            r, _, _ = self.run_command("dnf install -y sdcc")
            if r != 0:
                return False

            r, _, _ = self.run_command("ln -s /usr/bin/sdcc-sdcc /usr/bin/sdcc")
            if r != 0:
                return False

            r, _, _ = self.run_command("ln -s /usr/bin/sdcc-packihx /usr/bin/packihx")
            if r != 0:
                return False

        elif distribution in ("debian", "ubuntu", "raspbian"):
            r, _, _ = self.run_command("apt install -y sdcc")
            if r != 0:
                return False

        else:
            error("Platform not supported, exiting.")
            return False

        return True

    def flash_rfstorm(self):
        """Flash a compatible device with Bastille's RFStorm firmware.
        """
        if not self.install_sdcc():
            error("An error occurred during 'sdcc' installation.")

        r, _, _ = self.run_command("rm -rf /tmp/nrf-research-firmware-python3")
        if r != 0:
            return False
        r, _, _ = self.run_command("pip install pyusb platformio")
        if r != 0:
            return False
        r, _, _ = self.run_command(
            "git clone https://github.com/kuzmin-no/nrf-research-firmware-python3",
            cwd="/tmp"
        )
        if r != 0:
            return False
        r, _, _ = self.run_command("make", cwd="/tmp/nrf-research-firmware-python3")
        if r != 0:
            return False
        r, o, _ = self.run_command("lsusb")
        if b"1915:0102" in o or b"046d:c52b" in o:
            r, _, _ = self.run_command(
                "make logitech_install",
                cwd="/tmp/nrf-research-firmware-python3"
            )
            return r == 0

        r, _, _ = self.run_command(
            "make install", cwd="/tmp/nrf-research-firmware-python3"
        )
        return r == 0

    def install_esp_sdk(self):
        """Install Espressif SDK (esp-idf).
        """
        if self.check_tools_availability("idf.py"):
            return True

        distribution = distro.id()
        if distribution == "fedora":
            r, _, _ = self.run_command((
                "dnf install -y wget flex bison gperf python3 cmake ninja-build"
                " ccache dfu-util libusbx"
            ))
            if r != 0:
                return False

        elif distribution in ("debian", "ubuntu", "raspbian"):
            r, _, _ = self.run_command((
                "apt-get install -y git wget flex bison gperf python3 python3-pip"
                " python3-venv cmake ninja-build ccache libffi-dev libssl-dev dfu-util "
                "libusb-1.0-0"
            ))
            if r != 0:
                return False

        else:
            error("Platform not supported, exiting.")
            return False

        r, _, _ = self.run_command("rm -rf /tmp/esp")
        if r != 0:
            return False
        r, _, _ = self.run_command("mkdir -p /tmp/esp")
        if r != 0:
            return False

        r, _, _ = self.run_command(
            "git clone -b release/v4.4 --recursive https://github.com/espressif/esp-idf.git",
            cwd="/tmp/esp"
        )
        if r != 0:
            return False

        # Clear python path
        env = os.environ.copy()
        env["PYTHONPATH"] = ""

        r, _, _ = self.run_command("./install.sh esp32", shell=True, force_env=env,
                                   cwd="/tmp/esp/esp-idf")
        if r != 0:
            return False

        r, o, _ = self.run_command(". ./export.sh > /dev/null; env", shell=True,
                                   force_env=env, cwd="/tmp/esp/esp-idf")
        if r != 0:
            return False

        os.environ.update(dict(
            line.decode().partition('=   ')[::2] for line in o.split(b'\n')[:-1]
        ))

        r, o, _ = self.run_command("idf.py --version", force_env=os.environ,
                                   cwd="/tmp/esp/esp-idf")
        if r != 0:
            return False

        success("Espressif framework installed: " + o.decode())
        return True


    def flash_esp(self, port=None):
        """Flash an ESP device with latest NodeMCU WHAD firmware.
        """
        if not self.install_esp_sdk():
            error("An error occurred uring ESP SDK installation.")
            return False

        info("Cloning 'nodemcu-esp32-firmware' github repository...")
        r, _, _ = self.run_command("rm -rf /tmp/nodemcu-esp32-firmware/", force_env=os.environ,
                                   cwd="/tmp")
        if r != 0:
            return False

        r, _, _ = self.run_command(
            "git clone https://github.com/whad-team/nodemcu-esp32-firmware/ --recurse",
            force_env=os.environ,  cwd="/tmp"
        )
        if r != 0:
            return False

        info("Building firmware...")
        r, _, _ = self.run_command("idf.py build", force_env=os.environ,
                                   cwd="/tmp/nodemcu-esp32-firmware")
        if r != 0:
            return False

        info("Flashing firmware...")
        dev_port = f"-p {port}" if port is not None else ""
        r, _, _ = self.run_command(f"idf.py flash {dev_port}", force_env=os.environ,
                                   cwd="/tmp/nodemcu-esp32-firmware")
        if r != 0:
            return False

        # Success
        return True


    def download_latest_stm32wl55_release(self):
        """Download latest stable version of WHAD stm32wl55 compatible firmware
        for ST Nucleo WL55 board.
        """
        latest_release_url = self.get_latest_release("whad-team/stm32wlxx-firmware")
        try:
            release = latest_release_url.split("/tag/")[1]
            success("Latest STM32WL55 firmware release: " + release)
            zip_url = (
                f"https://github.com/whad-team/stm32wlxx-firmware/releases/download/"
                f"{release}/nucleo_wl55.hex"
            )
            z_request = requests.get(zip_url, allow_redirects=True)
            if z_request.status_code == 200:
                latest_release_filename = "/tmp/nucleo_wl55.hex"

                # Remove previous file if any
                if os.path.exists(latest_release_filename):
                    os.unlink(latest_release_filename)

                # Store latest version in temporary directory
                with open(latest_release_filename, "wb") as fw:
                    fw.write(z_request.content)

                # Return firmware path
                return latest_release_filename
        except IndexError:
            error("Release not found, exiting...")

        # Download failed
        return None

    def download_latest_lorae5mini_release(self):
        """Download the latest version of WHAD compatible firmware for SeeedStudio's
        LoRa-e5-mini/Wio-e5-mini board.
        """
        latest_release_url = self.get_latest_release("whad-team/stm32wlxx-firmware")
        try:
            release = latest_release_url.split("/tag/")[1]
            success("Latest STM32WL55 firmware release: " + release)
            zip_url = (
                f"https://github.com/whad-team/stm32wlxx-firmware/releases/download/"
                f"{release}/lora_e5_mini.hex"
            )
            z_request = requests.get(zip_url, allow_redirects=True)
            if z_request.status_code == 200:
                latest_release_filename = "/tmp/lora_e5_mini.hex"

                # Remove firmware if file exists
                if os.path.exists(latest_release_filename):
                    os.unlink(latest_release_filename)

                # Save latest version in temporary file
                with open(latest_release_filename, "wb") as fw:
                    fw.write(z_request.content)

                # Return firmware file path
                return latest_release_filename
        except IndexError:
            error("Release not found, exiting...")

        # Download failed.
        return None

    def install_stflash(self):
        """Install stflash.
        """
        if self.check_tools_availability('st-flash'):
            return True

        distribution = distro.id()
        if distribution == 'fedora':
            r, _, _ = self.run_command('dnf install -y stlink')
            if r != 0:
                return False

        elif distribution in ('debian', 'ubuntu', 'raspbian'):
            r, _, _ = self.run_command('apt-get install -y stlink-tools')
            if r != 0:
                return False

        else:
            error("Platform not supported, exiting.")

        # Cannot install st-flash.
        return False



    def flash_nucleowl55(self):
        """Flash a ST Nucleo WL55 devboard with compatible firmware.
        """
        if not self.install_stflash():
            error("An error occurred during 'st-flash' installation.")
            return False


        latest_release_filename = self.download_latest_stm32wl55_release()
        r, _, _ = self.run_command(f"st-flash --format=ihex write {latest_release_filename}",
                                   cwd="/tmp")
        if r != 0:
            return False

        return True

    def flash_lorae5mini(self):
        """Flash a SeeedStudio LoRa-e5-mini board with compatible firmware.
        """
        if not self.install_stflash():
            error("An error occurred during 'st-flash' installation.")
            return False


        latest_release_filename = self.download_latest_lorae5mini_release()
        r, _, _ = self.run_command(f"st-flash --format=ihex write {latest_release_filename}",
                                   cwd="/tmp")
        if r != 0:
            return False

        return True

    def rules_rfstorm(self):
        """Install udev rules for RFStorm firmware.
        """
        if self.install_udev_rule("rfstorm"):
            self.need_reload = True
        return True

    def rules_ubertooth(self):
        """Install udev rules for Ubertooth.
        """
        if self.install_udev_rule("ubertooth"):
            self.need_reload = True
        return True

    def rules_rzusbstick(self):
        """Install udev rules for AVR RZUSB Stick
        """
        if self.install_udev_rule("rzusbstick"):
            self.need_reload = True
        return True

    def rules_yardstickone(self):
        """Install udev rules for YardStickOne
        """
        if self.install_udev_rule("yardstickone"):
            self.need_reload = True
        return True

    def rules_nucleowl55(self):
        """Install udev rules for ST Nucleo WL55 devboard
        """
        return self.install_serial_port_capabilities()

    def rules_lorae5mini(self):
        """Install udev rules for SeeedStudio's LoRa-e5-mini
        """
        return self.install_serial_port_capabilities()

    def rules_esp(self):
        """Install udev rules for Espressif ESP devices
        """
        return self.install_serial_port_capabilities()

    def rules_butterfly(self):
        """Install udev rules for ButteRFly compatible hardware
        """
        return self.install_serial_port_capabilities()

    def rules_apimote(self):
        """Install udev rules for Apimote
        """
        return self.install_serial_port_capabilities()

    def rules_hci(self):
        """Install sniffing capabilities for HCI devices on Linux
        """
        python_interpreter = os.path.realpath(sys.executable)
        if not self.install_hci_capabilities(python_interpreter):
            return False
        success((f"HCI capabilities successfully added to python interpreter "
                f"({python_interpreter})."))
        return True

    def pre_run(self):
        """Pre-processing parameters.
        """
        super().pre_run()
        # find udev location
        candidate_udev_locations = [
            "/etc/udev/rules.d",
            "/lib/udev/rules.d",
            "/run/udev/rules.d",
            "/var/run/udev/rules.d"
        ]
        self.udev_rules = []

        for location in candidate_udev_locations:
            if os.path.exists(location):
                self.udev_rules += os.listdir(location)

        self.need_reload = False


    def install_serial_port_capabilities(self):
        """Configure machine to allow serial port access in user-mode.
        """
        if not self.check_tools_availability("usermod"):
            error("'usermod' tool is required but not available")
            return False
        # Find the right group which depends on the distribution (e.g. dialout
        # for Debian, uucp for Arch-Linux).
        groups = [ group.gr_name for group in getgrall() ]
        if "dialout" in groups:
            group = "dialout"
        elif "uucp" in groups:
            group = "uucp"
        else:
            error("Group granting serial port capabilities not found!")
            return False
        with Popen(['usermod', '-a', '-G', group, os.getlogin()], stdout=PIPE,
                   stderr=PIPE) as process:
            _, stderr = process.communicate()

            if len(stderr) > 0:
                return False

            success((
                f"Serial port capabilities successfully configured "
                f"(user {os.getlogin()} added to group {group}): logout to take "
                f"modification into account."
            ))

            # Success.
            return True


    def reload_udev_rules(self):
        """Reload udev rules on Linux host
        """
        if not self.check_tools_availability("udevadm"):
            error("'udevadm' tool is required but not available")
            return False
        info("Reloading udev rules...")
        with Popen(['udevadm', 'control', '--reload-rules'], stderr=PIPE,
                   stdout=PIPE) as process:
            _, stderr = process.communicate()
            if len(stderr) > 0:
                return False

        with Popen(['udevadm', 'trigger'],  stderr=PIPE, stdout=PIPE) as process:
            _, stderr = process.communicate()
            if len(stderr) > 0:
                return False

        return True


    def install_hci_capabilities(self, interpreter):
        """Install HCI user-mode access
        """
        if not self.check_tools_availability("getcap", "setcap"):
            error("'getcap' and 'setcap' tools are required but not available")
            return False

        with Popen(['getcap', interpreter], stdout=PIPE, stderr=PIPE) as process:
            stdout, stderr = process.communicate()

            if "cap_net_admin,cap_net_raw=eip" not in stdout.decode('utf-8'):
                with Popen(['setcap', 'cap_net_admin,cap_net_raw+eip',interpreter],
                                stdout=PIPE, stderr=PIPE) as setcap:
                    stdout, stderr = setcap.communicate()

                    if len(stdout) != 0 or len(stderr) != 0:
                        return False

            return True

        return True

    def list_devices(self):
        """Enumerate compatible devices
        """
        info("Detected devices:")
        print()
        for dev in comports():
            if (dev.vid == 0x10c4 and dev.pid == 0xea60) or dev.vid == 0x303a:
                print_formatted_text(HTML(f"  - <b>Espressif ESP-32 board: </b> {dev.device}"))
                print_formatted_text(HTML(
                    "    <u>Command (install rules):</u> <i>winstall --rules esp</i>"
                ))
                print_formatted_text(HTML((
                    f"    <u>Command (flash firmware):</u> <i>winstall --flash esp "
                    f"--port {dev.device}</i>"
                )))
                print()
            elif dev.vid == 0xc0ff and dev.pid == 0xeeee:
                print_formatted_text(HTML("  - <b>WHAD ButteRFly dongle: </b> {dev.device}"))
                print_formatted_text(HTML(
                    "    <u>Command (install rules):</u> <i>winstall --rules butterfly</i>"
                ))
                print_formatted_text(HTML((
                    f"    <u>Command (flash firmware):</u> <i>winstall --flash butterfly "
                    f"--port {dev.device}</i>"
                )))
                print()
            elif dev.vid == 0x0483 and dev.pid == 0x374e:
                print_formatted_text(HTML(f"  - <b>Nucleo STM32WL55: </b> {dev.device}"))
                print_formatted_text(HTML(
                    "    <u>Command (install rules):</u> <i>winstall --rules nucleowl55</i>"
                ))
                print_formatted_text(HTML((
                    f"    <u>Command (flash firmware):</u> <i>winstall --flash nucleowl55 "
                    f"--port {dev.device}</i>"
                )))
                print()

        ubertooth_count = 0
        yardstickone_count = 0
        rfstorm_count = 0
        rzusbstick_count = 0
        for device in usb.core.find(find_all=1):
            vid, pid = device.idVendor, device.idProduct
            if (vid == 0xffff and pid == 0x0004) or (vid == 0x1d50 and pid >= 0x6000 and pid <= 0x6003):
                print_formatted_text(HTML(
                    f"  - <b>Ubertooth One: </b> {ubertooth_count}"
                ))
                print_formatted_text(HTML(
                    (
                        "    <u>Command (install rules):</u> <i>winstall "
                        "--rules ubertooth </i>"
                    )
                ))
                print_formatted_text(HTML((
                    f"    <u>Command (flash firmware):</u> <i>winstall --flash ubertooth "
                    f"--port {ubertooth_count}</i>"
                )))
                ubertooth_count += 1
                print()
            elif (vid == 0x1d50 and pid in (0x605b, 0x6047, 0x6048, 0xecc1, 0x6049,
                                            0x604a, 0x605c, 0xecc0)):
                print_formatted_text(HTML(
                    f"  - <b>Yard Stick One: </b> {yardstickone_count}"
                ))
                print_formatted_text(HTML(
                    "    <u>Command (install rules):</u> <i>winstall --rules yardstickone </i>"
                ))
                print_formatted_text(HTML((
                    f"    <u>Command (flash firmware):</u> <i>winstall --flash yardstickone "
                    f"--port {yardstickone_count}</i>"
                )))
                yardstickone_count += 1
                print()
            elif (vid == 0x046d and pid in (0xc52b, 0xaaaa)) or (vid == 0x1915 and pid in (0x0102, 0x7777, 0x0101)):
                print_formatted_text(HTML(
                    f"  - <b>RFStorm compatible dongle: </b> {rfstorm_count}"
                ))
                print_formatted_text(HTML(
                    "    <u>Command (install rules):</u> <i>winstall --rules rfstorm </i>"
                ))
                print_formatted_text(HTML((
                    f"    <u>Command (flash firmware):</u> <i>winstall --flash rfstorm "
                    f"--port {rfstorm_count}</i>"
                )))
                rfstorm_count += 1
                print()
            elif (vid == 0x03eb and pid == 0x210a):
                print_formatted_text(HTML(
                    f"  - <b>RZUSBStick: </b> {rzusbstick_count}"
                ))
                print_formatted_text(HTML(
                    "    <u>Command (install rules):</u> <i>winstall --rules rzusbstick </i>"
                ))
                rzusbstick_count += 1
                print()

        for device in os.listdir("/sys/class/bluetooth"):
            print_formatted_text(HTML(f"  - <b>HCI device: </b> {device}"))
            print_formatted_text(HTML(
                "    <u>Command (install rules):</u> <i>winstall --rules hci </i>"
            ))
            print()

    def run(self):
        """winstall main function.
        """
        try:
            # Launch pre-run tasks
            self.pre_run()

            rules = self.args.rules
            flash = self.args.flash

            if not self.args.rules and not self.args.flash:
                # By default, if no option is provided, only use rules
                self.args.list = True

            if self.args.list or len(self.args.device) == 0:
                self.list_devices()
                return

            # We need root, let's ask
            if not self.ask_for_privileges():
                error("Login failed, aborting.")
                sys.exit(1)

            if  "all" in self.args.device:
                self.args.device = [
                    "hci",
                    "butterfly",
                    "esp",
                    "lorae5mini",
                    "rfstorm",
                    "ubertooth",
                    "apimote",
                    "nucleowl55",
                    "rzusbstick",
                    "yardstickone"
                ]

            # Iterate over devices
            for device in self.args.device:
                if flash:
                    if hasattr(self, "flash_" + device):
                        info(f"Flashing {device} device ...")

                        flashfunc = getattr(self, "flash_" + device)
                        if self.args.port and "port" in list(inspect.signature(flashfunc).parameters):
                            if flashfunc(port=self.args.port):
                                success(f"Flashing successful for device '{device}'.")
                            else:
                                error((f"An error occurred during device flashing"
                                      f" for device '{device}'."))
                                sys.exit(1)
                        else:
                            if flashfunc():
                                success(f"Flashing successful for device '{device}'.")
                            else:
                                error((f"An error occurred during device flashing"
                                      f" for device '{device}'."))
                                sys.exit(1)
                    else:
                        warning(f"Flashing {device} device is not supported yet.")

                if rules:
                    if hasattr(self, f"rules_{device}"):
                        info(f"Installing rules for {device} device ...")
                        if getattr(self, f"rules_{device}")():
                            success(f"Rules successfully added for device '{device}'.")
                        else:
                            error((f"An error occurred during device rules installation "
                                  f"for device '{device}'."))
                            sys.exit(1)
                    else:
                        warning(f"Installing rules for {device} device is not supported yet.")


            if rules and self.need_reload:
                if not self.reload_udev_rules():
                    error("An error occurred during udev rules reload, exiting.")
                    sys.exit(1)
                else:
                    success("Rules successfully reloaded.")
        except Exception as e:
            error("An error occurred: " + repr(e))

        # Launch post-run tasks
        self.post_run()

def winstall_main():
    """Launcher for winstall
    """
    try:
        app = WhadInstallApp()
        app.run()
    except ApplicationError as err:
        err.show()
