"""WHAD install tool

This utility is a simple helper facilitating the install of devices.
"""
import logging
import os
import sys
import whad
import requests
import stat
import distro
import shlex
import inspect
from shutil import copy, which
from prompt_toolkit import print_formatted_text, HTML
from whad.cli.ui import info, error, warning, success
from whad.cli.app import CommandLineApp, ApplicationError
from subprocess import Popen, DEVNULL, PIPE
from grp import getgrall
from pathlib import Path


logger = logging.getLogger(__name__)
#logging.basicConfig(level=logging.DEBUG)

class WhadInstallApp(CommandLineApp):

    def __init__(self):
        """Application uses no interface and has no commands.
        """
        super().__init__(
            description='WHAD install tool',
            interface=False,
            commands=False
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
            default=["hci", "butterfly", "esp", "lorae5mini", "rfstorm", "ubertooth", "apimote", "nucleowl55", "rzusbstick", "yardstickone"],
            help='Select a specific device'
        )

    def check_tools_availability(self, *tools):
        return all([which(tool) is not None for tool in tools])

    def ask_for_privileges(self):
        euid = os.geteuid()
        if euid != 0:
            info("This tool must run as root, let's elevate your privileges !")
            args = ['sudo', sys.executable] + sys.argv + [os.environ]
            # the next line replaces the currently-running process with the sudo
            pypath = ":".join(sys.path)
            args = ['sudo', f"PYTHONPATH={pypath}", sys.executable] + sys.argv
            os.execvpe('sudo', args, os.environ)
        return os.geteuid() == 0

    def get_udev_rule_filename(self, device_name):
        return os.path.realpath("{}/ressources/rules/{}.rules".format(os.path.dirname(whad.__file__), device_name))


    def install_udev_rule(self, device_name):
        matching_rules = [udev_name for udev_name in self.udev_rules if device_name in udev_name]
        if len(matching_rules) == 0:
            rule_filename = self.get_udev_rule_filename(device_name)
            rule_dest_filename = "/usr/lib/udev/rules.d/40-"+device_name+".rules"
            if os.path.exists(rule_filename):
                copy(rule_filename, rule_dest_filename)
                success("Rule successfully installed for device '%s': %s" % (device_name, rule_dest_filename))
                return True
            else:
                warning("Rule not found, skipping.")
                return False
        else:
            warning("Rules detected for device '%s' (%s), skipping." % (device_name, ",".join(matching_rules)))
            return False

    def get_latest_release(self, github_repository):
        g_request = requests.get("https://github.com/"+github_repository+"/releases/latest")
        if g_request.status_code == 200:
            return g_request.url
        else:
            return None

    def install_nrfutil(self):
        info("Downloading 'nrfutil' tool from nordicsemi.com...")
        nrfutil_url = "https://files.nordicsemi.com/ui/api/v1/download?repoKey=swtools&path=external/nrfutil/executables/x86_64-unknown-linux-gnu/nrfutil"
        n_request = requests.get(nrfutil_url, allow_redirects=True)
        if n_request.status_code == 200:
            if os.path.exists("/tmp/nrfutil"):
                os.unlink("/tmp/nrfutil")
            open("/tmp/nrfutil", "wb").write(n_request.content)
            f = Path("/tmp/nrfutil")
            f.chmod(f.stat().st_mode | stat.S_IEXEC)

            r, o, e = self.run_command('/tmp/nrfutil install nrf5sdk-tools --force')
            if len(e) > 0:
                return False
            return True

    def download_latest_butterfly_release(self):
         latest_release_url = self.get_latest_release("whad-team/butterfly")
         try:
             release = latest_release_url.split("/tag/")[1]
             success("Latest butterfly release: " + release)
             zip_url = "https://github.com/whad-team/butterfly/releases/download/" + release + "/butterfly-fwupgrade.zip"
             z_request = requests.get(zip_url, allow_redirects=True)
             if z_request.status_code == 200:
                 latest_release_filename = "/tmp/butterfly-"+release+".zip"
                 if os.path.exists(latest_release_filename):
                     os.unlink(latest_release_filename)
                 open(latest_release_filename, "wb").write(z_request.content)
                 return latest_release_filename
         except IndexError:
             error("Release not found, exiting...")
             return None

    def flash_firmware_with_nrfutil(self, firmware, serial_port="/dev/ttyACM0", nrfutil_exec="/tmp/nrfutil"):
        r, o, _  = self.run_command(nrfutil_exec + ' dfu usb-serial -pkg ' + firmware + ' -p ' + serial_port + ' -b 115200')

        return b"Device programmed" in o

    def flash_butterfly(self, port="/dev/ttyACM0"):
        if not self.install_nrfutil():
            error("Failure during 'nrfutil' installation.")
            return False

        latest_release_filename = self.download_latest_butterfly_release()
        if latest_release_filename is None:
            error("Failure during 'butterfly' release download")
            return False

        success = self.flash_firmware_with_nrfutil(latest_release_filename, serial_port=port, nrfutil_exec="/tmp/nrfutil")
        return success

    def run_command(self, cmd, shell=False, force_env=None, cwd=None, added_path=None):
        info("Running command: " + cmd)

        if added_path is not None:
            env  = os.environ.copy()
            env["PATH"] = f"{env['PATH']}:/" + added_path
        elif force_env is not None:
            env = force_env
        else:
            env = os.environ
        process = Popen(shlex.split(cmd) if not shell else cmd,  stderr=PIPE, stdout=PIPE, shell=shell, cwd=cwd, env=env)
        stdout, stderr = process.communicate()
        if process.returncode != 0:
            error("Standard output:" + stdout.decode())
            error("Standard error:" + stderr.decode())

        return process.returncode , stdout, stderr

    def install_ubertooth_host(self):
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


    def download_latest_ubertooth_release(self):
         latest_release_url = self.get_latest_release("greatscottgadgets/ubertooth")
         try:
             release = latest_release_url.split("/tag/")[1]
             success("Latest ubertooth release: " + release)
             zip_url = "https://github.com/greatscottgadgets/ubertooth/releases/download/" + release + "/ubertooth-" + release + ".tar.xz"
             z_request = requests.get(zip_url, allow_redirects=True)
             if z_request.status_code == 200:
                 latest_release_filename = "/tmp/ubertooth-"+release+".tar.xz"
                 if os.path.exists(latest_release_filename):
                     os.unlink(latest_release_filename)
                 open(latest_release_filename, "wb").write(z_request.content)
                 return latest_release_filename
         except IndexError:
             error("Release not found, exiting...")
             return None

    def flash_ubertooth(self, port=None):
        if not self.install_ubertooth_host():
            error("Failure during 'ubertooth-dfu' installation.")
            return False

        latest_release_filename = self.download_latest_ubertooth_release()
        r, _, _ = self.run_command("tar -xf " + latest_release_filename, cwd="/tmp")
        if r != 0:
            return False

        r, _, _ = self.run_command("ubertooth-dfu -d bluetooth_rxtx.dfu -r" + (" -U "+str(port) if port is not None else ""), cwd=latest_release_filename.replace('.tar.xz',"/ubertooth-one-firmware-bin/"))
        if r != 0:
            return False
        return True


    def flash_yardstickone(self, port="/dev/RFCAT_BL_YS1"):
        r, _, _ = self.run_command("rm -rf /tmp/rfcat")
        if r != 0:
            return False

        r, _, _ = self.run_command("git clone https://github.com/atlas0fd00m/rfcat", cwd="/tmp")
        if r != 0:
            return False

        warning("For some reason, latest build from rfcat repo crashes the dongle, let's get the latest functional build.")
        r, _, _ = self.run_command("wget https://gist.githubusercontent.com/mossmann/7b816680df2ac513df3835f3cb9eaa1b/raw/2f33a76a86c8f6ee71dacb385537386486fe633a/RfCatYS1CCBootloader.hex -O /tmp/ys1.hex")
        if r != 0:
            return False

        if not os.path.exists(port):
            r, _, _ = self.run_command("/tmp/rfcat/rfcat --bootloader --force")
            if r != 0:
                return False
        r, _, _ = self.run_command("/tmp/rfcat/CC-Bootloader/rfcat_bootloader "+ port +" erase_all")
        if r != 0:
            return False
        r, _, _ = self.run_command("/tmp/rfcat/CC-Bootloader/rfcat_bootloader "+port+" download /tmp/ys1.hex")
        if r != 0:
            return False
        r, _, _  = self.run_command("/tmp/rfcat/CC-Bootloader/rfcat_bootloader "+port+" verify /tmp/ys1.hex")
        if r != 0:
            return False
        r, _, _ = self.run_command("/tmp/rfcat/CC-Bootloader/rfcat_bootloader "+port+" run")
        if r != 0:
            return False
        return True

    def install_sdcc(self):
        if self.check_tools_availability('sdcc'):
            return True

        distribution = distro.id()

        if distribution == 'fedora':

            r, _, _ = self.run_command('rm -rf /usr/bin/packihx /usr/bin/sdcc')
            if r != 0:
                return False

            r, _, _ = self.run_command('dnf install -y sdcc')
            if r != 0:
                return False

            r, _, _ = self.run_command('ln -s /usr/bin/sdcc-sdcc /usr/bin/sdcc')
            if r != 0:
                return False

            r, _, _ = self.run_command('ln -s /usr/bin/sdcc-packihx /usr/bin/packihx')
            if r != 0:
                return False

        elif distribution in ('debian', 'ubuntu', 'raspbian'):
            r, _, _ = self.run_command('apt install -y sdcc')
            if r != 0:
                return False

        else:
            error("Platform not supported, exiting.")
            return False

        return True

    def flash_rfstorm(self):
        if not self.install_sdcc():
            error("An error occured during 'sdcc' installation.")

        r, _, _ = self.run_command("rm -rf /tmp/nrf-research-firmware-python3")
        if r != 0:
            return False
        r, _, _ = self.run_command("pip install pyusb platformio")
        if r != 0:
            return False
        r, _, _ = self.run_command("git clone https://github.com/kuzmin-no/nrf-research-firmware-python3", cwd="/tmp")
        if r != 0:
            return False
        r, _, _ = self.run_command("make", cwd="/tmp/nrf-research-firmware-python3")
        if r != 0:
            return False
        r, o, e = self.run_command("lsusb")
        if b"1915:0102" in o or b"046d:c52b" in o:
            r, _, _ = self.run_command("make logitech_install", cwd="/tmp/nrf-research-firmware-python3")
            return r == 0
        else:
            r, _, _ = self.run_command("make install", cwd="/tmp/nrf-research-firmware-python3")
            return r == 0
        return False

    def install_esp_sdk(self):
        if self.check_tools_availability('idf.py'):
            return True

        distribution = distro.id()
        if distribution == 'fedora':
            r, _, _ = self.run_command('dnf install -y wget flex bison gperf python3 cmake ninja-build ccache dfu-util libusbx')
            if r != 0:
                return False

        elif distribution in ('debian', 'ubuntu', 'raspbian'):
            r, _, _ = self.run_command('apt-get install -y git wget flex bison gperf python3 python3-pip python3-venv cmake ninja-build ccache libffi-dev libssl-dev dfu-util libusb-1.0-0')
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

        r, _, _ = self.run_command("git clone -b release/v4.4 --recursive https://github.com/espressif/esp-idf.git", cwd="/tmp/esp")
        if r != 0:
            return False

        # Clear python path
        env = os.environ.copy()
        env["PYTHONPATH"] = ""

        r, _, _ = self.run_command("./install.sh esp32", shell=True, force_env=env, cwd="/tmp/esp/esp-idf")
        if r != 0:
            return False

        r, o, e = self.run_command(". ./export.sh > /dev/null; env", shell=True, force_env=env, cwd="/tmp/esp/esp-idf")
        if r != 0:
            return False

        os.environ.update(dict(line.decode().partition('=')[::2] for line in o.split(b'\n')[:-1]))

        r, o, e = self.run_command("idf.py --version", force_env=os.environ,  cwd="/tmp/esp/esp-idf")
        if r != 0:
            return False

        success("Espressif framework installed: " + o.decode())
        return True


    def flash_esp(self, port=None):
        if not self.install_esp_sdk():
            error("An error occured uring ESP SDK installation.")
            return False

        info("Cloning 'nodemcu-esp32-firmware' github repository...")
        r, _, _ = self.run_command("rm -rf /tmp/nodemcu-esp32-firmware/", force_env=os.environ,  cwd="/tmp")
        if r != 0:
            return False

        r, _, _ = self.run_command("git clone https://github.com/whad-team/nodemcu-esp32-firmware/ --recurse", force_env=os.environ,  cwd="/tmp")
        if r != 0:
            return False

        info("Building firmware...")
        r, _, _ = self.run_command("idf.py build", force_env=os.environ,  cwd="/tmp/nodemcu-esp32-firmware")
        if r != 0:
            return False

        info("Flashing firmware...")
        r, o, e = self.run_command("idf.py flash" + ("" if port is None else " -p " + port), force_env=os.environ,  cwd="/tmp/nodemcu-esp32-firmware")
        if r != 0:
            return False

        return True


    def download_latest_stm32wl55_release(self):
         latest_release_url = self.get_latest_release("whad-team/stm32wlxx-firmware")
         try:
             release = latest_release_url.split("/tag/")[1]
             success("Latest STM32WL55 firmware release: " + release)
             zip_url = "https://github.com/whad-team/stm32wlxx-firmware/releases/download/" + release + "/nucleo_wl55.hex"
             z_request = requests.get(zip_url, allow_redirects=True)
             if z_request.status_code == 200:
                 latest_release_filename = "/tmp/nucleo_wl55.hex"
                 if os.path.exists(latest_release_filename):
                     os.unlink(latest_release_filename)
                 open(latest_release_filename, "wb").write(z_request.content)
                 return latest_release_filename
         except IndexError:
             error("Release not found, exiting...")
             return None

    def download_latest_lorae5mini_release(self):
         latest_release_url = self.get_latest_release("whad-team/stm32wlxx-firmware")
         try:
             release = latest_release_url.split("/tag/")[1]
             success("Latest STM32WL55 firmware release: " + release)
             zip_url = "https://github.com/whad-team/stm32wlxx-firmware/releases/download/" + release + "/lora_e5_mini.hex"
             z_request = requests.get(zip_url, allow_redirects=True)
             if z_request.status_code == 200:
                 latest_release_filename = "/tmp/lora_e5_mini.hex"
                 if os.path.exists(latest_release_filename):
                     os.unlink(latest_release_filename)
                 open(latest_release_filename, "wb").write(z_request.content)
                 return latest_release_filename
         except IndexError:
             error("Release not found, exiting...")
             return None

    def install_stflash(self):
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
            return False



    def flash_nucleowl55(self):
        if not self.install_stflash():
            error("An error occured during 'st-flash' installation.")
            return False


        latest_release_filename = self.download_latest_stm32wl55_release()
        r, _, _ = self.run_command("st-flash --format=ihex write " + latest_release_filename, cwd="/tmp")
        if r != 0:
            return False

        return True



    def flash_lorae5mini(self):
        if not self.install_stflash():
            error("An error occured during 'st-flash' installation.")
            return False


        latest_release_filename = self.download_latest_lorae5mini_release()
        r, _, _ = self.run_command("st-flash --format=ihex write " + latest_release_filename, cwd="/tmp")
        if r != 0:
            return False

        return True

    def rules_rfstorm(self):
        if self.install_udev_rule("rfstorm"):
            self.need_reload = True
        return True

    def rules_ubertooth(self):
        if self.install_udev_rule("ubertooth"):
            self.need_reload = True
        return True

    def rules_rzusbstick(self):
        if self.install_udev_rule("rzusbstick"):
            self.need_reload = True
        return True

    def rules_yardstickone(self):
        if self.install_udev_rule("yardstickone"):
            self.need_reload = True
        return True

    def rules_nucleowl55(self):
        return self.install_serial_port_capabilities()

    def rules_lorae5mini(self):
        return self.install_serial_port_capabilities()

    def rules_esp(self):
        return self.install_serial_port_capabilities()

    def rules_butterfly(self):
        return self.install_serial_port_capabilities()

    def rules_apimote(self):
        return self.install_serial_port_capabilities()

    def rules_hci(self):
        python_interpreter = os.path.realpath(sys.executable)
        if not self.install_hci_capabilities(python_interpreter):
            return False
        success("HCI capabilities successfully added to python interpreter (%s)." % python_interpreter)
        return True

    def pre_run(self):
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
        process = Popen(['usermod', '-a', '-G', group, os.getlogin()], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if len(stderr) > 0:
            return False

        success("Serial port capabilities successfully configured (user %s added to group %s): logout to take modification into account." % (os.getlogin(), group))
        return True


    def reload_udev_rules(self):
        if not self.check_tools_availability("udevadm"):
            error("'udevadm' tool is required but not available")
            return False
        info("Reloading udev rules...")
        process = Popen(['udevadm', 'control', '--reload-rules'], stderr=PIPE, stdout=PIPE)
        stdout, stderr = process.communicate()
        if len(stderr) > 0:
            return False
        process = Popen(['udevadm', 'trigger'],  stderr=PIPE, stdout=PIPE)
        stdout, stderr = process.communicate()
        if len(stderr) > 0:
            return False
        return True


    def install_hci_capabilities(self, interpreter):
        if not self.check_tools_availability("getcap", "setcap"):
            error("'getcap' and 'setcap' tools are required but not available")
            return False
        process = Popen(['getcap', interpreter], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if "cap_net_admin,cap_net_raw=eip" not in stdout.decode('utf-8'):
            process = Popen(['setcap', 'cap_net_admin,cap_net_raw+eip',interpreter], stdout=PIPE, stderr=PIPE)
            stdout, stderr = process.communicate()

            if len(stdout) != 0 or len(stderr) != 0:
                return False
            return True
        else:
            return True


    def run(self):
        try:
            # Launch pre-run tasks
            self.pre_run()

            rules = self.args.rules
            flash = self.args.flash

            if not self.args.rules and not self.args.flash:
                # By default, if no option is provided, only use rules
                rules = True

            # We need root, let's ask
            if not self.ask_for_privileges():
                error("Login failed, aborting.")
                exit(1)

            # Iterate over devices
            for device in self.args.device:
                if flash:
                    if hasattr(self, "flash_" + device):
                        info("Flashing {} device ...".format(device))

                        flashfunc = getattr(self, "flash_" + device)
                        if self.args.port and "port" in list(inspect.signature(flashfunc).parameters):
                            if flashfunc(port=self.args.port):
                                success("Flashing successful for device '%s'." % device)
                            else:
                                error("An error occured during device flashing for device '%s'." % device)
                                exit(1)
                        else:
                            if flashfunc():
                                success("Flashing successful for device '%s'." % device)
                            else:
                                error("An error occured during device flashing for device '%s'." % device)
                                exit(1)
                    else:
                        warning("Flashing {} device is not supported yet.".format(device))

                if rules:
                    if hasattr(self, "rules_" + device):
                        info("Installing rules for {} device ...".format(device))
                        if getattr(self, "rules_" + device)():
                            success("Rules successfully added for device '%s'." % device)
                        else:
                            error("An error occured during device rules installation for device '%s'." % device)
                            exit(1)
                    else:
                        warning("Installing rules for {} device is not supported yet.".format(device))


            if rules and self.need_reload:
                if not self.reload_udev_rules():
                    error("An error occured during udev rules reload, exiting.")
                    exit(1)
                else:
                    success("Rules successfully reloaded.")
        except Exception as e:
            error("An error occured: " + repr(e))

        # Launch post-run tasks
        self.post_run()

def winstall_main():
    try:
        app = WhadInstallApp()
        app.run()
    except ApplicationError as err:
        err.show()
