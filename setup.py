try:
    from setuptools import setup
    from setuptools.command.install import install
    from sys import platform, exit, executable
    from subprocess import Popen, DEVNULL, PIPE
    from os.path import exists, realpath
    from shutil import copy
    from os import listdir, geteuid, getlogin
    from grp import getgrall
except ImportError:
    print("Your operating system is not supported.")

class DevicesInstall(install):
    UDEV_LOCATION = [
        "/etc/udev/rules.d",
        "/lib/udev/rules.d",
        "/run/udev/rules.d",
        "/var/run/udev/rules.d"
    ]

    def install_udev_rule(self, name):
        print("Installing rules for %s device ..." % name)
        matching_rules = [udev_name for udev_name in self.udev_rules if name in udev_name]
        if len(matching_rules) == 0:
            if exists("ressources/rules/"+name+".rules"):
                copy("ressources/rules/"+name+".rules", "/usr/lib/udev/rules.d/40-"+name+".rules")
                return True
            else:
                print("Rule not found, skipping.")
                return False
        else:
            print("Rules detected for device %s (%s), skipping." % (name, ",".join(matching_rules)))
            return False

    def reload_udev_rules(self):
        print("Reloading udev rules...")
        process = Popen(['udevadm', 'control', '--reload-rules'], stderr=PIPE, stdout=PIPE)
        stdout, stderr = process.communicate()
        if len(stderr) > 0:
            return False

        process = Popen(['udevadm', 'trigger'],  stderr=PIPE, stdout=PIPE)
        stdout, stderr = process.communicate()
        if len(stderr) > 0:
            return False

        return True

    def install_serial_port_capabilities(self):
        print("Installing serial port capabilities...")
        # Find the right group which depends on the distribution (e.g. dialout
        # for Debian, uucp for Arch-Linux).
        groups = [ group.gr_name for group in getgrall() ]
        if "dialout" in groups:
            group = "dialout"
        elif "uucp" in groups:
            group = "uucp"
        else:
            raise Exception("Group granting serial port capabilities not found!")
        process = Popen(['usermod', '-a', '-G', group, getlogin()], stdout=PIPE, stderr=PIPE)
        stdout, stderr = process.communicate()

        if len(stderr) > 0:
            return False
        return True

    def install_hci_capabilities(self, interpreter):
        print("Installing HCI capabilities...")
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
        if platform == "linux" or platform == "linux2":
            if geteuid() != 0:
                print("You should run this installer as root !")
                exit(1)

            print("Installing devices...")
            # linux
            self.udev_rules = []
            for location in DevicesInstall.UDEV_LOCATION:
                if exists(location):
                    self.udev_rules += listdir(location)

            self.install_udev_rule("ubertooth")
            self.install_udev_rule("rzusbstick")
            self.install_udev_rule("rfstorm")
            self.install_udev_rule("yardstickone")

            if not self.reload_udev_rules():
                print("An error occured during udev rules reload.")

            python_interpreter = realpath(executable)
            if not self.install_hci_capabilities(python_interpreter):
                print("An error occured during HCI capabilities installation.")

            if not self.install_serial_port_capabilities():
                print("An error occured during Serial port capabilities installation.")
            else:
                print("User added to group 'dialout', please logout to take the modification into account.")
        else:
            print("Automatic device installation is not supported on your operating system.")
            exit(1)

if __name__ == "__main__":
    setup()
