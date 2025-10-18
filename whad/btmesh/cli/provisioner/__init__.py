"""Bluetooth Low Energy peripheral utility for WHAD"""

from whad.cli.app import CommandLineApp, run_app
from whad.btmesh.cli.provisioner.shell import BTMeshProvisionerShell

from .commands import *


class BTMeshProvisionerApp(CommandLineApp):
    """Bluetooth Mesh Provisionee emulation app"""

    def __init__(self):
        """Initialize our application: we need a WHAD interface (adapter) to be
        specified and we support custom commands.
        """
        super().__init__(
            description="WHAD Bluetooth Mesh provisioner utility",
            commands=True,
            interface=True,
        )

        # Add an option to specify the target Bluetooth Device address
        self.add_argument(
            "--bdaddr", "-b", dest="bdaddr", help="Specify device BD address"
        )

        # Add an option to provide an existing device profile
        self.add_argument(
            "--profile", "-p", dest="profile", help="Use a saved device profile"
        )

        # Add an option to allow scripting through a file
        self.add_argument("--file", "-f", dest="script", help="Specify a script to run")

    def run(self):
        """Override App's run() method to handle scripting feature."""
        # Launch pre-run tasks
        self.pre_run()

        if self.args.script is not None:
            # Launch an interactive shell (well, driven by our script)
            myshell = BTMeshProvisionerShell(self.interface)
            myshell.run_script(self.args.script)
        else:
            # Run the application through WHAD's main app routine
            super().run()

        # Launch post-run tasks
        self.post_run()


def btmesh_provisioner_main():
    """BTMesh provisioner emulation main routine."""
    app = BTMeshProvisionerApp()
    run_app(app)
