from whad.cli.app import command
from whad.btmesh.cli.provisioner.shell import BTMeshProvisionerShell


@command("interactive")
def interactive_handler(app, _):
    """interactive BTMesh shell

    <ansicyan><b>interactive</b></ansicyan>

    Starts an interactive shell and let you create and advertise a BT MESH Whad device:
    """
    # We need to have an interface specified
    if app.interface is not None:
        # Launch an interactive shell
        myshell = BTMeshProvisionerShell(app.interface)
        myshell.run()
    else:
        app.error("You need to specify an interface with option --interface.")
