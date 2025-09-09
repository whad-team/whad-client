"""Machine module
"""
import sys
import uuid

class Machine:
    """Store data about the host machine.
    """

    # Unique ID
    unique_id = None

    @staticmethod
    def gen_unique_id() -> bytes:
        """Generate a unique ID for this machine and store it in a temporary
        standardized file. This unique is store on the filesystem and can be
        accessed by other tools to synchronize the obfuscated values.

        :rtype: bytes
        :return: Unique ID for this machine
        """
        if Machine.unique_id is None:
            # Generate and save machine seed
            Machine.unique_id = bytes(uuid.uuid4().bytes.hex(), encoding="utf-8")
            with open("/tmp/whad-machine-id", "wb") as machine_id:
                machine_id.write(Machine.unique_id)

        return Machine.unique_id

    @staticmethod
    def get_unique_id():
        """Return this machine unique ID.

        :rtype: bytes
        :return: Machine unique ID
        """
        # On Linux platforms, use /etc/machine-id as unique ID.
        if sys.platform in ("linux", "linux2"):
            try:
                with open("/etc/machine-id", "rb") as mid:
                    return mid.read().strip()
            except FileNotFoundError:
                pass
            except IOError:
                pass

        # On other systems, try to write "/tmp/whad-machine-id" to emulate the
        # behaviour of /etc/machine-id
        try:
            with open("/tmp/whad-machine-id", "rb") as machine_id:
                Machine.unique_id = machine_id.read().strip()
                return Machine.unique_id
        except FileNotFoundError:
            return Machine.gen_unique_id()
        except IOError:
            Machine.unique_id = uuid.uuid4().bytes
            return Machine.unique_id
