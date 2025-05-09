"""WHAD user settings
"""
import os
import logging
from random import randbytes

import platformdirs
from tomlkit import load as load_toml, dump as dump_toml, document, comment, \
    table

# Module logger
logger = logging.getLogger(__name__)

class UserSettings:
    """User settings for WHAD.

    The following settings are stored in the user's default OS application
    configuration directory:

    - color preference: WHAD tools use colors for better readability but it can
      sometimes bother some users for some reason (color-blind people,
      color-less terminal, ...). This setting allow users to disable colors in
      WHAD CLI tools.

    - privacy seed: logging information for debugging or getting some help is a
      regular practice but could leak private information like a device
      identifier or a network name. WHAD uses this privacy seed to anonymize
      logs when required and keep any identifiable information private while
      being consistent from one tool to another. Any network name or device
      identifier will be replaced by a corresponding unique name or identifier
      in any log output, keeping logs information consistent while keeping
      private information private.
    """

    def __init__(self):
        """Loading user settings from user's WHAD configuration file.

        If configuration file cannot be find, create it with our default settings.
        """
        self.__config = None
        self.__nonpersistent = False

        # Resolve user configuration file for whad
        self.__config_path = platformdirs.user_config_path('whad')

        # If file does not exist, create default settings and save to file
        if not os.path.exists(self.__config_path):
            self.__create_default()
            self.__save()

        # If file does exist but is not a regular file, throw an error and use
        # default settings in a non-presistent way.
        if not os.path.isfile(self.__config_path):
            logger.error("WHAD user configuration file '%s' is not a file !",
                         self.__config_path)
            logger.error("Using default settings (not persistent)")
            self.__create_default()
            self.__nonpersistent = True
        else:
            # Load file (persistent mode)
            self.__load()

    def __load(self):
        """Load settings from user config file.
        """
        with open(self.__config_path, mode="rt", encoding="utf-8") as cfg:
            self.__config = load_toml(cfg)

    def __save(self):
        """Save settings to user config file.
        """
        if self.__nonpersistent:
            logger.warning("User settings cannot be saved.")
        else:
            with open(self.__config_path, mode="wt", encoding="utf-8") as cfg:
                dump_toml(self.__config, cfg)
                logger.info("WHAD user settings successfully loaded from %s.",
                            self.__config_path)

    def __create_default(self):
        """Create the user's whad configuration file and populate it with
        default settings.
        """
        seed = self.__create_privacy_seed()
        general = table().add("colors", True).add("privacy_seed", seed)
        self.__config = document().add(comment("General settings")).add("global", general)

    def __create_privacy_seed(self) -> str:
        """Generate a privacy seed for the current user.

        :return: Privacy seed
        :rtype: str
        """
        return randbytes(16).hex()

    @property
    def privacy_seed(self) -> bytes:
        """Privacy seed
        """
        try:
            return bytes.fromhex(self.__config["global"]["privacy_seed"])
        except ValueError:
            logger.error("Bad format for privacy seed, re-generating...")
            self.__config["global"]["privacy_seed"] = self.__create_privacy_seed()

    @property
    def color_enabled(self) -> bool:
        """Colors in terminal
        """
        return self.__config["global"]["colors"]
