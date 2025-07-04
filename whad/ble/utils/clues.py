"""Helper functions to parse DarkMentorLLC's CLUES collaborative database.
"""
import json
import os.path
import logging

from importlib import resources

from whad.ble.profile.attribute import UUID

logger = logging.getLogger(__name__)

def uuid_match(uuid: UUID, pattern: str) -> bool:
    """Determine if the provided UUID matches the pattern.
    """
    # Convert UUID to str
    uuid_s = str(uuid)

    # Make sure both have same length
    if len(pattern) != len(uuid_s):
        return False

    for pos, c in enumerate(pattern):
        # 'x' in pattern is a wildcard
        if c == 'x':
            continue

        # If characters do not match, UUID is different
        if uuid_s[pos] != c:
            return False

    # Success
    return True


class CluesDb:
    """DarkMentorLLC Clues collaborative database.
    """
    CLUES_CACHE = []
    loaded = False

    @staticmethod
    def load_data() -> bool:
        """Load data from CLUES_data.json file
        """
        result = False

        if not CluesDb.loaded:
            # Load data from CLUES_data.json into cache
            clues_data_path = os.path.join(resources.files("whad"),
                                           "resources/clues/CLUES_data.json")

            # Ensure the database file is present
            if os.path.exists(clues_data_path):
                try:
                    with open(clues_data_path, 'r', encoding="utf-8") as clues_json:
                        CluesDb.CLUES_CACHE = json.load(clues_json)

                    # Success
                    result = True
                except IOError:
                    logger.debug("[cluesdb] input/output error while trying to open file %s", clues_data_path)
                    logger.error("CLUES database could not be loaded (read error)")
            else:
                logger.debug("[cluesdb] missing database file CLUES_data.json, expected path: %s", clues_data_path)
                logger.error("CLUES database could not be be found (missing file)")

        # Mark DB as loaded, even if it failed (avoiding multiple error messages).
        CluesDb.loaded = True

        # Return operation result
        return result

    @staticmethod
    def get_uuid_alias(uuid: UUID) -> str:
        """Generate alias based on UUID.
        """
        # Load data into cache
        CluesDb.load_data()

        # Loop on services and known UUIDS
        for clue in CluesDb.CLUES_CACHE:
            # Is it our UUID ?
            if uuid_match(uuid, clue["UUID"]):
                # If UUID belongs to a service, include company name
                if "GATT Service" in clue["UUID_usage_array"] and "UUID_name" in clue:
                    name = clue["UUID_name"]
                    company = clue["company"]
                    return f"{company} | {name}"
                if "GATT Characteristic" in clue["UUID_usage_array"] and "UUID_name" in clue:
                    name = clue["UUID_name"]
                    return f"{clue['UUID_name']}"

        # Not found
        return None
