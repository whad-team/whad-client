"""Helper functions to parse DarkMentorLLC's CLUES collaborative database.
"""
import json
import os.path
from importlib import resources

from whad.ble.profile.attribute import UUID

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

    @staticmethod
    def load_data():
        """Load data from CLUES_data.json file
        """
        if len(CluesDb.CLUES_CACHE) == 0:
            # Load data from CLUES_data.json into cache
            clues_data_path = os.path.join(resources.files("whad"),
                                           "resources/clues/CLUES_data.json")
            with open(clues_data_path, 'r', encoding="utf-8") as clues_json:
                CluesDb.CLUES_CACHE = json.load(clues_json)

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
