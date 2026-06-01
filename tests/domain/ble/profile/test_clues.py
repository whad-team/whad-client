"""Test that CLUES data is available.
"""

import os
import json
from whad.ble.utils.clues import CluesDb

def test_clues_data():
    """Make sure CLUES data files have been fetched.
    """
    assert os.path.exists("./whad/resources/clues/data/CLUES_data_human_verified.json")
    assert os.path.isfile("./whad/resources/clues/data/CLUES_data_human_verified.json")
    # load JSON
    with open("./whad/resources/clues/data/CLUES_data_human_verified.json", 'r', encoding="utf-8") as clues_json:
        json.load(clues_json)
