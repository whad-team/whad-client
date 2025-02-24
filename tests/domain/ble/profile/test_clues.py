"""Test that CLUES data is available.
"""

import os
import json
from whad.ble.utils.clues import CluesDb

def test_clues_data():
    """Make sure CLUES data files have been fetched.
    """
    assert os.path.exists("./whad/resources/clues/CLUES_data.json")
    assert os.path.isfile("./whad/resources/clues/CLUES_data.json")

def test_clues_db():
    """Load CLUES database
    """
    # Must load without any error
    CluesDb.load_data()
