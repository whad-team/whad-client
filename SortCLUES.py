# Sorting logic auto-generated via AI, and results just eyeballed to see that they look good enough. Most likely has issues
# The basic goal is to sort first by company name, alphabetically, ascending order
# Then second to group things so that UUIDs with parent_UUID fields are placed underneath the parent_UUIDs
# and the placed-under elements should be sorted also in ascending order.

import json
from itertools import groupby
from collections import defaultdict

def merge_entries(entry1, entry2):
    # Check if UUID_usage_array fields are the same
    if entry1.get('UUID_usage_array') != entry2.get('UUID_usage_array'):
        return entry1  # Skip merge if UUID_usage_array fields are not the same

    merged_entry = {}
    for key in entry1:
        if isinstance(entry1[key], list) and isinstance(entry2[key], list):
            merged_entry[key] = list({json.dumps(item) for item in entry1[key] + entry2[key]})
            merged_entry[key] = [json.loads(item) for item in merged_entry[key]]
        elif isinstance(entry1[key], str) and isinstance(entry2[key], str):
            if entry1[key] == entry2[key]:
                merged_entry[key] = entry1[key]
            else:
                merged_entry[key] = f"MERGED: ({entry1[key]}), ({entry2[key]})"
        else:
            merged_entry[key] = entry1[key] if entry1[key] is not None else entry2[key]
    return merged_entry

def entries_are_equal(entry1, entry2):
    if not entry1 or not entry2:
        return False
    return all(entry1.get(key) == entry2.get(key) for key in entry1)

def sort_custom_uuids(file_path):
    with open(file_path, 'r') as f:
        data = json.load(f)

    def sort_key(entry):
        company = entry['company'] if entry['company'] is not None else ''
        return company, entry['UUID_purpose'], entry['UUID']

    # Convert UUID and parent_UUID to lowercase and group entries by concatenated key
    uuid_groups = {}
    for entry in data:
        entry['UUID'] = entry['UUID'].lower()
        if 'parent_UUID' in entry:
            entry['parent_UUID'] = entry['parent_UUID'].lower()
        company = entry['company'] if entry['company'] is not None else ''
        uuid_usage_array = json.dumps(entry.get('UUID_usage_array', []))
        key = f"{company}-{entry['UUID']}-{uuid_usage_array}"
        if key in uuid_groups:
            uuid_groups[key] = merge_entries(uuid_groups[key], entry)
        else:
            uuid_groups[key] = entry

    # Sort the entries
    sorted_entries = sorted(uuid_groups.values(), key=sort_key)

    # Group entries by parent_UUID
    parent_uuid_map = defaultdict(list)
    for entry in sorted_entries:
        parent_uuid = entry.get('parent_UUID')
        if parent_uuid:
            parent_uuid_map[parent_uuid].append(entry)
        else:
            parent_uuid_map[entry['UUID']].append(entry)

    # Flatten the grouped entries
    final_sorted_entries = []
    for uuid, entries in parent_uuid_map.items():
        # Add the parent entry first
        parent_entry = next((e for e in entries if e['UUID'] == uuid), None)
        if parent_entry:
            final_sorted_entries.append(parent_entry)
            entries.remove(parent_entry)
        # Sort the child entries by UUID
        sorted_children = sorted(entries, key=lambda e: e['UUID'])
        # Add the child entries
        final_sorted_entries.extend(sorted_children)

    # Write the sorted entries back to the file
    with open(file_path, 'w') as f:
        json.dump(final_sorted_entries, f, indent=4)

# Example usage
# sort_custom_uuids('/path/to/your/file.json')

if __name__ == "__main__":
    sort_custom_uuids('CLUES_data.json')
