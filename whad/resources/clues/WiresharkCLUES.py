import json
import csv
import sys
import os

def main():
    # Determine the input file path
    input_file = sys.argv[1] if len(sys.argv) > 1 else "./CLUES_data.json"
    output_file = "./bluetooth_uuids"

    # Check if the input file exists
    if not os.path.exists(input_file):
        print(f"Error: File '{input_file}' not found.")
        return

    try:
        # Open and load the JSON file
        with open(input_file, "r") as f:
            clues_data = json.load(f)

        # Open the CSV file for writing
        with open(output_file, "w", newline="") as csvfile:
            csv_writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)

            # Iterate through each entry in the JSON data
            for entry in clues_data:
                # Skip entries with "regex": true
                if "regex" in entry.keys():
                    continue

                # Extract the UUID
                first_field = entry.get("UUID")
                if not first_field:
                    continue  # Skip if UUID is missing

                # Determine the second CSV field
                company = entry.get("company", "Unknown")
                if "UUID_name" in entry:
                    second_field = f"{company}__{entry['UUID_name']}"
                else:
                    second_field = f"{company}__{entry['UUID_purpose']}"

                # Write the row to the CSV file
                csv_writer.writerow([first_field, second_field])

        print(f"CSV file '{output_file}' created successfully.")
        print(f"You must copy it to the correct location for Wireshark based on your OS.")
        print(f"E.g. on Linux and macOS: ~/.config/wireshark/bluetooth_uuids")
        print(f"E.g. on Windows: C:\Users\username\AppData\Roaming\Wireshark\bluetooth_uuids")

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    main()
