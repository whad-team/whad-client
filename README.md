# Custom Lightweight UUID Exchange Schema (CLUES!)

CLUES is an attempt to organize, capture, and share information about the many Universally Unique IDs (UUIDs) which are used in Bluetooth. UUIDs can be 16, 32, or 128 bits long.

The Bluetooth SIG defines *some* UUIDS (which are available in the Assigned Numbers PDFs or [git repository](https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/)), but many more are created as *custom UUIDs*, defined by vendors for whatever purpose they need. It's only possible to determine what a UUID is used for by:

 * Finding public vendor documentation for it.
 * Reverse engineering a device and how it uses a UUID.
 * Inferring information about it via data such as that collected by [Blue2thprinting](https://github.com/darkmentorllc/Blue2thprinting).

One interesting class of UUIDs are the UUID16s which are defined in [https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/member\_uuids.yaml](https://bitbucket.org/bluetooth-SIG/public/src/main/assigned_numbers/uuids/member_uuids.yaml). For these UUIDs, the *company* association has been assigned, but the *usage* is still often unknown, until we capture it here.

## Shared data

The `CLUES_data.json` file is the crowdsourced data which is currently captured in CLUES format (i.e. conforming to the `CLUES_schema.json` schema). It describes what is currently known/captured about custom UUIDs. This data is shared under a [CC BY-SA 4.0](https://creativecommons.org/licenses/by-sa/4.0/deed.en) license. It can be incorporated into other projects with an attribution of *"From the CLUES project - https://github.com/darkmentorllc/CLUES_Schema"*.

## Schema

The `CLUES_schema.json` is a schema which defines how the data in a CLUES file should be structured. The purpose of this file is to both allow for automatic verification, and automatic documentation creation.

The [automatically generated documentation](https://darkmentor.com/CLUES_Schema/CLUES.html) can be generated via the below commands.

```
python3 -m venv ./venv
source ./venv/bin/activate
pip3 install json-schema-for-humans
```

Documentation using online Javascript:  
`generate-schema-doc CLUES_schema.json CLUES.html`  

Documentation using offline/local Javascript:  
`generate-schema-doc CLUES_schema.json --config  template_name=js_offline CLUES.html`  

Documentation using Markdown:  
`generate-schema-doc CLUES_schema.json --config  template_name=md CLUES.md`

We prefer the collapsible HTML/JS formatting, therefore the latest copy of that documentation will always be mirroed to [https://darkmentor.com/CLUES_Schema/CLUES.html](https://darkmentor.com/CLUES_Schema/CLUES.html).

# Contributing

We are seeking contributions of more UUIDs. To add an entry perform the following steps:

1) Create a fork of this repository.

2) Add your change to the end of `CLUES_data.json`.

3) ***Verify the data still conforms to the schema***, by running the following on *nix or macOS:

 * `python3 -m venv ./venv`
 * `source ./venv/bin/activate`
 * `pip3 install check-jsonschema`
 * `check-jsonschema --verbose --base-uri ./CLUES_schema.json --schemafile ./CLUES_schema.json ./CLUES_data.json`

4) Re-sort the `CLUES_data.json` by running:

 *  `python3 SortCLUES.py` from within your fork.
 *  Search for any entries marked "MERGED", and correct them (e.g. if they should legitimately be merged, merge their descriptions. If not, correct the UUID conflict which caused them to be merged.)

5) Commit your changes and make a pull request.
