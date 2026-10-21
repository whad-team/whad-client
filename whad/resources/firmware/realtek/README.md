# Bundled Realtek Bluetooth firmware

These four unmodified binary files are from the upstream
[linux-firmware rtl_bt directory](https://gitlab.com/kernel-firmware/linux-firmware/-/tree/main/rtl_bt).
Their binary redistribution terms are reproduced in
`LICENCE.rtlwifi_firmware.txt`. WHAD's MIT license does not replace those terms.

| File | SHA-256 |
| --- | --- |
| `rtl8761bu_fw.bin` | `1d7a9597349ad89344fa16c1913d3e39e9a12e966e417ca16871bc79bbe59edb` |
| `rtl8761bu_config.bin` | `6c28a3f07c6a30ed208c4b64862a23f02b7d93543ea980edd24df16bab45095f` |
| `rtl8761cu_fw.bin` | `525bfa5ab9a3ed74b788f9ac494467c522a436c1bc5290ebcb05c7f920533c09` |
| `rtl8761cu_config.bin` | `3142c2732470e4edcdb68edf58cc505b581e38d56b3ec09c64eddcb1d5099507` |

The RTL8761CU file here is the ordinary upstream Bluetooth patch. It is not
the separate Realtek test firmware that enables LMP/LLCP passthrough.

On macOS, WHAD exposes supported USB adapters as `hciusb:<VID:PID/serial>`;
for example, `hciusb:0BDA:C761/10000`. Development boards running a separate
vendor test image may need that image loaded independently; it is not bundled
here.
