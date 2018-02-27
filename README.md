bootcode_parser
=================
```bootcode_parser.py``` is a Python script designed to perform a quick offline analysis of the boot records used by BIOS based systems (UEFI is *not* supported).

It is intended to help the analyst triaging individual boot record dumps or whole disk images.
The latter is preferred since it allows the script to perform additional checks that would not be possible on individual dumps alone.

This script only detects anomalies that have to be manually investigated by an analyst.
Because it works with a whitelist mechanism it will be able to detect a wide range of malicious codes,
but it will also detect legitimate (encryption software, etc...) or benign modification of the boot records.

This topic has been presented during a talk at the French conference CORI&IN 2017.

How does it work ?
==================
The script is based on the fact that boot records contain code sections that do not vary much from a machine to another.
The differences can be identified and understood by performing a static analysis.

This script merely implements the results of these analyses and tries to narrow down these "invariant" codes and hash them.
The hash is then compared to a whitelist of known good signatures that has to be built by the analyst (an example is given, but it is advised to build its own).
If no record is found in the whitelist then the boot record *must* be investigated by the analyst.
In this case, static analysis is the only way to decide whether the boot record has been infected or not.

How to interpret the results ?
==============================
[INFO] messages mean the boot record was found in the whitelist

[WARNING] messages mean the boot record or the boot sequence (when providing a whole disk image) needs to be investigated

[ERROR] messages mean the script could not finish its operation, generally because the sample's structure could not be validated

[DEBUG] messages (displayed with ```--logLevel DEBUG```) can be used to show internal details of the process of verification
 and display the newly calculated hash of an unknown boot record

Dependencies
============
* python2 >= 2.7
* python-construct == 2.8
* python-capstone >= 3.0.4

Usage
=====
```
usage: bootcode_parser.py [-h] --type {VBR,MBR,IPL,IMG} --input INPUT
                          [INPUT ...] [--offset OFFSET]
                          [--sector-size SECTOR_SIZE] [--whitelist WHITELIST]
                          [--logLevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}]

Check boot records for known good signatures

optional arguments:
  -h, --help            show this help message and exit
  --type {VBR,MBR,IPL,IMG}
                        Type of boot record: MBR, VBR or IPL. Or whole disk image.
  --input INPUT [INPUT ...]
                        Input file(s) to check
  --offset OFFSET       Offset in bytes at which the boot record was dumped. Required only for VBR. Without it, some heuristics to detect malicious VBR will not work.
  --sector-size SECTOR_SIZE
                        Disk sector size in bytes. Only applies for disk image input. Defaults to 512.
  --whitelist WHITELIST
                        CSV file containing whitelisted boot record signatures. Without it, the boot record will always be flagged as suspicious. Defaults to ./data/bootrecord_whitelist.csv
  --logLevel {DEBUG,INFO,WARNING,ERROR,CRITICAL}
                        Show debug messages according to the level provided.
```

Examples
========
Usage with individual boot records
----------------------------------

* MBR from fresh installs of Windows XP, Vista and 7, empty MBR (completely empty or just the code section), protective MBR and TrueCrypt MBR

```shell
python bootcode_parser.py --type MBR --input test_data/mbr_*
```
```
INFO     - [test_data/mbr_5.bin] [MBR] Known signatures found: ['NT5.1/5.2 MBR']
INFO     - [test_data/mbr_60.bin] [MBR] Known signatures found: ['NT6.0 MBR']
INFO     - [test_data/mbr_61.bin] [MBR] Known signatures found: ['NT6.1+ MBR']
ERROR    - [test_data/mbr_empty.bin] [MBR] Invalid MBR structure: expected 'U\xaa', found '\x00\x00'
00000000:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
[...]
000001F0:  00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00   |................|
WARNING  - [test_data/mbr_empty_code.bin] [MBR] No known code signature were found, this is highly suspicious.
WARNING  - [test_data/mbr_empty_code.bin] [MBR] Suspicious behaviours were detected: [u'Code section is null']
INFO     - [test_data/mbr_protect_uefi.bin] [MBR] Known signatures found: [u'Protective MBR', u'UEFI (no legacy boot code)']
INFO     - [test_data/mbr_tc.bin] [MBR] Known signatures found: ['TrueCrypt MBR']
```

* VBR from fresh installs of Windows Vista, 7 and 8

```shell
python bootcode_parser.py --type VBR --offset $((2048*512)) --input test_data/vbr_*_off_$((2048*512)).bin
```
```
INFO     - [test_data/vbr_60_off_1048576.bin] [VBR] Known signatures found: ['NT6.0 VBR']
INFO     - [test_data/vbr_61_off_1048576.bin] [VBR] Known signatures found: ['NT6.1 VBR']
INFO     - [test_data/vbr_62_off_1048576.bin] [VBR] Known signatures found: ['NT6.2+ VBR']
```

* VBR from a fresh install of Windows XP

```shell
python bootcode_parser.py --type VBR --offset $((63*512)) --input test_data/vbr_*_off_$((63*512)).bin
```
```
INFO     - [test_data/vbr_5_off_32256.bin] [VBR] Known signatures found: ['NT5.1/NT5.2 VBR']
```

* IPL from fresh installs of Windows XP, Vista, 7 and 8

```shell
python bootcode_parser.py --type IPL --input test_data/ipl_*
```
```
INFO     - [test_data/ipl_5.bin] [IPL] Known signatures found: ['NT5.1/NT5.2 IPL']
INFO     - [test_data/ipl_60.bin] [IPL] Known signatures found: ['NT6.0 IPL']
INFO     - [test_data/ipl_61.bin] [IPL] Known signatures found: ['NT6.1 IPL']
INFO     - [test_data/ipl_62.bin] [IPL] Known signatures found: ['NT6.2+ IPL']
```

Usage with whole disk images
----------------------------
* Fresh install of Windows 7

```shell
python bootcode_parser.py --input clean_win7.dd --type IMG
```
```
INFO     - [/dev/storage/VM-Win7] Known signatures found: ['NT6.1+ MBR']
INFO     - [/dev/storage/VM-Win7] Known signatures found: ['NT6.1 VBR']
INFO     - [/dev/storage/VM-Win7] Known signatures found: ['NT6.1 IPL']
```

* Windows XP infected with Gapz

```shell
python bootcode_parser.py --input infected_with_gapz.dd --type IMG
```
``` 
INFO     - [infected_with_gapz.dd] [MBR] Known signatures found: ['NT5.1/5.2 MBR']
INFO     - [infected_with_gapz.dd] [VBR] Known signatures found: ['NT5.1/NT5.2 VBR']
WARNING  - [infected_with_gapz.dd] [VBR] Suspicious behaviours were detected: [u'Suspicious HiddenSectors value: 41942254 (21474434048 bytes)']
WARNING  - [infected_with_gapz.dd] [VBR] VBR of the active partition located at sector 63 (offset 32256) is suspicious (see previous warning). This could mean that the partition table in the MBR or the BPB in the VBR has been tampered with !
WARNING  - [infected_with_gapz.dd] [IMG] HiddenSectors value in BiosParameterBlock is different than actual offset in partition table ! HiddenSectors=41942254, partition table offset=63
ERROR    - [infected_with_gapz.dd] [IMG] Invalid IPL structure: expected 74016, found 7678
00000000:  90 90 90 90 90 90 90 90  90 90 90 90 90 90 90 90   |................|
[...]
000001F0:  90 90 90 90 90 90 90 90  90 90 90 90 eb 49 55 aa   |.............IU.|
```

* Windows XP infected with Rovnix

```shell
python bootcode_parser.py --input infected_with_rovnix.dd --type IMG
```
```
INFO     - [infected_with_rovnix.dd] [MBR] Known signatures found: ['NT5.1/5.2 MBR']
INFO     - [infected_with_rovnix.dd] [VBR] Known signatures found: ['NT5.1/NT5.2 VBR']
WARNING  - [infected_with_rovnix.dd] [IPL] No known code signature were found, this is highly suspicious.
WARNING  - [infected_with_rovnix.dd] [IPL] Suspicious behaviours were detected: [u'Unknown Interrupt : 0x70']
```
