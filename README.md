# CTF Tools

This is a collection of CTF-tools explained with a quick how to commend.

First an honorable mention to some other big collections of tools:

1. [Eric Zimmerman's tools](https://ericzimmerman.github.io/#!index.md)
1. [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)

## Table of Contents

## Crypto

### RsaCtfTool

This tool is an utility designed to decrypt data from weak public keys and attempt to recover the corresponding private key. Also this tool offers a comprehensive range of attack options, enabling users to apply various strategies to crack the encryption. The RSA security, at its core, relies on the complexity of the integer factorization problem. This project serves as a valuable resource by combining multiple integer factorization algorithms, effectively enhancing the overall decryption capabilities.

```bash
docker run -it --rm -v $PWD:/data rsactftool/rsactftool
[-h]
[--publickey PUBLICKEY]
[--output OUTPUT]
[--timeout TIMEOUT]
[--createpub]
[--dumpkey]
[--ext]
[--decryptfile DECRYPTFILE]
[--decrypt DECRYPT]
```

For more about usage see [RsaCtfTool](https://github.com/RsaCtfTool/RsaCtfTool).


## Forensics

### Volatility

Volatility is the world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples. The extraction techniques are performed completely independent of the system being investigated but offer visibility into the runtime state of the system. The framework is intended to introduce people to the techniques and complexities associated with extracting digital artifacts from volatile memory samples and provide a platform for further work into this exciting area of research.

Links: [Volatility](https://github.com/volatilityfoundation/volatility) / [Volatility 3](https://github.com/volatilityfoundation/volatility3)

How to use Volatility 3:

```bash
docker run -it --rm -v $PWD:/workspace --entrypoint volshell sk4la/volatility3 -f dump.dmp
```

Alter the command by appending your wanted plugin:

| **Plugin** | **Description** | **Command-Line Example** |
| --- | --- | --- |
| **pslist** | Lists active processes by scanning memory for process structures, providing PID, name, and more. | `windows.pslist` |
| **pstree** | Displays processes in a tree format, showing parent-child relationships for easier analysis of process hierarchies. | `windows.pstree` |
| **dlllist** | Lists loaded DLLs for each process, useful for identifying injected DLLs or unusual libraries. | `windows.dlllist --pid <PID>` |
| **handles** | Shows open handles for each process, which can include files, registry keys, or other objects. | `windows.handles --pid <PID>` |
| **malfind** | Detects potentially malicious code injections and executable memory regions, highlighting suspicious activity. | `windows.malfind --pid <PID>` |
| **cmdline** | Extracts the command-line arguments for each process, useful for identifying suspicious process launches. | `windows.cmdline --pid <PID>` |
| **netscan** | Lists network connections and listening ports, providing insights into active or terminated network connections.| `windows.netscan` |
| **ssdt** | Displays the System Service Descriptor Table (SSDT), helping identify system call hooking by rootkits. | `windows.ssdt` |
| **filescan** | Scans for file objects in memory, useful for recovering files or identifying deleted/malicious files. | `windows.filescan` |
| **registry** | Extracts registry hives from memory, allowing the recovery of critical system and user information. | `windows.registry` |



## Reversing



## PWN

### pwntools

Docs: [pwntools.com](https://docs.pwntools.com/)

```bash
pip install pwntools
```

Quick buffer overflow example:

```py
from pwn import *

# process('./binary')
p = remote(host, port)

offset = 20
payload = b'A'*offset + p32(0x00000000)

p.sendline(payload)

p.interactive()
```


## OSINT

### Overpass turbo

Interpreter: https://overpass-turbo.eu/

```c
area[name="Norge"];
node(area)[highway=bus_stop];
node(around:100)[amenity=cinema];
out;
```

Another example:

```c
area[name="Oslo"];
node(area)[shop=electronics][brand~power, i];
out;
```

Docs for [how to use Overpass QL](https://wiki.openstreetmap.org/wiki/Overpass_API/Overpass_QL). Here is a list of different keys to use when querying:

| **Key** | **Values** |
|---------------|----------------------------------------------------------------------------------|
| [highway](https://wiki.openstreetmap.org/wiki/Key:highway) | motorway, road |
| [amenity](https://wiki.openstreetmap.org/wiki/Key:amenity) | fountain, hospital, fast_food, restaurant, library |
| [building](https://wiki.openstreetmap.org/wiki/Key:building)| house, hotel, school, church, bridge |
| [leisure](https://wiki.openstreetmap.org/wiki/Key:leisure) | park, garden, playground, swimming_pool, pitch, stadium |
| [shop](https://wiki.openstreetmap.org/wiki/Key:shop)| bakery, supermarket, clothing, electronics, furniture, hairdresser |
| [waterway](https://wiki.openstreetmap.org/wiki/Key:waterway)| river, waterfall, dock |
| [railway](https://wiki.openstreetmap.org/wiki/Key:railway) | rail, subway, tram, platform, halt, crossing |

`[out:json];` can be used when using tools like [overpass-api.de](https://overpass-api.de/api/interpreter?data=[out:json];area[name=%22Oslo%22];%20node(area)[shop=electronics][brand~power,%20i];%20out;r) to ensure it outputs json.


## Miscellaneous

### bkcrack

You can see a list of entry names and metadata in an archive named `archive.zip` like this:

```bash
./bkcrack -L archive.zip
```

Entries using ZipCrypto encryption are vulnerable to a known-plaintext attack.

```
bkcrack -j 4 -C challenge.zip -c challenge.iso -x 0x8001 4344303031 -x 0x8010 
202020202020202020202020202020202020202020202020
```

Remove password after found keys

```bash
./bkcrack -C secrets.zip -k c4490e28 b414a23d 91404b31 -D secrets_without_password.zip
```

| **Option** | **Description** |
|---|---|
| `-C <archive>`| Zip archive containing the ciphertext entry |
| `-c <file>` | Zip entry/file containing ciphertext |
| `-p <file>` | Zip entry/file containing plaintext |
| `-P <archive>` | Zip archive containing the plaintext entry|
| `-x <data>` | Additional plaintext in hexadecimal starting at the given offset (may be negative)|
| `--continue-attack <checkpoint>`| Start point to continue an interrupted attack|
| `-j <count>`| Number of threads for parallel operations|
| `-L <archive>`| List entries in a zip archive and exit|
| `-k <X> <Y> <Z>`| Internal password representation as three 32-bit integers in hexadecimal|
| `-D <archive>` | Create a copy of zip archive with deciphered entries (removes password protection)|
| `-r <min>..<max> <charset>` | Create a copy of zip archive with deciphered entries (removes password protection)|

Recover the password:

```bash
./bkcrack -k 18f285c6 881f2169 b35d661d -r 9..12 ?p
```

Charsets for bruteforce is as follows:

| **Shortcut** | **Description** |
|--------------|----------------------------|
| `?l` | Lowercase letters |
| `?d` | Decimal digits |
| `?a` | Alpha-numerical characters |
| `?p` | Printable ASCII characters |
| `?b` | Full range (0x00 - 0xff) |