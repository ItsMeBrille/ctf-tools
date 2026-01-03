# CTF Tools

This is a collection of CTF-tools explained with quick how-to commands.


## Table of Contents

## Quick Linux tools

### Change IP

```bash
ip addr add 192.168.1.1/24 dev eth0
```


### Quick SSH file copy

```bash
echo "tar cvfz - ." | ssh server > loot.tgz 
tar -xvzf loot.tgz
```


## Crypto

### dCode.fr

[Cipher identifier](https://www.dcode.fr/cipher-identifier)
[Hash identifier](https://www.dcode.fr/hash-identifier)


### RsaCtfTool

This tool is a utility designed to decrypt data from weak public keys and attempt to recover the corresponding private key. Also, this tool offers a comprehensive range of attack options, enabling users to apply various strategies to crack the encryption. The RSA security, at its core, relies on the complexity of the integer factorization problem. This project serves as a valuable resource by combining multiple integer factorization algorithms, effectively enhancing the overall decryption capabilities.

```bash
docker run -it --rm -v "$PWD":/data rsactftool/rsactftool
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



## Cracking

### CrackStation

Find hashed passwords using a rainbow table attack.

[crackstation.net](https://crackstation.net/)


### Hashcat

Try to identify the hash:

```bash
hashcat -a 0 hash.txt rockyou.txt
```

#### Set `-m` to crack a specific hash type.

- `-a 0` — **Straight / Dictionary**. Try words from a wordlist (can use rules).
- `-a 1` — **Combination**. Concatenate words from two wordlists.
- `-a 3` — **Brute-force / Mask**. Try all combinations from charset masks.
- `-a 6` — **Hybrid (wordlist + mask)**. Wordlist entry + mask.
- `-a 7` — **Hybrid (mask + wordlist)**. Mask + wordlist entry.

Crack hash with wordlist (-m sets hash type)

hashcat list: https://hashcat.net/wiki/doku.php?id=example_hashes

```bash
hashcat -m 0 -a 0 hash.txt rockyou.txt
```

Brute force a specific pattern:
```bash
hashcat -m 0 -a 3 hash.txt ?u?u?d?d?d?d?d
```


### CeWLeR

[roys/cewler](https://github.com/roys/cewler) is a program used to generate a wordlist from a url.

```bash
docker run --rm -v "$PWD":/w ghcr.io/ItsMeBrille/cewler:latest --output /w/wordlist.txt https://example.com
```


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

Remove the password after finding the keys

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

Charsets for bruteforce are as follows:

| **Shortcut** | **Description** |
|--------------|----------------------------|
| `?l` | Lowercase letters |
| `?d` | Decimal digits |
| `?a` | Alpha-numerical characters |
| `?p` | Printable ASCII characters |
| `?b` | Full range (0x00 - 0xff) |



## Forensics

### Eric Zimmerman's tools

[Eric Zimmerman's tools](https://ericzimmerman.github.io/#!index.md)

| Name               | Purpose |
|--------------------|---------|
| [Timeline Explorer](https://download.ericzimmermanstools.com/net9/TimelineExplorer.zip) | View CSV and Excel files, filter, group, sort, etc. with ease |
| [Registry Explorer](https://download.ericzimmermanstools.com/net9/RegistryExplorer.zip) | Registry viewer with searching, multi-hive support, plugins, and more. Handles locked files |
| [EvtxECmd](https://download.ericzimmermanstools.com/net9/EvtxECmd.zip)                  | Event log (evtx) parser with standardized CSV, XML, and JSON output; supports locked files |
| [RECmd](https://download.ericzimmermanstools.com/net9/RECmd.zip)                        | Powerful command line Registry tool with searching, multi-hive support, plugins |


### Volatility

Volatility is the world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples. The extraction techniques are performed completely independent of the system being investigated, but offer visibility into the runtime state of the system. The framework is intended to introduce people to the techniques and complexities associated with extracting digital artifacts from volatile memory samples and provide a platform for further work into this exciting area of research.

Links: [Volatility](https://github.com/volatilityfoundation/volatility) / [Volatility 3](https://github.com/volatilityfoundation/volatility3)

How to use Volatility 3:

```bash
docker run -it --rm -v "$PWD":/workspace sk4la/volatility3 -f dump.dmp windows.pslist
```

Alter the command by appending your wanted plugin:

| **Plugin**   | **Description** | **Command-Line Example** |
| --- | --- | --- |
| **pslist**   | Lists active processes by scanning memory for process structures, providing PID, name, and more.               | `windows.pslist` |
| **pstree**   | Displays processes in a tree format, showing parent-child relationships.                                       | `windows.pstree` |
| **dlllist**  | Lists loaded DLLs for each process, useful for identifying injected DLLs or unusual libraries.                 | `windows.dlllist --pid <PID>` |
| **handles**  | Shows open handles for each process, which can include files, registry keys, or other objects.                 | `windows.handles --pid <PID>` |
| **malfind**  | Detects potentially malicious code injections and executable memory regions, highlighting suspicious activity. | `windows.malfind --pid <PID>` |
| **cmdline**  | Extracts the command-line arguments for each process, useful for identifying suspicious process launches.      | `windows.cmdline --pid <PID>` |
| **netscan**  | Lists network connections and listening ports, providing insights to active or terminated network connections. | `windows.netscan` |
| **ssdt**     | Displays the System Service Descriptor Table (SSDT), helping identify system call hooking by rootkits.         | `windows.ssdt` |
| **filescan** | Scans for file objects in memory, useful for recovering files or identifying deleted/malicious files.          | `windows.filescan` |
| **registry** | Extracts registry hives from memory, allowing the recovery of critical system and user information.            | `windows.registry` |



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
Docs for [how to use Overpass QL](https://wiki.openstreetmap.org/wiki/Overpass_API/Overpass_QL). Here is a list of different keys to use when querying:
Database for [key value pairs](https://taginfo.openstreetmap.org/search#keys)

Simple usage:

```c
area["name:en"="Norway"];
node(area)[highway=bus_stop];
node(around:100)[amenity=cinema];
out;
```

Useful keys and links to where to find more:

| **Key** | **Way** | **Node** |
|---------|----------|-----------|
| [highway](https://wiki.openstreetmap.org/wiki/Key:highway)     | motorway, road, footway, cycleway, pedestrian, service, track | bus_stop |
| [amenity](https://wiki.openstreetmap.org/wiki/Key:amenity)     | hospital, restaurant, library, school, pharmacy, place_of_worship, cafe, kindergarten, police | fountain, bench, toilet, bank, charging_station, fuel |
| [leisure](https://wiki.openstreetmap.org/wiki/Key:leisure)     | park, garden, playground, swimming_pool, pitch, stadium, golf_course | — |
| [shop](https://wiki.openstreetmap.org/wiki/Key:shop)           | — | bakery, supermarket, clothes, electronics, furniture, hairdresser, bookstore, pet, jeweller, music |
| [railway](https://wiki.openstreetmap.org/wiki/Key:railway)     | rail, subway, tram, tunnel | platform, halt, crossing, station |
| [building](https://wiki.openstreetmap.org/wiki/Key:building)   | house, apartment, barn, church, school, hospital, office, warehouse, museum, hotel, post_office, cinema, theatre | — |
| [aeroway](https://wiki.openstreetmap.org/wiki/Key:aeroway)     | runway | helipad |
| [power](https://wiki.openstreetmap.org/wiki/Key:power)         | line, generator | substation, tower |
| [man_made](https://wiki.openstreetmap.org/wiki/Key:man_made)   | pier, bridge, tower | - |
| [military](https://wiki.openstreetmap.org/wiki/Key:military)   | camp, base | bunker, checkpoint |
| [water](https://wiki.openstreetmap.org/wiki/Key:water)         | reservoir, tank | well, spring |

Here are some useful settings elements:

| **Element**                        | **Description**                                                                   |
|------------------------------------|-----------------------------------------------------------------------------------|
| `[out:json];`                      | Specifies the result format as JSON (alternatives: `out:xml`, `out:csv`).         |
| `timeout`                          | Sets the query timeout in seconds (e.g., `[timeout:30];` for 30 seconds).         |
| `{{bbox}}`                         | Represents the current bounding box, limiting the query to the visible area.      |
| `(.result;.result >;) -> .result;` | Expands results to include related elements, like showing ways as nodes.          |
| `,i`                               | Makes tag matching case-insensitive.                                              |
| `~`                                | Matches a tag value containing a specified pattern.                               |
| Settings for Output                | Controls how much data is returned, e.g., `out body`, `out skel`, or `out count`. |


#### Advanced examples

```c
area["name"="Oslo"]->.a;
node(area.a)[shop=electronics][brand~"power", i]->.result;
```

```c
// Area
area[name="Oslo"]->.a;

// Secondary Schools
way(area.a)[amenity=school][grades~"8-10|1-10"]->.schools;

// Count schools
.schools out count;

// Display schools
(.schools;.schools >;) -> .display;
.display out;
```

```c
[out:json]; 

// Area
(
	area["name"="Oslo"];
	area["name"="Bærum"];
)->.a;

// Bus stops
node(area.a)[highway=bus_stop]->.bus_stops;

// Elkjøp (not phonehouse) close to bus stops
(
    node(around.bus_stops: 1000)[shop][name~"elkjøp", i];
  - node(area.a)[shop][name~"phone", i];
)->.result;

.result out;
```



## Penetration testing

### Nmap

Nmap is a free network scanning tool used to discover hosts and services on a network by analyzing responses to various packets and requests.

Installation:
```bash
sudo apt-get install nmap
```

Usage:
```bash
nmap [<Scan Type>] [<Options>] <target specification>
```

[Cheat Sheet](https://www.geeksforgeeks.org/nmap-cheat-sheet/)



## Web

### PayloadsAllTheThings

[PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) is a big collection of payloads for injections like XSS, SQLi and template injections.


### tshark

#### Installation:

```bash
apt install tshark
```

#### Usage:

```bash
tshark -f "port 31337" -w capture.pcap
```

Follow tcp stream:

```bash
tshark -r capture.pcap -qz follow,tcp,ascii,0
```

You can use filters in the commandline just like in the app using the `-Y`:

```bash
tshark -r capture.pcap -Y 'frame contains "flag"' -V
```


### Webhook

[Webhook.site](https://webhook.site/) is a tool for receiving HTTP requests. It provides a unique URL to capture and inspect incoming requests, including headers, payloads, and metadata.


1. Generate a unique URL at [Webhook.site](https://webhook.site/).
1. Send a request using your tool or application:
   ```bash
   curl -X POST -d "param=value" https://webhook.site/<unique_id>
   ```


### Gobuster

Gobuster is a tool for directory and file brute-forcing on web servers. It can discover hidden resources on a web server by guessing directories, files, or DNS subdomains.

It is often used together with [CeWLeR](#cewler)

```bash
docker run --rm -v "$PWD":/mnt ghcr.io/oj/gobuster:latest dir -u www.example.com -w /mnt/common.txt
```

A common wordlist to use with Gobuster is [common.txt](Scripts/common.txt). To use it with the example above, download the file and run the command in the same dir.

| `Short Name` | `Description` | `Example Command` |
|---|---|---|
| `dir`     | Brute-forces directories and files on a web server using a wordlist to discover hidden resources like `/admin`, `/backup`, etc. | `dir -u www.example.com -w /mnt/<wordlist>` |
| `fuzz`     | Brute-forces custom fuzzing points in URLs using a wordlist to discover hidden parameters or endpoints. | `fuzz -u www.example.com/FUZZ -w /mnt/<wordlist>` |
| `dns`     | Brute-forces subdomains of a given domain using a wordlist to find hidden or undocumented subdomains (e.g., `test.example.com`). | `dns -d example.com -w /mnt/<subdomain_wordlist>` |
| `vhost`   | Brute-forces virtual hosts (vhosts) to discover different websites hosted on the same server by using different hostnames. | `vhost -u www.example.com -w /mnt/<vhost_wordlist>` |
| `s3`      | Scans for publicly accessible AWS S3 buckets by brute-forcing bucket names. | `s3 -b -w /mnt/<bucket_wordlist>` |
