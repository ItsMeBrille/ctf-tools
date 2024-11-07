# CTF Tools

## Table of Contents

### Crypto

#### RsaCtfTool

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

For more about usage see [README.md](Repos/RsaCtfTool/README.md#usage).


### Forensics

#### Volatility

Volatility is the world's most widely used framework for extracting digital artifacts from volatile memory (RAM) samples. The extraction techniques are performed completely independent of the system being investigated but offer visibility into the runtime state of the system. The framework is intended to introduce people to the techniques and complexities associated with extracting digital artifacts from volatile memory samples and provide a platform for further work into this exciting area of research.

Links: [Volatility](https://github.com/volatilityfoundation/volatility) / [Volatility 3](https://github.com/volatilityfoundation/volatility3)

How to use Voloatility 3:

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



### Reversing



### PWN



### OSINT



### Miscellaneous



