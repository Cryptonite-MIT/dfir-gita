# Memory Forensics with Volatility 3: A Deep Dive into MemLabs Lab 6

## Introduction

Memory forensics has become an indispensable skill in modern digital investigations. Whether you're hunting advanced persistent threats, analyzing malware behavior, or solving CTF challenges, the ability to extract actionable intelligence from volatile memory can make the difference between cracking a case and hitting a dead end.

In this comprehensive guide, we'll explore the fascinating world of memory analysis using Volatility 3, the industry-standard framework for memory forensics. We'll walk through both the theoretical foundations and practical applications by solving MemLabs Lab 6 - "The Reckoning," a challenging CTF scenario.

---


## **Part 1: Understanding Memory Dumps**

### **What Are Memory Dumps?**

A **memory dump** (also called a **memory image** or **RAM dump**) is a snapshot of a computer’s **physical memory (RAM)** at a specific point in time.
Think of it as a **freeze-frame of everything happening inside the system** : running processes, network connections, decrypted data, encryption keys, passwords, cached credentials, and even deleted files that haven’t yet been overwritten.

When captured, it preserves the entire **volatile state** of the system, allowing forensic analysts to reconstruct system activity, detect malware, and extract live artifacts that never touch the disk.

---

### **Why Memory Dumps Matter**

Unlike disk forensics, which deals with long-term storage (files and partitions), **memory forensics** operates on the system’s *ephemeral* data (information that disappears once the system powers off.)

Key reasons why memory dumps are crucial:

* **Live Execution State:** Reveals every process, thread, handle, and loaded DLL at the exact moment of capture.
* **Decrypted Data:** Files or communications encrypted on disk are often *decrypted in memory* for active use.
* **Network Activity:** Shows open sockets, TCP/UDP connections, and in-memory packet buffers that may never reach logs.
* **Malware Artifacts:** Detects fileless malware, injected code, and kernel hooks invisible to disk-based scanners.
* **User Activity:** Uncovers commands, chat sessions, clipboard content, browser sessions, and open documents.

In short, memory forensics exposes what the system was *doing*, not just what was *stored*.

---

### **Types of Memory Dumps**

Depending on the acquisition method or the OS configuration, different dump types exist:

1. **Full Memory Dump:**
   Captures *all* physical RAM — every page of system and user-space memory.

   * Size = Physical RAM (e.g., 16 GB RAM → ~16 GB dump file).
   * Most complete form for forensic analysis.

2. **Kernel Memory Dump:**
   Contains only **kernel-mode** memory (system processes, drivers, kernel objects).

   * Excludes user-space data like running applications.
   * Smaller size, often a few hundred MBs to a few GBs.

3. **Minidump:**
   A **truncated dump** used mainly for debugging.

   * Includes registers, stack traces, and small kernel sections.
   * Not suitable for deep forensic reconstruction.

---

### **Acquiring Memory Dumps**

Common tools for memory capture include:

* **FTK Imager:** GUI-based forensic tool capable of capturing live RAM.
* **DumpIt:** Lightweight, single-executable command-line tool for Windows.
* **WinPmem:** Part of the Rekall suite; supports Windows acquisition with driver-level access.
* **LiME (Linux Memory Extractor):** Kernel module for acquiring Linux memory images.

Each tool must be run with administrative privileges, and ideally from trusted, write-protected media to prevent contamination.

---

## Inside a Memory Dump — Structure, Storage, and Representation**

### **How a Memory Dump Looks to the Computer**

To the **operating system**, physical memory is a **contiguous address space** filled with bytes — every instruction, variable, network packet, and pixel lives somewhere inside it.
When a dump is created, the acquisition tool reads memory *sequentially or page-by-page* through kernel APIs or direct physical address mapping and writes those bytes to disk.

From the system’s point of view:

* It’s just **a linear range of memory addresses**: `0x00000000 → 0xFFFFFFFF` (32-bit) or `0x0000000000000000 → 0xFFFFFFFFFFFFFFFF` (64-bit).
* Each **page (usually 4 KB)** of RAM is dumped in physical order or virtual order, depending on the tool.
* The dump file contains **no filesystem metadata** (no filenames, no folders) — just binary data representing memory cells.

Essentially, it’s like photographing every byte of RAM exactly as it existed at capture time.

---

### **How It Appears to Us (Analyst’s View)**

When opened in a hex editor (like **HxD**, **WinHex**, or **010 Editor**), a memory dump appears as **raw hexadecimal bytes** — no formatting, no human readability.
You’ll see sequences like:

```
00000000  4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF 00 00  MZ..............
00000010  B8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00  ........@.......
...
```

Here, `4D 5A` corresponds to the ASCII signature **“MZ”**, which indicates the start of a **Windows executable file** (`.exe`) found in memory.
Throughout the dump, you can find fragments of:

* PE headers (`MZ`, `PE\0\0`)
* Text fragments (from chat messages or logs)
* HTML or JSON (from browser memory)
* Network data
* Kernel objects
* Page tables and thread stacks

For analysts, specialized tools like **Volatility** or **Rekall** interpret these bytes according to known Windows or Linux kernel structures, reconstructing **process lists**, **network tables**, and **memory maps** from the raw binary data.

---

### **Where Memory Dumps Are Stored**

By default, memory dumps are stored as **flat binary files** on disk.
Typical storage conventions:

* **Windows crash dumps:**

  * `C:\Windows\MEMORY.DMP` → full or kernel dump (generated on BSOD).
  * `%SystemRoot%\Minidump\*.dmp` → minidumps.
* **Manual forensic dumps:**

  * Saved to an analyst-specified path, e.g., `E:\evidence\case001\memdump.raw`.

File extensions vary:

* `.raw` — pure binary dump (common in forensics)
* `.dmp` — structured Windows crash dump
* `.vmem` — VMware memory snapshot
* `.lime` — Linux memory dump format

The **file size** is typically equal to the physical RAM size or smaller if compression or selective capture is applied.

---

### **Compression and Storage Optimization**

Memory dumps can be very large — for example, a system with 32 GB of RAM yields a 32 GB `.raw` file. To handle this:

* Some acquisition tools (like **LiME** or **WinPmem**) support **on-the-fly compression**, writing `.raw.lime` or `.raw.gz` files.
* Compression is **lossless** — all bytes can be reconstructed exactly.
* However, tools like Volatility generally prefer **uncompressed dumps** for direct analysis. If a dump is compressed, it must be decompressed before parsing.

Internally, dumps may also include **page flags** or metadata (e.g., “page in use”, “page swapped”) — depending on the format, some tools store these as part of the dump header.

---

### **Internal Structure of a Memory Dump (Technical View)**

A typical physical memory dump contains:

| Section                          | Description                                                                                      |
| -------------------------------- | ------------------------------------------------------------------------------------------------ |
| **Header (Optional)**            | May store metadata like system time, OS type, or dump format (depends on tool).                  |
| **Physical Pages**               | 4 KB chunks representing physical RAM pages, sequentially written or mapped from virtual memory. |
| **Paged-Out Data (optional)**    | Some tools retrieve swapped pages from pagefile.sys to create a more complete memory image.      |
| **Footer / Metadata (optional)** | Contains integrity hashes or timestamps verifying dump authenticity.                             |

There is **no filesystem hierarchy** inside. Tools like Volatility reconstruct logical views (e.g., processes, DLLs, handles) by interpreting memory structures, not by reading directories.



---


 

## Part 2: Introduction to Volatility 3

### What is Volatility?

Volatility is an open-source memory forensics framework written in Python. It's the gold standard for memory analysis, used by incident responders, malware analysts, and digital forensics professionals worldwide.

### Volatility 2 vs Volatility 3: What Changed?

**Volatility 2 (Legacy)**:
- Profile-based system (required OS-specific profiles)
- Command syntax: `vol.py -f dump.raw --profile=Win7SP1x64 pslist`
- Separate plugins for different OS versions

**Volatility 3 (Modern)**:
- Symbol-based architecture (auto-detection)
- Simplified syntax: `vol3 -f dump.raw windows.pslist`
- Better performance and extensibility
- Unified plugin system

### Installation

```bash
# Install via pip
pip3 install volatility3

# Or clone from GitHub
git clone https://github.com/volatilityfoundation/volatility3.git
cd volatility3
python3 setup.py install

# Verify installation
vol3 --help
```

### Architecture Overview

Volatility 3's architecture consists of:
- **Framework Core**: Handles memory parsing and symbol resolution
- **Plugins**: Modular analysis components
- **Symbol Tables**: OS structure definitions (ISF format)
- **Renderers**: Output formatting (text, JSON, etc.)

---

## Part 3: Essential Volatility 3 Plugins

Let's dive deep into the plugins we'll use for our investigation. I'll explain not just how to use them, but how they work under the hood.

### **3.1 windows.info : OS Identification**

The `windows.info` plugin in Volatility is used to **identify the operating system details** of a captured Windows memory dump. It extracts and reports critical metadata such as:

* OS name and version (e.g., Windows 10, Windows Server 2016)
* Build number and Service Pack level
* System architecture (x86 or x64)
* Kernel base address and type
* System time and date when the dump was captured
* Major kernel symbols and offsets used for parsing

This information is essential because it determines **how Volatility interprets memory structures** and which profiles or symbol tables it must load to correctly analyze the dump.

Internally, `windows.info` performs a structured scan and validation process involving **Windows kernel data blocks** and **paging structures**.

1. **Locating the KDBG (Kernel Debugger Data Block):**

   * The **KDBG** is a global structure used by the Windows kernel debugger that contains references to vital kernel objects.
   * Volatility scans physical memory for patterns matching known KDBG signatures.
   * Once identified, it verifies the structure by cross-checking pointer consistency and magic values.
   * The KDBG provides:

     * **OS version and build numbers** (from `KdVersionBlock`)
     * **Kernel base address**
     * **Machine architecture** (x86 or x64)
     * **System time and time zone bias** (from `KeSystemTime` and `KeTimeZoneBias`)
     * **Memory layout offsets** and symbol table references

2. **Extracting the DTB (Directory Table Base):**

   * The **DTB**, also known as the **CR3 register**, holds the **physical address of the Page Directory** (for x86) or the **Page Map Level 4 (PML4)** (for x64).
   * It defines how virtual memory addresses are translated into physical ones.
   * Volatility reads the DTB value from the KDBG or the EPROCESS structure of the system process (`System`) to correctly resolve virtual-to-physical address mappings.
   * This allows all subsequent plugins to accurately traverse kernel memory structures.

3. **Symbol Table Matching:**

   * Once the KDBG and DTB are validated, Volatility automatically loads the appropriate PDB symbols (Volatility 3).
   * This ensures that every kernel offset and data type used in later analysis corresponds exactly to the structure definitions of the detected Windows version.

4. **Validation and Output:**

   * The plugin verifies consistency across multiple structures (KDBG, KPCR, EPROCESS).
   * If mismatches occur, it may attempt secondary heuristics or fallback scanning to confirm the correct OS version and kernel layout.

**Command**:
```bash
vol -f MemoryDump_Lab6.raw windows.info
```

**Output**:
```
Variable        Value

Kernel Base     0xf80002609000
DTB     0x187000
Symbols file:///C:/Users/dasad/AppData/Local/Programs/Python/Python312/Lib/site-packages/volatility3/symbols/windows/ntkrnlmp.pdb/3844DBB920174967BE7AA4A2C20430FA-2.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdDebuggerDataBlock     0xf800027fa0a0
NTBuildLab      7601.17514.amd64fre.win7sp1_rtm.
CSDVersion      1
KdVersionBlock  0xf800027fa068
Major/Minor     15.7601
MachineType     34404
KeNumberProcessors      1
SystemTime      2019-08-19 14:41:58+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  6
NtMinorVersion  1
PE MajorOperatingSystemVersion  6
PE MinorOperatingSystemVersion  1
PE Machine      34404
PE TimeDateStamp        Sat Nov 20 09:30:02 2010
```

This output tells us that the memory dump is from a **64-bit Windows 7 SP1 system (build 7601) with one processor, kernel loaded at `0xf80002609000`, using the `ntkrnlmp.pdb` symbols, and captured on 2019-08-19 14:41:58 UTC**.

---



### **3.2 windows.pslist — Process Listing**

The `windows.pslist` plugin in Volatility is used to **enumerate all processes that were active at the time of the memory dump**. It provides a snapshot of system activity by listing each process along with metadata such as PID, parent PID, thread count, handle count, session ID, architecture (Wow64), and creation/exit times. This is a foundational step for memory forensics, as it establishes the set of running processes from which further investigation (e.g., process memory analysis, handle enumeration, DLL listing) can be conducted.

How this works under the hood:

   * In Windows, every running process is represented by an **EPROCESS (Executive Process) structure** in kernel memory.
   * This structure contains key information about the process:

     * **Process ID (PID)** and **Parent PID (PPID)**
     * **Image file name** (limited to 15 characters)
     * **Virtual Address Descriptor (VAD) tree** — describes the memory layout of the process
     * **Thread list** — contains all active threads belonging to the process
     * **Handle table** — tracks open handles (files, registry keys, synchronization objects, etc.)
     * **Creation time** and **exit time**
     * Architecture information for Wow64 processes (32-bit process on 64-bit Windows)


   * All EPROCESS structures are connected via the **`ActiveProcessLinks` field**, forming a circular doubly-linked list maintained by the Windows kernel.
   * Volatility traverses this list starting from the **`System` process** (PID 4), following each `Flink` pointer to reach the next EPROCESS.
   * For each EPROCESS, Volatility reads the relevant offsets depending on the OS version (obtained via `windows.info`) to extract process metadata.


   * Before reading each EPROCESS, Volatility validates pointer addresses to ensure they are within valid kernel memory ranges.
   * This prevents crashes or false positives due to memory corruption or partially overwritten structures in the dump.


   * The plugin formats the extracted data into a table with the following key columns:

     * **PID / PPID** — shows process hierarchy
     * **ImageFileName** — process executable name
     * **Offset(V)** — virtual memory offset of the EPROCESS structure
     * **Threads** — number of threads
     * **Handles** — number of open handles
     * **SessionId** — session ID (useful in terminal server/multi-user environments)
     * **Wow64** — indicates if a 32-bit process runs on a 64-bit OS
     * **CreateTime / ExitTime** — process lifecycle timestamps
     * **File output** — indicates if file output logging is enabled




**Command**:
```bash
vol -f MemoryDump_Lab6.raw windows.pslist
```

**Output**:

```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime       File output

4       0       System  0xfa80012a5040  78      495     N/A     False   2019-08-19 14:40:07.000000 UTC  N/A     Disabled
264     4       smss.exe        0xfa8002971470  2       29      N/A     False   2019-08-19 14:40:07.000000 UTC  N/A    Disabled
336     328     csrss.exe       0xfa800234cb30  10      415     0       False   2019-08-19 14:40:10.000000 UTC  N/A    Disabled
384     328     wininit.exe     0xfa8002aae910  3       74      0       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
396     376     csrss.exe       0xfa8002ab7060  9       499     1       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
436     376     winlogon.exe    0xfa8002b66560  6       116     1       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
480     384     services.exe    0xfa8002b99200  9       194     0       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
496     384     lsass.exe       0xfa8002bb4600  7       513     0       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
504     384     lsm.exe 0xfa80022ff910  10      152     0       False   2019-08-19 14:40:11.000000 UTC  N/A     Disabled
608     480     svchost.exe     0xfa8002ce8740  10      358     0       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
668     480     VBoxService.ex  0xfa8002d13060  13      136     0       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
724     480     svchost.exe     0xfa8002d4bb30  6       257     0       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
780     480     svchost.exe     0xfa8002d4fb30  19      405     0       False   2019-08-19 14:40:11.000000 UTC  N/A    Disabled
896     480     svchost.exe     0xfa8002dcf5f0  22      452     0       False   2019-08-19 14:40:12.000000 UTC  N/A    Disabled
948     480     svchost.exe     0xfa8002de1b30  35      893     0       False   2019-08-19 14:40:12.000000 UTC  N/A    Disabled
1008    780     audiodg.exe     0xfa8002e0b1c0  7       132     0       False   2019-08-19 14:40:12.000000 UTC  N/A    Disabled
400     480     svchost.exe     0xfa8002e645f0  13      275     0       False   2019-08-19 14:40:12.000000 UTC  N/A    Disabled
1052    480     svchost.exe     0xfa8002eac740  17      368     0       False   2019-08-19 14:40:12.000000 UTC  N/A    Disabled
1176    480     spoolsv.exe     0xfa8002e76b30  14      279     0       False   2019-08-19 14:40:13.000000 UTC  N/A    Disabled
1212    480     svchost.exe     0xfa8002f4d780  21      311     0       False   2019-08-19 14:40:13.000000 UTC  N/A    Disabled
1308    480     svchost.exe     0xfa8002f79b30  17      253     0       False   2019-08-19 14:40:13.000000 UTC  N/A    Disabled
1812    480     taskhost.exe    0xfa8003144250  9       147     1       False   2019-08-19 14:40:18.000000 UTC  N/A    Disabled
1868    896     dwm.exe 0xfa8003160120  4       70      1       False   2019-08-19 14:40:18.000000 UTC  N/A     Disabled
1876    948     taskeng.exe     0xfa8003164b30  5       81      0       False   2019-08-19 14:40:18.000000 UTC  N/A    Disabled
1944    1844    explorer.exe    0xfa800319a060  35      894     1       False   2019-08-19 14:40:19.000000 UTC  N/A    Disabled
1292    1928    GoogleCrashHan  0xfa8003227060  7       105     0       True    2019-08-19 14:40:19.000000 UTC  N/A    Disabled
924     1928    GoogleCrashHan  0xfa8003219060  6       93      0       False   2019-08-19 14:40:19.000000 UTC  N/A    Disabled
1108    1944    VBoxTray.exe    0xfa8003277810  14      139     1       False   2019-08-19 14:40:20.000000 UTC  N/A    Disabled
880     1944    cmd.exe 0xfa8002324b30  1       21      1       False   2019-08-19 14:40:26.000000 UTC  N/A     Disabled
916     396     conhost.exe     0xfa800231e370  3       50      1       False   2019-08-19 14:40:26.000000 UTC  N/A    Disabled
856     480     SearchIndexer.  0xfa8003315060  13      689     0       False   2019-08-19 14:40:27.000000 UTC  N/A    Disabled
2124    1944    chrome.exe      0xfa800234eb30  27      662     1       False   2019-08-19 14:40:46.000000 UTC  N/A    Disabled
2132    2124    chrome.exe      0xfa800234f780  9       75      1       False   2019-08-19 14:40:46.000000 UTC  N/A    Disabled
2168    2124    chrome.exe      0xfa800314fab0  3       55      1       False   2019-08-19 14:40:49.000000 UTC  N/A    Disabled
2292    608     WmiPrvSE.exe    0xfa80032d9060  13      288     0       False   2019-08-19 14:40:52.000000 UTC  N/A    Disabled
2340    2124    chrome.exe      0xfa80032f9a70  12      282     1       False   2019-08-19 14:40:52.000000 UTC  N/A    Disabled
2440    2124    chrome.exe      0xfa8003741b30  13      263     1       False   2019-08-19 14:40:54.000000 UTC  N/A    Disabled
2452    2124    chrome.exe      0xfa800374bb30  14      167     1       False   2019-08-19 14:40:54.000000 UTC  N/A    Disabled
2800    480     WmiApSrv.exe    0xfa8002b74060  6       115     0       False   2019-08-19 14:40:57.000000 UTC  N/A    Disabled
2896    608     WmiPrvSE.exe    0xfa8002d9eab0  7       124     0       False   2019-08-19 14:40:57.000000 UTC  N/A    Disabled
2940    2124    chrome.exe      0xfa80032d4380  9       172     1       False   2019-08-19 14:41:06.000000 UTC  N/A    Disabled
2080    3060    firefox.exe     0xfa8003905b30  59      970     1       True    2019-08-19 14:41:08.000000 UTC  N/A    Disabled
2860    2080    firefox.exe     0xfa80021fa630  11      210     1       True    2019-08-19 14:41:09.000000 UTC  N/A    Disabled
3016    2080    firefox.exe     0xfa80013a4580  31      413     1       True    2019-08-19 14:41:10.000000 UTC  N/A    Disabled
2968    2080    firefox.exe     0xfa8001415b30  22      323     1       True    2019-08-19 14:41:11.000000 UTC  N/A    Disabled
3316    2080    firefox.exe     0xfa8001454b30  21      307     1       True    2019-08-19 14:41:13.000000 UTC  N/A    Disabled
3716    1944    WinRAR.exe      0xfa80035e71e0  7       201     1       False   2019-08-19 14:41:43.000000 UTC  N/A    Disabled
4084    1944    DumpIt.exe      0xfa800156e400  5       46      1       True    2019-08-19 14:41:55.000000 UTC  N/A    Disabled
4092    396     conhost.exe     0xfa80014c1060  2       50      1       False   2019-08-19 14:41:55.000000 UTC  N/A    Disabled
1224    480     sppsvc.exe      0xfa80014aa060  5       0       0       False   2019-08-19 14:42:39.000000 UTC  N/A    Disabled
2256    2396    GoogleUpdate.e  0xfa800157eb30  3       118     0       True    2019-08-19 14:42:40.000000 UTC  N/A    Disabled
1192    2256    GoogleCrashHan  0xfa80014f9060  3       46      0       True    2019-08-19 14:42:41.000000 UTC  N/A    Disabled
864     2256    GoogleCrashHan  0xfa80035e3700  1       1279459345      0       False   2019-08-19 14:42:41.000000 UTC N/A      Disabled
```

This gives us many insights into the system like



   * The `System` process (PID 4) is the root of the process tree.
   * Most processes like `smss.exe`, `csrss.exe`, `wininit.exe`, and `services.exe` are child processes of PID 4 or PID 480 (typically `services.exe`), reflecting standard Windows startup hierarchy.


   * Multiple instances of `svchost.exe` (service host) appear, each with a specific PID and thread count, reflecting different loaded Windows services.
   * Processes like `spoolsv.exe`, `taskhost.exe`, and `WmiPrvSE.exe` indicate background services for printing, task scheduling, and WMI providers, respectively.


   * Applications like `firefox.exe`, `chrome.exe`, `WinRAR.exe`, and `DumpIt.exe` appear with their respective parent PIDs, reflecting user-launched processes.
   * Multiple instances of browsers (`chrome.exe`, `firefox.exe`) indicate tabs or subprocesses created by multi-process architectures.


   * Columns like `Wow64=True` indicate 32-bit processes running on a 64-bit OS. For example, `GoogleCrashHan` appears with Wow64 enabled, confirming it’s a 32-bit process.


   * `CreateTime` allows analysts to establish the timeline of process execution.
   * `ExitTime` indicates whether a process had terminated before the memory dump; `N/A` implies the process was still running.


   * Suspicious or unexpected processes can be flagged for further investigation (e.g., unknown processes, unusual parent-child relationships, unusually high thread/handle counts).
   * PID and EPROCESS offsets allow cross-referencing with other plugins like `dlllist`, `handles`, `malfind`, or `cmdline`.


---

### **3.3 windows.pstree – Process Tree Analysis**

The `windows.pstree` plugin reconstructs the **hierarchical relationship of running and exited processes** at the time of memory capture. It visualizes **parent–child relationships**, allowing analysts to understand the **process lineage** and spot anomalies such as **process injection**, **unusual parentage**, or **malicious spawning chains**.

Unlike `windows.pslist` which enumerates individual processes, `windows.pstree` maps process relationships by:

1. **Traversing EPROCESS structures** from kernel memory to gather `PID`, `PPID`, and other metadata.
2. **Following the `ActiveProcessLinks` list** to identify all active processes and then resolving their **parent pointers** using:

   * `EPROCESS.InheritedFromUniqueProcessId` (the PPID)
   * `EPROCESS.UniqueProcessId` (the PID)
3. Building a **tree structure in memory** by linking each child to its parent using these identifiers.
4. Detecting **cross-session anomalies** (e.g., GUI vs. service session) using `EPROCESS.SessionId`.
5. Flagging **inconsistencies** where a parent process no longer exists (common in process hollowing or orphaned malware threads).
6. Optionally dereferencing the **Command Line arguments** and **image path** through the process environment block (PEB) and RTL_USER_PROCESS_PARAMETERS structures, if accessible.
7. Integrating data from the **thread list** to count threads per process and identify injected or remote-created threads.

This structured approach gives a **time-consistent view of process ancestry**—useful for correlating execution behavior during incident response.


#### **Command**

```bash
vol -f MemoryDump_Lab6.raw windows.pstree
```


#### **Output Snippet**

```
PID     PPID    ImageFileName   Offset(V)        Threads Handles SessionId Wow64  CreateTime                ExitTime        Path
--------------------------------------------------------------------------------------------------------------
4       0       System          0xfa80012a5040   78      495     N/A       False  2019-08-19 14:40:07 UTC   N/A             --
└── 264   4     smss.exe        0xfa8002971470   2       29      N/A       False  2019-08-19 14:40:07 UTC   N/A             C:\Windows\System32\smss.exe
    ├── 336  328 csrss.exe      0xfa800234cb30   10      415     0         False  2019-08-19 14:40:10 UTC   N/A             C:\Windows\System32\csrss.exe
    ├── 384  328 wininit.exe    0xfa8002aae910   3       74      0         False  2019-08-19 14:40:11 UTC   N/A             C:\Windows\System32\wininit.exe
    │   ├── 480   384 services.exe     0xfa8002b99200   9   194   0  False 2019-08-19 14:40:11 UTC N/A C:\Windows\System32\services.exe
    │   │   ├── 608   480 svchost.exe  0xfa8002ce8740  10  358   0  False 2019-08-19 14:40:11 UTC N/A C:\Windows\System32\svchost.exe
    │   │   │   ├── 2292  608 WmiPrvSE.exe 0xfa80032d9060 13 288 0 False 2019-08-19 14:40:52 UTC N/A C:\Windows\System32\wbem\WmiPrvSE.exe
    │   │   │   └── 2896  608 WmiPrvSE.exe 0xfa8002d9eab0 7 124 0 False 2019-08-19 14:40:57 UTC N/A C:\Windows\System32\wbem\WmiPrvSE.exe
    │   │   ├── 896   480 svchost.exe  0xfa8002dcf5f0  22 452   0  False 2019-08-19 14:40:12 UTC N/A C:\Windows\System32\svchost.exe
    │   │   │   └── 1868  896 dwm.exe   0xfa8003160120  4  70   1  False 2019-08-19 14:40:18 UTC N/A C:\Windows\System32\dwm.exe
    │   │   ├── 780   480 svchost.exe  0xfa8002d4fb30  19 405   0  False 2019-08-19 14:40:11 UTC N/A C:\Windows\System32\svchost.exe
    │   │   │   └── 1008  780 audiodg.exe 0xfa8002e0b1c0 7 132 0 False 2019-08-19 14:40:12 UTC N/A C:\Windows\System32\audiodg.exe
    │   │  
    │   ├── 496   384 lsass.exe   0xfa8002bb4600 7 513   0 False 2019-08-19 14:40:11 UTC N/A C:\Windows\System32\lsass.exe
    │   └── 504   384 lsm.exe     0xfa80022ff910 10 152   0 False 2019-08-19 14:40:11 UTC N/A C:\Windows\System32\lsm.exe
    ├── 436   376 winlogon.exe  0xfa8002b66560   6       116     1         False  2019-08-19 14:40:11 UTC   N/A             C:\Windows\System32\winlogon.exe
    │   └── 1944 1844 explorer.exe 0xfa800319a060 35 894 1 False 2019-08-19 14:40:19 UTC N/A C:\Windows\explorer.exe
    │       ├── 4084 1944 DumpIt.exe  0xfa800156e400 5 46 1 True  2019-08-19 14:41:55 UTC N/A C:\Users\Jaffa\Desktop\DumpIt.exe
    │       ├── 3716 1944 WinRAR.exe  0xfa80035e71e0 7 201 1 False 2019-08-19 14:41:43 UTC N/A C:\Program Files\WinRAR\WinRAR.exe
    │       ├── 2124 1944 chrome.exe  0xfa800234eb30 27 662 1 False 2019-08-19 14:40:46 UTC N/A C:\Program Files (x86)\Google\Chrome\Application\chrome.exe
    │       └── 880   1944 cmd.exe    0xfa8002324b30 1 21 1 False 2019-08-19 14:40:26 UTC N/A C:\Windows\System32\cmd.exe
--------------------------------------------------------------------------------------------------------------
```
This gives us valuable information like: 
* **System (PID 4)** is the root of the hierarchy; all other system processes ultimately descend from it.
* **smss.exe** → **wininit.exe** → **services.exe** chain confirms proper Windows startup sequence.
* Multiple **svchost.exe** instances host modular Windows services — normal but worth checking unusual parameters.
* **explorer.exe** is the shell process for the logged-in user.

  * **cmd.exe** and **DumpIt.exe** under explorer indicate manual user execution (DumpIt confirms memory capture activity).
  * **chrome.exe** and its children show browser sandboxing and multiprocess architecture.
* The presence of both **firefox.exe** and **chrome.exe** suggests multiple browsers active during dump capture.
* **VBoxService.exe** and **VBoxTray.exe** identify that the system was running inside a **VirtualBox environment**.


For a DFIR analyst this can help us to: 

* Quickly reconstructs **attack chains**, e.g., `explorer.exe → cmd.exe → powershell.exe → malware.exe`
* Detects **process hollowing** when parent process exists but child’s image/path mismatches.
* Identifies **orphaned or zombie processes** (no valid parent).
* Helps validate **system integrity** by comparing the expected Windows process hierarchy with the actual one.

---

## **3.4 windows.cmdline — Command Line Arguments**




The `windows.cmdline` plugin in Volatility is used to **extract the complete command-line strings used to launch each process** at the time the memory image was captured.
Unlike `pslist`, which only enumerates process names and IDs, `cmdline` provides **the exact command-line arguments** that were passed during process creation, including executable paths, flags, runtime parameters, configuration directives, or payload locations.

This plugin is especially useful in **malware investigations** and **intrusion analysis**, as it allows analysts to spot:

* Suspicious executables launched from non-standard directories,
* Legitimate processes launched with unusual parameters,
* Script interpreters (like `cmd.exe`, `powershell.exe`, or `wscript.exe`) with embedded or obfuscated commands,
* Self-extracting archives, dump utilities, or data exfiltration tools invoked manually.




The `windows.cmdline` plugin works by **navigating from kernel-level process structures (EPROCESS) to user-mode memory structures** that store environment and startup information.


   * Each active process is represented by an `EPROCESS` structure in kernel memory.
   * Volatility identifies these via the process list (ActiveProcessLinks) similarly to `pslist`.
   * The EPROCESS structure contains a pointer to the **Process Environment Block (PEB)**, located in the process’s user-mode address space.


   * The PEB holds process-wide data such as image base address, heap locations, loaded modules, and runtime flags.
   * It also stores a pointer to the **RTL_USER_PROCESS_PARAMETERS** structure, which contains environment variables, the current working directory, and command-line arguments.


   * The key field here is the **`CommandLine`**, a `UNICODE_STRING` structure (two 16-bit fields: `Length` and `Buffer`).
   * Volatility reads the contents of this buffer directly from the process’s address space, reconstructing the full Unicode command line string.


   * The extracted `CommandLine` is decoded from UTF-16 and displayed alongside the process ID (PID) and executable name.
   * If the command-line buffer is inaccessible (e.g., paged out or corrupted), the field is shown as a dash (“-”).

This hierarchical traversal — from **EPROCESS → PEB → RTL_USER_PROCESS_PARAMETERS → CommandLine**, is what allows Volatility to recover the **exact runtime invocation context** of every process in memory.


### **Command**

```bash
vol -f MemoryDump_Lab6.raw windows.cmdline
```

---

### **Output**



```bash
PID     Process          Args
4       System           -
264     smss.exe         \SystemRoot\System32\smss.exe
336     csrss.exe        %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
384     wininit.exe      wininit.exe
396     csrss.exe        %SystemRoot%\system32\csrss.exe ObjectDirectory=\Windows SharedSection=1024,20480,768 Windows=On SubSystemType=Windows ServerDll=basesrv,1 ServerDll=winsrv:UserServerDllInitialization,3 ServerDll=winsrv:ConServerDllInitialization,2 ServerDll=sxssrv,4 ProfileControl=Off MaxRequestThreads=16
436     winlogon.exe     winlogon.exe
480     services.exe     C:\Windows\system32\services.exe
496     lsass.exe        C:\Windows\system32\lsass.exe
504     lsm.exe          C:\Windows\system32\lsm.exe
608     svchost.exe      C:\Windows\system32\svchost.exe -k DcomLaunch
668     VBoxService.exe  C:\Windows\System32\VBoxService.exe
724     svchost.exe      C:\Windows\system32\svchost.exe -k RPCSS
780     svchost.exe      C:\Windows\System32\svchost.exe -k LocalServiceNetworkRestricted
896     svchost.exe      C:\Windows\System32\svchost.exe -k LocalSystemNetworkRestricted
948     svchost.exe      C:\Windows\system32\svchost.exe -k netsvcs
1008    audiodg.exe      C:\Windows\system32\AUDIODG.EXE 0x2ac
400     svchost.exe      C:\Windows\system32\svchost.exe -k LocalService
1052    svchost.exe      C:\Windows\system32\svchost.exe -k NetworkService
1176    spoolsv.exe      C:\Windows\System32\spoolsv.exe
1212    svchost.exe      C:\Windows\system32\svchost.exe -k LocalServiceNoNetwork
1308    svchost.exe      C:\Windows\system32\svchost.exe -k LocalServiceAndNoImpersonation
1812    taskhost.exe     "taskhost.exe"
1868    dwm.exe          "C:\Windows\system32\Dwm.exe"
1876    taskeng.exe      taskeng.exe {54DBC692-AE6C-4620-B58A-A05704950172}
1944    explorer.exe     C:\Windows\Explorer.EXE
1292    GoogleCrashHan   "C:\Program Files (x86)\Google\Update\1.3.34.11\GoogleCrashHandler.exe"
924     GoogleCrashHan   "C:\Program Files (x86)\Google\Update\1.3.34.11\GoogleCrashHandler64.exe"
1108    VBoxTray.exe     "C:\Windows\System32\VBoxTray.exe"
880     cmd.exe          "C:\Windows\system32\cmd.exe"
916     conhost.exe      \??\C:\Windows\system32\conhost.exe
856     SearchIndexer.exe C:\Windows\system32\SearchIndexer.exe /Embedding
2124    chrome.exe       "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe"
2132    chrome.exe       "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=crashpad-handler "--user-data-dir=C:\Users\Jaffa\AppData\Local\Google\Chrome\User Data" /prefetch:7 --monitor-self-annotation=ptype=crashpad-handler "--database=C:\Users\Jaffa\AppData\Local\Google\Chrome\User Data\Crashpad" "--metrics-dir=C:\Users\Jaffa\AppData\Local\Google\Chrome\User Data" --url=https://clients2.google.com/cr/report --annotation=channel= --annotation=plat=Win64 --annotation=prod=Chrome --annotation=ver=76.0.3809.100 --initial-client-data=0x38,0x3c,0x40,0x34,0x44,0x7fef693ef08,0x7fef693ef18,0x7fef693ef28
2168    chrome.exe       "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=watcher --main-thread-id=2128 --on-initialized-event-handle=12 --parent-handle=164 /prefetch:6
2292    WmiPrvSE.exe     C:\Windows\system32\wbem\wmiprvse.exe
2340    chrome.exe       "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=utility --field-trial-handle=912,6904440883533218926,14009848578096020689,131072 --lang=en-US --service-sandbox-type=network --service-request-channel-token=7087325372642059998 --mojo-platform-channel-handle=1404 /prefetch:8
2440    chrome.exe       "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=912,6904440883533218926,14009848578096020689,131072 --lang=en-US --instant-process --enable-auto-reload --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=30920957510107878 --renderer-client-id=6 --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=1956 /prefetch:1
2452    chrome.exe       "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=renderer --field-trial-handle=912,6904440883533218926,14009848578096020689,131072 --lang=en-US --enable-auto-reload --device-scale-factor=1 --num-raster-threads=1 --service-request-channel-token=8732891429699623721 --renderer-client-id=7 --no-v8-untrusted-code-mitigations --mojo-platform-channel-handle=2148 /prefetch:1
2800    WmiApSrv.exe     C:\Windows\system32\wbem\WmiApSrv.exe
2896    WmiPrvSE.exe     C:\Windows\system32\wbem\wmiprvse.exe
2940    chrome.exe       "C:\Program Files (x86)\Google\Chrome\Application\chrome.exe" --type=gpu-process --field-trial-handle=912,6904440883533218926,14009848578096020689,131072 --gpu-preferences=IAAAAAAAAADgAAAwAAAAAAAAYAAAAAAACAAAAAAAAAAoAAAABAAAACAAAAAAAAAAKAAAAAAAAAAwAAAAAAAAADgAAAAAAAAAEAAAAAAAAAAAAAAABQAAABAAAAAAAAAAAAAAAAYAAAAQAAAAAAAAAAEAAAAFAAAAEAAAAAAAAAABAAAABgAAAA== --use-gl=swiftshader-webgl --service-request-channel-token=8183290027954516201 --mojo-platform-channel-handle=2724 --ignored=" --type=renderer " /prefetch:2
2080    firefox.exe      "C:\Program Files (x86)\Mozilla Firefox\firefox.exe"
2860    firefox.exe      "C:\Program Files (x86)\Mozilla Firefox\firefox.exe" -contentproc --channel="2080.0.1430399655\1507561340" -parentBuildID 20190813150448 -greomni "C:\Program Files (x86)\Mozilla Firefox\omni.ja" -appomni "C:\Program Files (x86)\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files (x86)\Mozilla Firefox\browser" - 2080 "\\.\pipe\gecko-crash-server-pipe.2080" 1096 gpu
3016    firefox.exe      "C:\Program Files (x86)\Mozilla Firefox\firefox.exe" -contentproc --channel="2080.3.1961766982\1524136179" -childID 1 -isForBrowser -prefsHandle 1596 -prefMapHandle 1652 -prefsLen 1 -prefMapSize 190550 -parentBuildID 20190813150448 -greomni "C:\Program Files (x86)\Mozilla Firefox\omni.ja" -appomni "C:\Program Files (x86)\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files (x86)\Mozilla Firefox\browser" - 2080 "\\.\pipe\gecko-crash-server-pipe.2080" 764 tab
2968    firefox.exe      "C:\Program Files (x86)\Mozilla Firefox\firefox.exe" -contentproc --channel="2080.13.820371489\1898621292" -childID 2 -isForBrowser -prefsHandle 2684 -prefMapHandle 2688 -prefsLen 5982 -prefMapSize 190550 -parentBuildID 20190813150448 -greomni "C:\Program Files (x86)\Mozilla Firefox\omni.ja" -appomni "C:\Program Files (x86)\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files (x86)\Mozilla Firefox\browser" - 2080 "\\.\pipe\gecko-crash-server-pipe.2080" 2700 tab
3316    firefox.exe      "C:\Program Files (x86)\Mozilla Firefox\firefox.exe" -contentproc --channel="2080.20.122820616\259359170" -childID 3 -isForBrowser -prefsHandle 3252 -prefMapHandle 3728 -prefsLen 6704 -prefMapSize 190550 -parentBuildID 20190813150448 -greomni "C:\Program Files (x86)\Mozilla Firefox\omni.ja" -appomni "C:\Program Files (x86)\Mozilla Firefox\browser\omni.ja" -appdir "C:\Program Files (x86)\Mozilla Firefox\browser" - 2080 "\\.\pipe\gecko-crash-server-pipe.2080" 3740 tab
3716    WinRAR.exe       "C:\Program Files\WinRAR\WinRAR.exe" "C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"
4084    DumpIt.exe       "C:\Users\Jaffa\Desktop\DumpIt.exe"
4092    conhost.exe      \??\C:\Windows\system32\conhost.exe
1224    sppsvc.exe       -
2256    GoogleUpdate.e   -
1192    GoogleCrashHan   -
864     GoogleCrashHan   -
```

---

The output gives us many insights like: 

   * Processes like `smss.exe`, `csrss.exe`, `wininit.exe`, and `winlogon.exe` show typical Windows startup command-lines referencing system paths (`%SystemRoot%`, `C:\Windows\System32`).
   * Their parameters (`SharedSection`, `SubSystemType`, etc.) indicate normal subsystem and window server initialization behavior.


   * Multiple service hosts run with different `-k` arguments, each representing a **service group**:

     * `-k DcomLaunch`, `-k RPCSS`, `-k netsvcs`, `-k LocalServiceNoNetwork`, etc.
   * This modular design is typical of Windows service management, so no anomaly here.


   * `VBoxService.exe` and `VBoxTray.exe` indicate the system is running inside a **VirtualBox VM** — confirming a controlled or sandboxed environment for analysis.


   * `explorer.exe` (PID 1944) is the desktop shell, showing standard command line (`C:\Windows\Explorer.EXE`).
   * `cmd.exe` and `conhost.exe` suggest command prompt usage — possibly related to user or administrative interaction.


   * Numerous instances of `chrome.exe` and `firefox.exe` exist, each with unique `--type` arguments:

     * `--type=renderer`, `--type=gpu-process`, `--type=utility`, etc.
     * This is **normal for multiprocess browsers**, where each tab, renderer, and GPU thread runs separately.
   * The presence of parameters like `--no-v8-untrusted-code-mitigations` or `--swiftshader-webgl` can be flagged for further inspection, as these sometimes appear in browser exploit or debugging sessions.


   * `WinRAR.exe` invoked with argument `"C:\Users\Jaffa\Desktop\pr0t3ct3d\flag.rar"` shows manual archive access — potentially related to retrieving evidence or CTF-related content.
   * `DumpIt.exe` (PID 4084) indicates the tool used to **create the memory dump itself**, confirming this image was captured intentionally for forensic analysis.


   * Several `GoogleCrashHandler.exe` and `GoogleUpdate.exe` processes exist — legitimate background utilities for Chrome and Google Updater, though their frequent spawning can sometimes mimic persistence mechanisms.


---



## 3.5 windows.filescan — File Object Scan


The `windows.filescan` plugin scans kernel memory for active `_FILE_OBJECT` structures. It is used to enumerate:

* Files that were open at the time of memory acquisition
* Temporary files, browser cache files, or data exfiltration files in use
* Evidence of processes accessing specific files or suspicious artifacts

Unlike `cmdline` or `pslist`, `filescan` does not rely on file system metadata on disk. It retrieves files directly from memory-resident structures, which is particularly useful for:

* Detecting deleted files that remain mapped in memory
* Revealing file usage by malware or forensic artifacts
* Cross-referencing file access with process activity for timeline reconstruction

`filescan` works by  Searching kernel memory for `_FILE_OBJECT` signatures
   `_FILE_OBJECT` structures exist in the Windows kernel to represent each open file handle. The structures are linked to processes via handle tables in the `EPROCESS` structure.

   Key fields include:

   * `FileName` (UNICODE_STRING) — full path of the open file
   * `DeviceObject` and `Vpb` — storage device and volume references
   * `Flags` — attributes describing file access (read/write/shared, etc.)
     The plugin reads these structures directly from physical memory.

   Each `_FILE_OBJECT` instance is output with its physical memory offset and file path. Deleted or temporary files may appear if their structures are still in memory, even if they are not on disk.


### Command

```bash
vol -f MemoryDump_Lab6.raw windows.filescan
```


### Output (Truncated for Brevity)

```bash
Offset         Name
0x53f2690      \Endpoint
0x53f2800      \chrome.2968.1.28264847
0x53f3770      \Users\Jaffa\AppData\Local\Mozilla\Firefox\Profiles\84kisw0a.default-release\cache2\entries\F3A2A55211EE66D36F43F15EFF501E9546680661
0x53f4430      \Users\Jaffa\AppData\Local\Mozilla\Firefox\Profiles\84kisw0a.default-release\cache2\entries\3168C61F89D068684E314E0668C083341C5929A8
0x53f47e0      \Users\Jaffa\AppData\Local\Mozilla\Firefox\Profiles\84kisw0a.default-release\cache2\entries\32027373AB514902694BD2F13A8E08513EAF1DF9
0x53f5180      \chrome.2968.2.15970394
0x53f59e0      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\webappsstore.sqlite-wal
0x53f5d00      \chrome.2968.1.28264847
0x53f5f20      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\favicons.sqlite
0x53f65f0      \Endpoint
0x53f6f20      \chrome.2968.0.66569659
0x53f7070      \Windows\SysWOW64\actxprxy.dll
0x53f7760      \Endpoint
0x53f7cb0      \Users\Jaffa\AppData\Local\Mozilla\Firefox\Profiles\84kisw0a.default-release\cache2\entries\3695979DC4CDB6256489DC66C1152B1985B55252
0x53f7f20      \chrome.3016.3.194647336
0x53f8070      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\storage\permanent\chrome\idb\1657114595AmcateirvtiSty.sqlite
0x53f89e0      \$Directory
0x53f8d10      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\webappsstore.sqlite
0x53f9070      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\storage\default\https+++mail.google.com\cache\morgue\75\{f4ec0805-5e72-4cbe-a262-5a99a7abb04b}.tmp
0x53f94a0      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\webappsstore.sqlite-shm
0x53f9680      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\favicons.sqlite-wal
0x53f9890      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\webappsstore.sqlite-wal
0x53f9c80      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\favicons.sqlite-wal
0x53fa630      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\storage\permanent\chrome\idb\3561288849sdhlie.sqlite
0x53fac80      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\favicons.sqlite-shm
0x53faf20      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\content-prefs.sqlite
0x53fb2d0      \Windows\System32\samlib.dll
0x53fcbd0      \Windows\System32\dui70.dll
0x53fd070      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\places.sqlite
0x53fdb30      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\places.sqlite-wal
0x53fde20      \Users\Jaffa\AppData\Roaming\Mozilla\Firefox\Profiles\84kisw0a.default-release\storage\default\https+++mail.google.com\cache\morgue\63\{401978b9-d8ee-4339-8725-fcdb3224fd3f}.final
0x53fe830      \Users\Jaffa\AppData\Local\Microsoft\Windows\Explorer\thumbcache_256.db
```


This gives us insights like: 

*   Many files belong to Firefox cache and storage, including `cache2/entries/…`, `webappsstore.sqlite`, `favicons.sqlite`, `places.sqlite`, and `storage/permanent/chrome/idb/*.sqlite`. These indicate active web browsing and local caching at the time of memory capture.

 *  `chrome.2968.1.28264847`, `chrome.2968.2.15970394`, and `chrome.3016.3.194647336` suggest temporary or mapped Chrome processes. The numeric suffixes correspond to PID and internal identifiers.

  * `\Endpoint` entries likely belong to security software or system service file handles. `\Windows\System32\samlib.dll` and `\dui70.dll` are standard system DLLs loaded in memory.

   * Firefox cached emails such as `https+++mail.google.com\cache\morgue\…{GUID}.tmp` and `…final` files can be recovered for forensic analysis to inspect recently accessed emails or attachments.

   * `thumbcache_256.db` indicates Explorer thumbnail caching, which can reveal recently viewed image files.


---

## 3.6 windows.dumpfiles — File Extraction from Memory


The `windows.dumpfiles` plugin is used to extract or recover files directly from memory. It leverages the `_FILE_OBJECT` structures identified by `windows.filescan` to access the actual file contents stored in RAM. This is particularly useful in forensic investigations to:

* Recover files that were open at the time of the memory capture
* Extract temporary files, browser cache, or document fragments
* Retrieve files that have been deleted from disk but still reside in memory
* Collect evidence of malware storing payloads in memory rather than on disk


Internally:

   * The plugin uses memory-resident `_FILE_OBJECT` structures found by `filescan`. These structures contain metadata about the file, including the full path, size, and device/volume mapping.

   * For each `_FILE_OBJECT`, `dumpfiles` locates the memory pages that contain the file data. Depending on how the file is mapped by the system, this includes:

      * Cached file data in RAM
      * Directly mapped executable or DLL pages
       * Temporary storage created by applications like browsers or Office programs

   The plugin extracts the memory regions and saves them as a file in a user-specified output directory. The original filename can be preserved or generated automatically based on the memory offset.


This plugin can recover: 
* Files currently in use by processes at the time of the dump
* Deleted files that remain cached in memory
* Temporary or partially written files (e.g., browser cache, email attachments)
* Embedded payloads or malware that avoid disk storage

Howeever we must note that:

* Only files that have memory-resident representations can be recovered. Fully deleted files that have been unmapped from memory cannot be dumped.
* Some file contents may be partially cached. For example, only fragments of a large file may reside in RAM.
* Encrypted or compressed in-memory data require additional processing to reconstruct.
* System permissions and kernel protections may prevent access to certain memory regions.



### Commmand

A typical `dumpfiles` command looks like:

```bash
vol -f MemoryDump_Lab6.raw --dump-dir ./dumpfiles windows.dumpfiles
```

This will extract all files that `filescan` identified, saving them to the `./dumpfiles` folder. Individual files can also be targeted using the `--offset` parameter to specify a particular `_FILE_OBJECT` structure.


`dumpfiles` is particularly powerful when combined with `filescan` and `handles`, as it allows forensic investigators to map files back to the processes that accessed them, reconstruct timelines, and recover evidence that no longer exists on disk.





---

## 3.7 windows.envars — Environment Variables Extraction


The `windows.envars` plugin extracts environment variables for each process from a memory dump, providing insight into the runtime configuration of applications and the system. This includes standard system paths, temporary directories, user profiles, and potentially sensitive information such as passwords, tokens, or API keys that may be stored in environment variables.

Internally, Volatility performs the following steps:

1. **Process Identification**
   For each running process in memory, the plugin locates the `_EPROCESS` structure, which represents the process in kernel space.

2. **Accessing the PEB**
   From `_EPROCESS`, it navigates to the Process Environment Block (PEB) in user-space memory. The PEB contains a pointer to the `RTL_USER_PROCESS_PARAMETERS` structure.

3. **Reading Environment Variables**
   Inside `RTL_USER_PROCESS_PARAMETERS`, Volatility accesses the `Environment` pointer, which references a contiguous block of UNICODE_STRING entries. Each entry corresponds to a `KEY=VALUE` environment variable.

4. **Decoding and Filtering**
   The plugin reads memory from the environment block and decodes the UNICODE strings into readable format. It preserves both standard system variables (e.g., `SystemRoot`, `TEMP`, `PATH`) and process-specific variables set by applications or the user. Variables with sensitive content (like `RAR password`) are also captured if present in memory.

5. **Output Mapping**
   Each variable is associated with the process name, PID, and the memory offset where the environment block was found. This allows for correlation with other artifacts like handles, loaded modules, or command-line arguments.

We can use envars to extract:

  * System-level variables (`PATH`, `TEMP`, `SystemRoot`)
  * User-level variables (`USERNAME`, `USERPROFILE`, `USERDOMAIN`)
  * Application-specific variables, including passwords or tokens temporarily stored in memory
  * Process runtime configuration and module paths (`ProgramFiles`, `PSModulePath`)


This makes `windows.envars` particularly useful for forensic investigations where environment-specific settings might reveal malware configuration, process context, or hidden credentials.


### Command

```bash
vol -f MemoryDump_Lab6.raw windows.envars
```



### Output (Truncated for brevity)

```
PID     Process          Offset      Variable Name           Value

4084    DumpIt.exe       0x4e1dc0    ProgramFiles(x86)       C:\Program Files (x86)
4084    DumpIt.exe       0x4e1dc0    ProgramW6432            C:\Program Files
4084    DumpIt.exe       0x4e1dc0    PSModulePath            C:\Windows\system32\WindowsPowerShell\v1.0\Modules\
4084    DumpIt.exe       0x4e1dc0    RAR password            easypeasyvirus
4084    DumpIt.exe       0x4e1dc0    TEMP                    C:\Users\Jaffa\AppData\Local\Temp
4084    DumpIt.exe       0x4e1dc0    USERNAME                Jaffa
4084    DumpIt.exe       0x4e1dc0    USERPROFILE             C:\Users\Jaffa
4092    conhost.exe      0x2d1900    OS                      Windows_NT
4092    conhost.exe      0x2d1900    Path                    C:\Windows\system32;C:\Windows;C:\Windows\System32\Wbem;C:\Windows\System32\WindowsPowerShell\v1.0\
4092    conhost.exe      0x2d1900    PROCESSOR_ARCHITECTURE  AMD64
4092    conhost.exe      0x2d1900    PROCESSOR_IDENTIFIER    Intel64 Family 6 Model 158 Stepping 10, GenuineIntel
```



From this extraction, we can see that:

* **System and User Context**: Key system directories (`SystemRoot`, `ProgramFiles`, `TEMP`) and user context variables (`USERNAME`, `USERPROFILE`) are exposed in process memory.
* **Application Secrets in Memory**: A RAR password (`easypeasyvirus`) was present in the environment variables of DumpIt.exe, demonstrating how volatile memory can leak sensitive data.
* **Process-Specific Runtime Configuration**: Variables like `PSModulePath`, `Path`, and processor info reveal the runtime environment and architecture of processes, which is crucial for forensic reconstruction or malware analysis.
* **Correlation Potential**: These variables can be cross-referenced with command-line arguments, loaded modules, or file paths to understand exactly how a process was configured and executed at the time of the memory capture.


---

## 3.8 windows.netscan — Network Connections Extraction


The `windows.netscan` plugin in Volatility extracts live and historical TCP/UDP network connections from a memory dump, providing a snapshot of the network activity of processes at the time of capture. This is crucial for forensic investigations as it can reveal ongoing connections, listening services, and potential command-and-control communications from malware.

Under the hood, `netscan` parses the kernel’s **TCP/IP protocol control blocks (PCBs)** for IPv4 and IPv6. Specifically, it enumerates structures like `TCB` (TCP Control Block) and `UDP_ENDPOINT` linked to the `EPROCESS` structures of running processes. The plugin reads connection states (`ESTABLISHED`, `LISTENING`, `CLOSED`), local and foreign addresses/ports, and associates them with owning PIDs by correlating kernel objects to process structures. UDP endpoints are also scanned, even if no active session exists, since UDP is connectionless. For each connection, `netscan` checks the creation timestamp (if available), protocol type, and links back to the owning executable.

The plugin is capable of uncovering both legitimate and potentially malicious network activity, including:

* **TCP connections**: Both inbound and outbound, with full state information.
* **UDP endpoints**: Including ephemeral ports used for service discovery or inter-process communication.
* **Listening sockets**: Which processes are waiting for connections, including system services.
* **IPv4 and IPv6 support**: Allowing full coverage of network stacks.
* **Process mapping**: Identifying which executable is responsible for each network endpoint.

Because this information is extracted directly from memory, it can include connections that were open but never logged to the system’s netstat or firewall logs, as well as hidden or injected network activity used by malware.


### Command

```bash
vol -f MemoryDump_Lab6.raw windows.netscan
```


### Output 

```
Offset       Proto    LocalAddr       LocalPort    ForeignAddr          ForeignPort    State          PID    Owner            Created
0x53f2010    TCPv4    127.0.0.1       49171       127.0.0.1            49170          ESTABLISHED    2968   firefox.exe       N/A
0x53f2a90    TCPv4    127.0.0.1       49170       127.0.0.1            49171          ESTABLISHED    2968   firefox.exe       N/A
0x5d80d9f0   UDPv4    127.0.0.1       58500       *                    0              1308           svchost.exe       2019-08-19 14:42:39.000000 UTC
0x5d8c3360   UDPv4    0.0.0.0         5353        *                    0              2124           chrome.exe        2019-08-19 14:40:55.000000 UTC
0x5d8c3360   UDPv6    ::              5353        *                    0              2124           chrome.exe        2019-08-19 14:40:55.000000 UTC
0x5d8c3ec0   UDPv4    0.0.0.0         5353        *                    0              2124           chrome.exe        2019-08-19 14:40:55.000000 UTC
0x5d8d8500   TCPv4    10.0.2.15       49232       172.217.160.131      80             ESTABLISHED    2080   firefox.exe       N/A
0x5d8e7b90   TCPv4    127.0.0.1       49166       127.0.0.1            49165          ESTABLISHED    2080   firefox.exe       N/A
0x5d8e9010   TCPv4    10.0.2.15       49235       172.217.194.189      443            ESTABLISHED    2080   firefox.exe       N/A
0x5d9705f0   TCPv4    10.0.2.15       49196       172.217.160.133      443            ESTABLISHED    2080   firefox.exe       N/A
0x5dadd860   TCPv4    10.0.2.15       49198       216.58.197.67        443            ESTABLISHED    2080   firefox.exe       N/A
0x5daeb850   TCPv4    127.0.0.1       49165       127.0.0.1            49166          ESTABLISHED    2080   firefox.exe       N/A
0x5dafccf0   TCPv4    10.0.2.15       49224       172.217.163.205      443            ESTABLISHED    2080   firefox.exe       N/A
0x5dde8680   TCPv4    10.0.2.15       49234       172.217.163.106      443            ESTABLISHED    2080   firefox.exe       N/A
0x5ddf9010   TCPv4    10.0.2.15       49202       216.58.196.163       443            ESTABLISHED    2080   firefox.exe       N/A
0x5de48b50   TCPv4    0.0.0.0         49156       0.0.0.0              0              LISTENING       496   lsass.exe         -
0x5e0663e0   TCPv4    0.0.0.0         5357        0.0.0.0              0              LISTENING       4     System            -
0x5e0663e0   TCPv6    ::              5357        ::                   0              LISTENING       4     System            -
0x5e06b010   UDPv4    0.0.0.0         64930       *                    0              1308           svchost.exe       2019-08-19 14:40:13.000000 UTC
0x5e06b620   UDPv4    0.0.0.0         64931       *                    0              1308           svchost.exe       2019-08-19 14:40:13.000000 UTC
0x5e06b620   UDPv6    ::              64931       *                    0              1308           svchost.exe       2019-08-19 14:40:13.000000 UTC
...
0x5ff6b6d0   UDPv6    ::1             1900        *                    0              1308           svchost.exe       2019-08-19 14:42:39.000000 UTC
```



From the network scan, we can observe:

* **Local Loopback Activity**: Multiple established TCP connections on `127.0.0.1` indicate inter-process communication, such as Firefox components communicating internally.
* **External Connections**: Firefox is actively communicating with multiple external IPs over both HTTP (80) and HTTPS (443), showing normal browsing traffic and connections to Google servers (`172.217.x.x`) and other sites.
* **Listening Services**: System processes (`System`, `lsass.exe`, `services.exe`, `svchost.exe`) are listening on standard ports (e.g., 135, 445, 49152-49156), reflecting normal Windows service activity.
* **UDP Services**: svchost.exe and Chrome are using UDP ports for service discovery and local communication (5353 for mDNS, 3702 for WS-Discovery).
* **IPv6 Endpoints**: Multiple IPv6 endpoints exist, including `::1` loopback and global addresses, highlighting dual-stack network support.
* **Connection States**: Most connections are `ESTABLISHED`, but some TCP entries are in `FIN_WAIT2` or `CLOSED` states, indicating recently terminated connections.



---

## 3.9 windows.registry.hivelist — Registry Hive Enumeration


The `windows.registry.hivelist` plugin enumerates all registry hives present in a Windows memory dump. This is a critical step in memory forensics because the registry stores persistent configuration, system policies, user profiles, and software/hardware settings. By listing hives, investigators can locate and later parse sensitive keys for malware persistence, system configuration, or forensic artifacts.

Internally, the plugin scans the kernel’s `\Registry` objects. Each hive is represented by a `CMHIVE` structure in memory, which contains pointers to the hive base, allocated bins, and associated metadata. The plugin locates these structures by walking the `\Registry` object tree in kernel memory and extracting the full path of the hive as recognized by Windows. It also captures the memory offset of the hive, which is crucial for subsequent plugin usage (like `printkey`, `userassist`, or `shimcache`) since these offsets allow direct access to the in-memory hive structures.

The plugin is capable of detecting:

* **System-wide hives**: Such as `SYSTEM`, `SOFTWARE`, `SECURITY`, `SAM`, and `DEFAULT`, which store core OS configuration and security information.
* **User hives**: Including `NTUSER.DAT` for individual users and `UsrClass.dat` for user-specific COM/Explorer settings.
* **Service profiles**: Hives for built-in accounts like `NetworkService` and `LocalService`.
* **Boot configuration**: Hives like `BCD` that control startup options.

It identifies whether each hive is actively mapped in memory and ready for analysis (enabled) or not (disabled). While disabled hives cannot be directly parsed without first mapping them into the analysis session, the offsets and paths provide a roadmap for deeper registry investigations.


### Command

```bash
vol -f MemoryDump_Lab6.raw windows.registry.hivelist
```


### Output

```
Offset          FileFullPath                                                           File output
0xf8a00000d010  Disabled
0xf8a000024010  \REGISTRY\MACHINE\SYSTEM                                          Disabled
0xf8a00004e010  \REGISTRY\MACHINE\HARDWARE                                        Disabled
0xf8a0006d7010  \SystemRoot\System32\Config\SOFTWARE                               Disabled
0xf8a0009611f0  \SystemRoot\System32\Config\SECURITY                               Disabled
0xf8a0009bc410  \SystemRoot\System32\Config\SAM                                     Disabled
0xf8a000a9d410  \??\C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT            Disabled
0xf8a000b8e410  \??\C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT              Disabled
0xf8a000df7010  \??\C:\Users\Jaffa\ntuser.dat                                      Disabled
0xf8a001023010  \??\C:\Users\Jaffa\AppData\Local\Microsoft\Windows\UsrClass.dat   Disabled
0xf8a003ca8010  \Device\HarddiskVolume1\Boot\BCD                                    Disabled
0xf8a005b63410  \SystemRoot\System32\Config\DEFAULT                                Disabled
```



From the hivelist output, several insights emerge:

* **System configuration hives** (`SYSTEM`, `SOFTWARE`, `SECURITY`, `SAM`, `DEFAULT`) are present but marked disabled, meaning they were not actively mapped at the time of the memory capture. For forensic parsing, these hives would require manual mapping or extraction from disk backups.
* **User profiles** for the primary user `Jaffa` as well as built-in service accounts (`NetworkService`, `LocalService`) are listed. These can contain user-specific configurations, recently accessed files, and potential malware persistence keys.
* **Boot configuration** is available via the `BCD` hive, which is useful for analyzing startup options, boot-time malware, or OS-level tampering.
* The presence of `UsrClass.dat` shows that per-user COM and shell settings are available for forensic examination, including shellbag artifacts.

In practice, this plugin provides a map of all registry hives in memory, serving as a foundation for further in-memory registry analysis. Even when disabled, knowing their offsets and paths allows subsequent Volatility plugins to extract sensitive forensic artifacts from both system and user hives.

---


---

## 3.10 windows.malware.malfind — Malicious Memory Segment Identification


The `windows.malware.malfind` plugin is used to identify potentially malicious or injected code within the memory of Windows processes. Its primary goal is to locate executable memory regions that exhibit anomalous characteristics, such as read/write/execute permissions, which are uncommon in legitimate process memory layouts. This is particularly useful for spotting code injections, shellcode, in-memory malware, or exploit artifacts.

Internally, the plugin scans each process’s Virtual Address Descriptor (VAD) tree to locate memory regions marked with `PAGE_EXECUTE_READWRITE` or other suspicious protection flags. It extracts the virtual memory range, the process ID, and the associated executable, and can also produce a hexdump, disassembly, and a summary of memory commit and private memory size. By cross-referencing these regions with loaded modules and known DLLs, the plugin can flag anomalies, such as code executing outside standard module ranges, which are indicative of code injection or in-memory malware.

The plugin is capable of:

* Detecting injected code in running processes.
* Highlighting suspicious memory permissions like `PAGE_EXECUTE_READWRITE`.
* Extracting raw memory for further static or dynamic analysis.
* Generating partial disassembly of suspicious code for inspection.

It cannot automatically confirm maliciousness—it highlights anomalies for an investigator to analyze further.


### Command

```bash
vol -f MemoryDump_Lab6.raw windows.malware.malfind
```



```
PID     Process       Start VPN   End VPN     Tag     Protection               CommitCharge    PrivateMemory  File output  Notes  Hexdump  Disasm
1944    explorer.exe  0x4320000   0x432ffff   VadS    PAGE_EXECUTE_READWRITE     16             1              Disabled     N/A    ...      ...
0x4320000:      mov     r10d, 0x80
0x4320006:      movabs  rax, 0x7feff86a138
0x4320010:      jmp     qword ptr [rax]
0x4320013:      nop
0x4320014:      mov     r10d, 0x81
0x432001a:      movabs  rax, 0x7feff86a138
0x4320024:      jmp     qword ptr [rax]
0x4320027:      nop
0x4320028:      mov     r10d, 0x82
0x432002e:      movabs  rax, 0x7feff86a138
0x4320038:      jmp     qword ptr [rax]
0x432003b:      nop
```



From the `malfind` output, several insights emerge:

* Multiple processes (`explorer.exe` and `chrome.exe`) have memory regions with `PAGE_EXECUTE_READWRITE`, which is abnormal for standard process memory and a common sign of code injection.
* The first disassembly snippet from `explorer.exe` shows a loop of `mov` and indirect `jmp` instructions, suggesting dynamically injected code or shellcode using absolute addressing.
* The memory regions are marked `Disabled` in file output, indicating that these regions do not correspond to mapped executable files on disk, reinforcing the suspicion of in-memory malware.
* The hexdump and disassembly allow for low-level analysis, such as identifying payload patterns, jump obfuscation, or inline shellcode.

---




# Putting It All Together

Now that we've explored the essential Volatility plugins and understand how they work under the hood, it's time to put our knowledge to the test. Let's solve one of my favorite DFIR challenges that  demonstrates the power of memory forensics in a real-world investigation scenario. Here is the [Writeup](https://github.com/Cryptonite-MIT/dfir-gita/blob/main/Memory%20Analysis%20Tutorial/MemLab6.md) to follow along and deepen your understanding of Volatility and memory analysis techniques.

--- 

# References, Sources and Further Reading

* [Volatility 3 Official Documentation](https://volatility3.readthedocs.io/en/latest/) : Core reference for installation, architecture, and plugin usage in Volatility 3.

* [Volatility GitHub Repository](https://github.com/volatilityfoundation/volatility3) : Source code for Volatility 3; essential for understanding the internal memory model and plugin framework.

* [MemLabs by StuxNet](https://github.com/stuxnet999/MemLabs/tree/master) : Hands-on memory forensics labs designed for practical exploration of Windows memory.

* [Volatility3 Plugin Development Guide](https://volatility3.readthedocs.io/en/revert-1566-develop/development.html) : Step-by-step guide for writing custom plugins, exploring how Volatility structures memory objects internally.

* [Volatility Community Plugins](https://github.com/volatilityfoundation/community-plugins) : Collection of community-contributed plugins extending Volatility capabilities.

* [Windows Internals, 7th Edition](https://docs.microsoft.com/en-us/sysinternals/) : Deep dive into Windows processes, memory structures, kernel internals, and security mechanisms.
