# Cryptonite Forensics Training Resources aka DFIR Gita

Cryptonite is the official CTF team of MIT Manipal currently ranked #3 across India.

The forensics domain is focused on incident response, network traffic analysis, steganography and malware analysis for CTFs and practical incident response. This repository is a living resource list for trainees: tools, reference material, and CTF challenges grouped by domain.

> [!NOTE]
> This is a work in progress, check back periodically for updates and additions.

The domain covers three main areas:
- Steganography and file structures
- Network and PCAP/Log analysis
- Digital forensics and incident response

Every section will have a list of required information and a list of challenges, some with file links, that will teach you how most Forensics challenges in CTFs operate.

## TODO

- [ ] fix all .zip drive links
- [ ] add all challenge files, some are missing
- [ ] add scripts to finish text steganography easily
- [ ] custom challenges
- [ ] malware resource
- [ ] add all nite chals

# Steganography / File structures

## Essential tools

stego-toolkit (Docker image: https://github.com/DominicBreuker/stego-toolkit)

_One stop resource for any and all steg related challenges_

| Tool        | File Types Supported        | Password Support        | Primary Function                                      |
|--------------|-----------------------------|--------------------------|--------------------------------------------------------|
| **steghide** | JPG, WAV                    | With/Without password    | Embed/extract data                                    |
| **jsteg**    | JPG                         | No                       | Embed/extract data                                    |
| **zsteg**    | PNG                         | No                       | Detect and extract hidden data                        |
| **openstego**| Multiple                    | Yes                      | General-purpose steganography                         |
| **stegseek** | JPG, WAV (via steghide)     | Brute force supported    | Password brute-forcing for steghide                   |
| **stegsolve**| Any image                   | N/A                      | Analyze bitplanes and color channels                  |
| **deepsound**| WAV                         | With/Without password    | Embed/extract data in audio                           |
| **wavsteg**  | WAV                         | No                       | Embed/extract data in audio                           |
| **qrazybox** | QR codes                    | N/A                      | Analyze and reconstruct QR codes                      |
| **stegsnow** | Text (whitespace)           | Optional password        | Whitespace steganography                              |
| **zwsp-steg**| Text (zero-width chars)     | No                       | Zero-width steganography                              |
| **exiftool** | Any file                    | N/A                      | View and edit metadata                                |
| **binwalk**  | Any file                    | N/A                      | Extract embedded files and data                       |
| **foremost** | Any file                    | N/A                      | Carve and recover embedded or deleted files           |

## Recommended CTF challenges to do:

- TUCTF 2025: Bunker
- CSAW 2024 Qualifiers: ZIPZIPZIP
- CSAW 2024 Qualifiers: The Triple Illusion
- CSAW 2024 Qualifiers: Is There An Echo
- CSAW 2024 Qualifiers: I Like My Camera RAW
- N0PS CTF 2024: ZipZip
- IRONCTF 2024: Uncrackable Zip
- WaniCTF 2024: tiny10px

Files for Wani, NOPS and PearlCTF are in this archive https://drive.google.com/file/d/1uUQRf-RBgYiOcpfKISGM6eqNhO1G2fqs

## Informational videos

All videos in this playlist dive in depth into one kind of file type, either showing its workings internally or how it can be used to hide data inside it: https://www.youtube.com/playlist?list=PLuqhjCtN5ZL6n787NuzelPTmequ66TSp1

# Networking / PCAP / Log Analysis

A sub part of the DFIR domain. Focuses on networking and traffic analysis to analyze transmission of information across networks.

## Core tools, libraries and their use

- Wireshark (GUI)
- tshark (CLI)
- tcpdump
- scapy
- pyshark

- tcpdump
  - Capture: `tcpdump -i eth0 -w capture.pcap`
  - Filtered capture: `tcpdump -i eth0 port 80 -w http.pcap`
  - Read: `tcpdump -r capture.pcap`

- tshark
  - Extract fields: `tshark -r capture.pcap -T fields -e ip.src -e ip.dst`
  - Live capture to file: `tshark -i eth0 -f "tcp and port 80" -w out.pcap`

- scapy (Python)
  - Read pcap: `pkts = rdpcap("capture.pcap")`
  - Send packet: `send(IP(dst="1.2.3.4")/TCP()/b"data")`

- pyshark
  - Iterate: `cap = pyshark.FileCapture("capture.pcap"); for pkt in cap: print(pkt)`

PCAP vs PCAPNG:

- pcap: simple libpcap format, per-packet headers, widely supported.
- pcapng: richer metadata, per-interface blocks, comments, better timestamps.

Tool differences (short):

- wireshark: GUI analyzer, deep dissectors, follow TCP stream, visualizations.
- tcpdump: capture/filter CLI tool, lightweight.
- scapy: Python packet crafting/manipulation and analysis library.
- tshark: CLI Wireshark for batch processing and field extraction.

## Recommended CTF challenges to do:

- PicoCTF: Wireshark doo dooo do doo...
- PicoCTF: Wireshark twoo twooo two twoo...
- PicoCTF: shark on wire 1
- PicoCTF: shark on wire 2
- PicoCTF: WebNet1
- PicoCTF: Torrent Analyze
- WaniCTF 2024: I wanna be a streamer
- NOPSCTF 2024: HID
- PearlCTF 2024: pcap busterz 1
- cruXipher 2024: blues
- M\*CTF 2024: Average Bluetooth Enjoyer
- BCCTF 2025: Lost City
- BCCTF 2025: Times to Die
- ASIS CTF Finals 2013: PCap
- CrewCTF 2024: Recursion
- HITCON CTF 2023: Not Just usbpcap
- ShunyaCTF 2024: Bluetooth For The Win
- ShunyaCTF 2024: Check Research and Check again
- SarCTF 2020: Blogger
- VolgaCTF Qualifiers 2021: Streams
- WaniCTF 2024: tiny10px
- DawgCTF: Someone's at the Door
- DawgCTF: Stingray Snipher
- FMCTF: UDP Upload
- niteCTF 2023: I give up
- CSAW 2024 Qualifiers: C0vert

- Files for cruXipher, M\*CTF and Enigma https://drive.google.com/file/d/1NOPhEfhhXJm-h-XG6IysfJKfBQVBQsjW
- Other challenge files (not complete): https://drive.google.com/file/d/17GRGobyw4LXfEA_xLKFTz_Y70PBgGYOw

Other useful resources:

- pwn.college's `intercepting-communication` module: https://pwn.college/intro-to-cybersecurity/intercepting-communication/
- pwn.college's `reverse-engineering` (relevant) https://pwn.college/intro-to-cybersecurity/reverse-engineering/
- TryHackMe room - Intro to Networking: https://tryhackme.com/room/introtonetworking
- Free CCNA playlist: https://www.youtube.com/playlist?list=PLxbwE86jKRgMpuZuLBivzlM8s2Dk5lXBQ

# Digital Forensics and Incident Response

DFIR covers disk and memory forensics, timeline reconstruction, registry analysis, artifact extraction, and incident reporting.

## Core tools and frameworks

- Volatility 2
- Volatility 3
- Autopsy/Sleuth Kit
- FTK Imager
- LiME (memory acquisition for Linux)
- Sysinternals suite (Windows)

## Volatility 2 vs Volatility 3

- Volatility 3 is Python 3 native; Volatility 2 historically used Python 2.
- Plugin architectures differ, many plugins reworked in v3.
- v3 has updated parsers and active development, v2 has many mature community plugins and writeups.
- Performance and cross-platform improvements exist in v3, but some v2 plugins may not have direct equivalents.

Memlabs:

- Repo: https://github.com/stuxnet999/MemLabs
- Used by bi0s as part of their DFIR training, great starter resource.
- **Volatility 2 recommended to solve.**

## Recommended CTF challenges to do:

- bi0sCTF 2025: AnansiTap

Drive: https://drive.google.com/file/d/1Myv-ObaP2XZufNcZfPHrnrV3RIvY63zr/view?usp=sharing

Questions: https://github.com/teambi0s/bi0sCTF/tree/bd6d2efbf5c8e69e5d9c06fcbfadd7733cdaffae/2025/DFIR/AnansiTap

- bi0sCTF 2025: Bombardino Exfilrino

Drive: https://drive.google.com/file/d/1nbozAcQu7Sm7JOwWV_cwmcdtz-47uxSZ/view?usp=sharing

Questions: https://github.com/teambi0s/bi0sCTF/blob/bd6d2efbf5c8e69e5d9c06fcbfadd7733cdaffae/2025/DFIR/Bombardino%20Exfilrino/Admin/Questions.md

- bi0sCTF 2024: Batman Investigation II — Gotham Underground Corruption

Drive: https://drive.google.com/file/d/1Z3TH8qo8SyEZO6UjteakHsekRKoZgE3C/view?usp=sharing

Questions: https://github.com/Azr43lKn1ght/DFIR-LABS/tree/main/Batman%20Investigation%20II

- Gotham Hustle DFIR (easy challenge from bi0sCTF): https://drive.google.com/file/d/1fwqdgpXkEnZ2xgujGaRufmPht5H_3xrT

- BITSCTF 2024 Challenge bundle: https://drive.google.com/file/d/1fut8RMl7-PJHYybRD89mAWah2B8M3ftY/view?usp=sharing

  Questions:

  1. Access Granted!

  > First things first. MogamBro is so dumb that he might be using the same set of passwords everywhere, so lets try cracking his PC's password for some luck.

  2. 0.69 Day:

  > MogamBro was using some really old piece of software for his daily tasks. What a noob! Doesn't he know that using these deprecated versions of the same leaves him vulnerable towards various attacks! Sure he faced the consequences through those spam mails.

  3. MogamBro's Guilty Pleasure:

  > MogamBro was spammed with a lot of emails, he was able to evade some but fell for some of them due to his greed. Can you analyze the emails & figure out how he got scammed, not once but twice!

  4. I'm wired in:

  > MogamBro got scared after knowing that his PC has been hacked and tried to type a SOS message to his friend through his 'keyboard'. Can you find the contents of that message, obviously the attacker was logging him!

  5. Bypassing Transport Layer:

  > The exploit not only manipulated MogamBro's secret but also tried to establish an external TCP connection to gain further access to the machine. But I don't really think he was able to do so. Can you figure out where the exploit was trying to reach to?

  6. Lottery:

  > Now that you know the CVE, figure out how the attacker crafted the payload & executed it to compromise the 'secret'.

  Flag format: `BITSCTF{}`

- Schmerz DFIR challenges : https://mega.nz/file/CKI1XI5L#4XWGTbC-U-Ym4BM-0IAQICsf6T7f-FkH4OKQ1zYYV3I

  - **schmerz-1:** _What is the value of the registry entry that was stored by the macro?_
  - **schmerz-2:** _What was the first shell command attacker executed?_
  - **schmerz-3:** _What was the value of key attacker used to encrypt the data?_
  - **schmerz-4:** _What were the contents of the secret file? (flag is the sha256sum of the file inside the zip)_
  - Flag format: `flag{}`

- **Additional challenges:** https://drive.google.com/file/d/17GRGobyw4LXfEA_xLKFTz_Y70PBgGYOw/

  - ASIS CTF Finals 2013: PCap
  - CrewCTF 2024: Recursion
  - HITCON CTF 2023: Not Just usbpcap
  - ShunyaCTF 2024: Bluetooth For The Win
  - ShunyaCTF 2024: Check Research and Check again
  - SarCTF 2020: Blogger
  - VolgaCTF Qualifiers 2021: Streams

# Other Resources and Books

- Malware & DFIR series by bi0s: https://azr43lkn1ght.github.io/Malware%20Development,%20Analysis%20and%20DFIR%20Series%20-%20Part%20I%2f
- The Art of Memory Forensics (book): https://repo.zenk-security.com/Forensic/The%20Art%20of%20Memory%20Forensics%20-%20Detecting%20Malware%20and%20Threats%20in%20Windows,%20Linux,%20and%20Mac%20Memory%20(2014).pdf
- [Docker Tutorial](https://www.docker.com/101-tutorial/)
- [Docker Docs](https://docs.docker.com/get-started/introduction/)
- `regdmp` - highly useful tool for registry analysis. Dumps registry binaries as raw text: https://github.com/adoxa/regdump
- `vol3-plugins` - repo for several useful Volatility **3** plugins that target common points of hiding data: https://github.com/spitfirerxf/vol3-plugins


