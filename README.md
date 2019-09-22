# VAC 🛡️
This repository contains parts of source code of Valve Anti-Cheat recreated from machine code.

## Introduction
Valve Anti-Cheat (VAC) is user-mode noninvasive anti-cheat system developed by Valve. It is delivered in form of modules (dlls) streamed from remote server. `steamservice.dll` handles module loading.

## Modules
| ID | Purpose | Timestamp (UTC) |
| --- | --- | --- |
| 1 | | Mon Mar 18 18:55:25 2019 |
| 2 | | Mon Mar 18 18:52:35 2019 |
| 3 | | Mon Mar 18 19:37:52 2019 |
| 4 | | Mon Mar 18 19:07:44 2019 |
| 5 | | Mon Mar 18 19:06:04 2019 |
| 6 | | Mon Mar 18 18:03:28 2019 |
| 7 | | Mon Mar 18 19:10:14 2019 |
| 8 | | Mon Mar 18 18:47:55 2019 |
| 9 | | Mon Mar 18 18:55:45 2019 |
| 10 | | Mon Mar 18 19:26:53 2019 |
| 11 | | Mon Mar 18 19:28:33 2019 |
| 12 | | Mon Mar 18 19:06:54 2019 |
| 13 | | Mon Mar 18 18:18:27 2019 |
| 14 | | Mon Mar 18 18:52:25 2019 |
| 15 | | Mon Mar 18 19:22:23 2019 |
| 16 | | Mon Mar 18 19:06:04 2019 |
| 17 | | Mon Mar 18 19:09:54 2019 |
| 18 | | Mon Mar 18 20:14:40 2019 |
| 19 | | Mon Mar 18 19:41:32 2019 |
| 20 | | Mon Mar 18 19:41:42 2019 |

## Encryption / hashing
VAC uses several encryption / hashing methods:
- MD5 - hashing data read from process memory
- ICE - decryption of imported functions names and encryption of scan results
- CRC32 - hashing table of WinAPI functions addresses
- Xor (?)