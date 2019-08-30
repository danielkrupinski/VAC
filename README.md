# VAC 🛡️
This repository contains parts of source code of Valve Anti-Cheat recreated from machine code.

## Encryption
VAC uses several encryption methods:
- MD5 - hashing data read from process memory
- ICE - decryption of imported functions names and encryption of scan results
- CRC32 - hashing table of WinAPI functions addresses
- Xor (?)