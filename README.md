# CTF's Tools 

Repository to index interesting Capture The Flag tools and other stuff.

## Platforms to practice:

https://ctftime.org/

https://www.hackthebox.eu/

https://atenea.ccn-cert.cni.es/home

* Hacking challenges for web: http://webhacking.kr/

* Platform for learning modern cryptography: https://cryptohack.org/

* Reversing platform: https://crackmes.one/


## Cryptography:

https://gchq.github.io/CyberChef/

https://www.dcode.fr/tools-list#cryptography

* Decrpyt emoji messages https://emoji-cypher.netlify.app/

* Cipher Identifier and Analyzer: https://www.boxentriq.com/code-breaking/cipher-identifier

* Data format identifier: https://geocaching.dennistreysa.de/multisolver/

* RsaCtfTool: https://github.com/Ganapati/RsaCtfTool

* Frequency Analysis: https://crypto.interactive-maths.com/frequency-analysis-breaking-the-code.html

* Hash DB: https://crackstation.net/

* Hash DB: https://hashes.org/search.php

* Padding-oracle-attacker: https://github.com/KishanBagaria/padding-oracle-attacker

* Maritime signal flags dictionary: https://en.wikipedia.org/wiki/International_maritime_signal_flags

* Enigma: https://cryptii.com/

* Substitution: https://quipqiup.com/

* Factoring: http://factordb.com/

* Cryptanalysis recopilation: https://github.com/mindcrypt/Cryptanalysis

http://rumkin.com/tools/cipher/

* Real time converter: https://kt.gy/tools.html#conv/ 

* Ook! esoteric programming language decoder: https://www.dcode.fr/ook-language

* Brainfuck esoteric programming language decoder: https://www.dcode.fr/brainfuck-language

* Malboge esoteric programming language decoder: https://www.malbolge.doleczek.pl/

* Simple script to calculate the onion address from a Tor hidden service descriptor or public key: https://gist.github.com/DonnchaC/d6428881f451097f329e (you need to modify the line 14 for working properly "onion_address = hashlib.sha1(key.exportKey('DER')[22:]).digest()[:10]").

## Steganography:

* Exiftool

* Zsteg 

* Exiv2

* Magic Numbers Signatures: https://asecuritysite.com/forensics/magic → Hexeditor

* Binwalk -e image

* Foremost -i image -o outdir

* Steghide: http://steghide.sourceforge.net/documentation/manpage_es.php (e.g: steghide extract -sf file , steghide info file)

* StegCracker: https://github.com/Paradoxis/StegCracker

* Magic Eye Solver / Viewer: https://magiceye.ecksdee.co.uk/

* Deeper steganography analysis tool: https://aperisolve.fr/

* QR decoder: https://zxing.org/w/decode.jspx

* Stegsolve: https://github.com/zardus/ctf-tools/blob/master/stegsolve/install (running: java -jar steg_solve.jar)

* Fourier Transform: http://bigwww.epfl.ch/demo/ip/demos/FFT/   https://github.com/0xcomposure/FFTStegPic

* Analyze suspicious files and urls to detect stegomalware: https://stegoinspector.com/#/

http://exif-viewer.com/

https://stegonline.georgeom.net/upload

https://stylesuxx.github.io/steganography/

https://incoherency.co.uk/image-steganography/#unhide

https://29a.ch/photo-forensics/#forensic-magnifier

* Stegosuite:  http://manpages.ubuntu.com/manpages/bionic/man1/stegosuite.1.html

* StegSpy: http://www.spy-hunter.com/stegspydownload.htm

* StegSecret: http://stegsecret.sourceforge.net/

* Bytehist: https://www.cert.at/en/downloads/software/software-bytehist

* Morse Code Adaptive Audio Decoder: https://morsecode.world/international/decoder/audio-decoder-adaptive.html

https://www.bertnase.de/npiet/npiet-execute.php

## OSINT:
 
* Google CheatSheet: https://www.sans.org/security-resources/GoogleCheatSheet.pdf

https://ciberpatrulla.com/links/

https://inteltechniques.com/JE/OSINT_Packet_2019.pdf

* World domain DB: http://web.archive.org/

https://viewdns.info/

https://www.threatcrowd.org/

* The search engine for the Internet of Things: https://www.shodan.io/

* Honeypot or not: https://honeyscore.shodan.io/

https://talosintelligence.com/

https://osintframework.com/

https://centralops.net/co/

* Pwn DB TOR:  http://pwndb2am4tzkvold ...

* Website to check if emails or passwords have been compromised: https://haveibeenpwned.com/

* Pwn DB: https://intelx.io/

* Search filtered credentials in plain text: https://esgeeks.com/pwndb-buscar-credenciales-filtradas-texto-plano/

* Email checker: https://toolbox.googleapps.com/apps/checkmx/

* General purpose: https://github.com/Moham3dRiahi/Th3inspector

* Gooogle Image Search: https://www.google.es/imghp?hl=es , Yandex: https://yandex.com/images/ , Bing: https://www.bing.com/?scope=images&nr=1&FORM=NOFORM

* Reverse Image Search: https://tineye.com/

* Tool for tracking the redirection paths of URLs: https://wheregoes.com/

* Phishing Domain DB: http://phishtank.org/

* Phishing Domain DB: https://phishcheck.me/

* Instagram: https://github.com/th3unkn0n/osi.ig

* Hurricane Electric BGP: https://bgp.he.net/


## Forensic:

* Online PCAP Analysis: https://packettotal.com/

* Wireshark. Cheat sheet: https://cdn.comparitech.com/wp-content/uploads/2019/06/Wireshark-Cheat-Sheet-1.jpg

* To decrypt WPA keys: pyrit -r "capctura.pcap" analyze 

* Volatility. Cheat sheet: https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf

* Foremost

* Binwalk

* Autopsy

* AccessData FTK Imager 

* EnCase 

* Powershell Decoder: https://github.com/R3MRUM/PSDecode

* Diskeditor: https://www.disk-editor.org/index.html

* PhotoRec: https://www.cgsecurity.org/wiki/PhotoRec

* Passware encryption analyzer: https://www.passware.com/encryption-analyzer/

* Windows Registry Recovery: https://www.softpedia.com/get/Tweak/Registry-Tweak/Windows-Registry-Recovery.shtml

* xxd command

* Blue Team Cheatsheet: https://itblogr.com/wp-content/uploads/2020/04/The-Concise-Blue-Team-cheat-Sheets.pdf

https://www.jaiminton.com/cheatsheet/DFIR/#

* Parse a user agent: https://developers.whatismybrowser.com/useragents/parse/

https://javiermartinalonso.github.io/linux/2018/01/15/linux-grep-patrones-debug.html

https://www.osintme.com/

* Regular expressions for grep -Po " " https://regex101.com/

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

## Web:

* Wappalyzer

* Burpsuite

* OWASP ZAP, OpenVas, Sparta & Nikto. Cheat Sheet: https://redteamtutorials.com/2018/10/24/nikto-cheatsheet/ 

* Hydra. Cheat Sheet: https://redteamtutorials.com/2018/10/25/hydra-brute-force-techniques/

* Gobuster. Cheat Sheet: https://redteamtutorials.com/2018/11/19/gobuster-cheatsheet/

* wfuzz. Cheat Sheet: https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz

* Nmap cheatsheet: https://scadahacker.com/library/Documents/Cheat_Sheets/Hacking%20-%20NMap%20Quick%20Reference%20Guide.pdf

* Automated All-in-One OS command injection and exploitation tool: https://github.com/commixproject/commix

* Automated XSS tool: https://xsser.03c8.net/

https://github.com/payloadbox/sql-injection-payload-list

https://github.com/payloadbox/command-injection-payload-list

https://pentest-tools.com/home

https://book.hacktricks.xyz/

http://jsonviewer.stack.hu/

https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE

https://jorgectf.gitbook.io/awae-oswe-preparation-resources/

## Reversing:

* Binwalk

* Dotpeek (.NET)

* IDA pro. Cheat Sheet: https://www.dragonjar.org/cheat-sheet-ida-pro-interactive-disassembler.xhtml

* Ollydbg. Cheat Sheet: http://www.ollydbg.de/quickst.htm

* Radare2. Cheat Sheet: https://gist.github.com/williballenthin/6857590dab3e2a6559d7

* Ghidra. Cheat Sheet: https://hackersfun.com/wp-content/uploads/2019/03/Ghidra-Cheat-Sheet.pdf

* x64dbg

* DnSpy https://github.com/dnSpy/dnSpy

* Regshot:  https://sourceforge.net/projects/regshot/ (before and after running a binary)

https://www.gnu.org/software/gdb/

https://download.cnet.com/CFF-Explorer/3000-2383_4-10431156.html

* Online Disassembler: https://onlinedisassembler.com/static/home/index.html

* Online .JAR and .Class to Java decompiler:  http://www.javadecompilers.com/

* Android Decompiler: https://ibotpeaches.github.io/Apktool/

* Decompile Android files: https://github.com/skylot/jadx

* List Dynamic Dependencies: Ldd file

* Unpacking binaries: Upx -d file

* Intel® 64 and IA-32 Architectures Software Developer’s Manual: https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf 

* Free book of reversing: https://beginners.re/

## Malware 

* Virustotal: https://www.virustotal.com/gui/home/search

* Joesandbox: https://www.joesandbox.com/#windows

* Hybrid Analysis: https://www.hybrid-analysis.com/?lang=es

* ANY.RUN https://any.run/

* Sandbox: https://github.com/CERT-Polska/drakvuf-sandbox

* Ransomware decryption tools: https://www.nomoreransom.org/es/decryption-tools.html , https://www.avast.com/es-es/ransomware-decryption-tools , https://noransom.kaspersky.com/ , https://www.mcafee.com/enterprise/es-es/downloads/free-tools/ransomware-decryption.html

* Database of counterfeit-related webs: https://desenmascara.me/

* https://github.com/alexandreborges/malwoverview

* https://nodistribute.com/

* https://metadefender.opswat.com/?lang=en

* https://www.virscan.org/

* https://sandbox.anlyz.io/dashboard

* https://github.com/mindcrypt/powerglot

* Malware examples/binaries: https://github.com/ytisf/theZoo

## Utility:

* Hexeditor

* Grep

* awk

* perl

* tail / head 

* Identify -verbose 

* Hash-identifier

* cat 'file' | md5sum, sha1sum,sha256sum...

* echo " string" | base64 -d 

* Strings 

* File 

* Password Recovery Online : https://www.lostmypass.com/try/

https://github.com/Xpykerz/CrackZip

https://github.com/openwall/john/blob/bleeding-jumbo/src/zip2john.c


## Wikis:

https://uppusaikiran.github.io/hacking/Capture-the-Flag-CheatSheet/

https://github.com/OpenToAllCTF/Tips

https://github.com/uppusaikiran/awesome-ctf-cheatsheet#awesome-ctf-cheatsheet-


## Write-Ups:

https://ctftime.org/writeups

https://apsdehal.in/awesome-ctf/

https://ctf.courgettes.club/

https://jorgectf.gitlab.io/

https://github.com/0e85dc6eaf/CTF-Writeups

https://github.com/RazviOverflow/ctfs


## Other tools:

https://github.com/zardus/ctf-tools

