# CTF's Tools 

Repository to index interesting Capture The Flag tools and another stuff.

## Platforms to practice:

https://ctftime.org/

https://www.hackthebox.eu/

https://atenea.ccn-cert.cni.es/home


## Cryptography:

https://gchq.github.io/CyberChef/

https://www.dcode.fr/tools-list#cryptography

* Data format identifier: https://geocaching.dennistreysa.de/multisolver/

* RsaCtfTool: https://github.com/Ganapati/RsaCtfTool

* Real time converter: https://kt.gy/tools.html#conv/ 

* Hash DB: https://crackstation.net/

* Hash DB: https://hashes.org/search.php

* Enigma: https://cryptii.com/

* Substitution: https://quipqiup.com/

* Simple script to calculate the onion address from a Tor hidden service descriptor or public key: https://gist.github.com/DonnchaC/d6428881f451097f329e (you need to modify the line 14 for working properly "onion_address = hashlib.sha1(key.exportKey('DER')[22:]).digest()[:10]").

## Steganography:

* Exiftool

* Zsteg 

* Exiv2

* StegCracker: https://github.com/Paradoxis/StegCracker

* Steghide: http://steghide.sourceforge.net/documentation/manpage_es.php (e.g: steghide extract -sf file , steghide info file)

* Stegsolve: https://github.com/zardus/ctf-tools/blob/master/stegsolve/install (running: java -jar steg_solve.jar)

* Magic Numbers Signatures: https://asecuritysite.com/forensics/magic → Hexeditor

* Stegosuite:  http://manpages.ubuntu.com/manpages/bionic/man1/stegosuite.1.html

* StegSpy: http://www.spy-hunter.com/stegspydownload.htm

* StegSecret: http://stegsecret.sourceforge.net/

https://stegonline.georgeom.net/upload

http://exif-viewer.com/

https://futureboy.us/stegano/decinput.html

https://stylesuxx.github.io/steganography/

https://incoherency.co.uk/image-steganography/#unhide

* Bytehist: https://www.cert.at/en/downloads/software/software-bytehist

* Morse Code Adaptive Audio Decoder: https://morsecode.world/international/decoder/audio-decoder-adaptive.html

* Fourier Transform: http://bigwww.epfl.ch/demo/ip/demos/FFT/

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

* Gooogle Image Search: https://www.google.es/imghp?hl=es

* Reverse Image Search: https://tineye.com/


## Forensic:

* Online PCAP Analysis: https://packettotal.com/

* Wireshark

* Volatility

* Foremost

* Autopsy

* AccessData FTK Imager 

* EnCase 

* Diskeditor: https://www.disk-editor.org/index.html

* PhotoRec: https://www.cgsecurity.org/wiki/PhotoRec

* Passware encryption analyzer: https://www.passware.com/encryption-analyzer/

* Windows Registry Recovery: https://www.softpedia.com/get/Tweak/Registry-Tweak/Windows-Registry-Recovery.shtml

* xxd command

https://www.jaiminton.com/cheatsheet/DFIR/#

https://developers.whatismybrowser.com/useragents/parse/

https://javiermartinalonso.github.io/linux/2018/01/15/linux-grep-patrones-debug.html

* Expresiones regulares para el grep -Po " " https://regex101.com/

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

## Web:

* Wappalyzer

* Burpsuite

* OWASP ZAP, OpenVas, Sparta & Nikto.

* Hydra

* Gobuster

* wfuzz

https://github.com/payloadbox/sql-injection-payload-list

https://github.com/payloadbox/command-injection-payload-list

https://pentest-tools.com/home

https://book.hacktricks.xyz/pentesting-web/command-injection

http://jsonviewer.stack.hu/

https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE

## Reversing:

* Binwalk

* Dotpeek

* Radare2 (izq. icq , afl, vv @ function , pdf @ function ... )

* Ollydbg

* IDA pro

* Ghidra

* x64dbg

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

* Ransomware decryption tools: https://www.nomoreransom.org/es/decryption-tools.html

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


