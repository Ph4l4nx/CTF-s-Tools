# CTF's Tools 

Repository to index interesting Capture The Flag tools and other stuff.

# Table of Contents
[Platforms to practice](##platforms to practice)  
[Cryptography](##cryptography)
[Emphasis](##steganography)
[Emphasis](##osint)
[Emphasis](##forensic)
[Emphasis](##web)
[Emphasis](##reversing)
[Emphasis](##exploiting)
[Emphasis](##pentesting)
[Emphasis](##malware)
[Emphasis](##mobile)
[Emphasis](##utility)
[Emphasis](##real world interaction map)
[Emphasis](##wikis)
[Emphasis](##write-ups)
[Emphasis](##other tools)
<a name="headers"/>
## Headers

##### Table of Contents  
[Headers](#headers)  
[Emphasis](#emphasis)  
...snip...    
<a name="headers"/>


## Platforms to practice

https://ctftime.org/

https://www.hackthebox.eu/

https://atenea.ccn-cert.cni.es/home

* Hacking challenges for web: http://webhacking.kr/

* Platform for learning modern cryptography: https://cryptohack.org/

* Reversing platform: https://crackmes.one/


## Cryptography

https://gchq.github.io/CyberChef/

https://www.dcode.fr/tools-list#cryptography

* Cipher Identifier and Analyzer: https://www.boxentriq.com/code-breaking/cipher-identifier

* Data format identifier: https://geocaching.dennistreysa.de/multisolver/

* Automated cryptogram solver (substitution) https://quipqiup.com/

* Frequency Analysis: https://crypto.interactive-maths.com/frequency-analysis-breaking-the-code.html

* Brute force Vigenere: https://guballa.de/vigenere-solver

* RsaCtfTool: https://github.com/Ganapati/RsaCtfTool

* Decrpyt emoji messages https://emoji-cypher.netlify.app/

* Hash DB: https://crackstation.net/

* Hash DB: https://hashes.org/search.php

* Hash DB: https://www.onlinehashcrack.com/

* Padding-oracle-attacker: https://github.com/KishanBagaria/padding-oracle-attacker

* Maritime signal flags dictionary: https://en.wikipedia.org/wiki/International_maritime_signal_flags

* Enigma: https://cryptii.com/

* Factoring: http://factordb.com/

* Cryptanalysis recopilation: https://github.com/mindcrypt/Cryptanalysis

http://rumkin.com/tools/cipher/

* Real time converter: https://kt.gy/tools.html#conv/ 

* Ook! esoteric programming language decoder: https://www.dcode.fr/ook-language

* Brainfuck esoteric programming language decoder: https://www.dcode.fr/brainfuck-language

* Malboge esoteric programming language decoder: https://www.malbolge.doleczek.pl/

* Simple script to calculate the onion address from a Tor hidden service descriptor or public key: https://gist.github.com/DonnchaC/d6428881f451097f329e (you need to modify the line 14 for working properly "onion_address = hashlib.sha1(key.exportKey('DER')[22:]).digest()[:10]").

* Speech to text: https://speech-to-text-demo.ng.bluemix.net/

* Lyrics song: https://codewithrockstar.com/online

* Online generator md5 hash of a string: http://www.md5.cz/

## Headers

## Steganography

* Exiftool

* Zsteg 

* Exiv2

* Identify -verbose file

* Magic Numbers Signatures: https://asecuritysite.com/forensics/magic && https://www.garykessler.net/library/file_sigs.html → Hexeditor

* Binwalk -e image

* Foremost -i image -o outdir

* Steghide: http://steghide.sourceforge.net/documentation/manpage_es.php (e.g: steghide extract -sf file , steghide info file)

* Stegseek: https://github.com/RickdeJager/stegseek (Better than Stegcracker)

* StegCracker: https://github.com/Paradoxis/StegCracker

* Deeper steganography analysis tool: https://aperisolve.fr/

* Spectrum Analyzer: https://academo.org/demos/spectrum-analyzer/

* Stegsolve: https://github.com/zardus/ctf-tools/blob/master/stegsolve/install (running: java -jar steg_solve.jar)

* Fourier Transform: http://bigwww.epfl.ch/demo/ip/demos/FFT/ && https://github.com/0xcomposure/FFTStegPic

* Digital invisible ink stego tool: https://sourceforge.net/projects/diit/

https://incoherency.co.uk/image-steganography/#unhide

http://exif-viewer.com/

https://stegonline.georgeom.net/upload

https://stylesuxx.github.io/steganography/

* Morse Code Adaptive Audio Decoder: https://morsecode.world/international/decoder/audio-decoder-adaptive.html

* Audacity (sudo apt-get install audacity) E.g: https://www.hackiit.cf/write-up-hackiit-ctf-biological-hazard-ii/

* AudioStego: https://github.com/danielcardeenas/AudioStego

* Analyze suspicious files and urls to detect stegomalware: https://stegoinspector.com/#/

* Aurebesh Translator: https://funtranslations.com/aurebesh

* Bitcoin Steganography: https://incoherency.co.uk/stegoseed/

* Mojibake Steganography: https://incoherency.co.uk/mojibake/

* Chess Steganography : https://incoherency.co.uk/chess-steg/

* Magic Eye Solver / Viewer: https://magiceye.ecksdee.co.uk/

* QR decoder: https://online-barcode-reader.inliteresearch.com/ && https://zxing.org/w/decode.jspx

* Stegosuite:  http://manpages.ubuntu.com/manpages/bionic/man1/stegosuite.1.html

* StegSpy: http://www.spy-hunter.com/stegspydownload.htm

* StegSecret: http://stegsecret.sourceforge.net/

* Openstego: https://www.openstego.com/

* Stegpic: https://domnit.org/stepic/doc/

* Bytehist: https://www.cert.at/en/downloads/software/software-bytehist

https://www.bertnase.de/npiet/npiet-execute.php

* Repair images: https://online.officerecovery.com/es/pixrecovery/

* Tool for recovering passwords from pixelized screenshots: https://github.com/beurtschipper/Depix

* Forensic Image Analysis: https://github.com/GuidoBartoli/sherloq

* Unicode Steganography with Zero-Width Characters: https://330k.github.io/misc_tools/unicode_steganography.html 

* Stegsnow(Zero-Width Characters): https://pentesttools.net/hide-secret-messages-in-text-using-stegsnow-zero-width-characters/

* SPAM language or PGP: https://www.spammimic.com/decode.shtml

* f5stegojs: https://desudesutalk.github.io/f5stegojs/

## OSINT
 
* Google CheatSheet: https://www.sans.org/security-resources/GoogleCheatSheet.pdf

https://ciberpatrulla.com/links/

https://inteltechniques.com/JE/OSINT_Packet_2019.pdf

* Tools, flowcharts and cheatsheets to help you do your OSINT research:  https://technisette.com/p/tools

* World domain DB: http://web.archive.org/

* Abuse Domain,IP: https://www.abuseipdb.com/

https://viewdns.info/

https://www.threatcrowd.org/

* The search engine for the Internet of Things: https://www.shodan.io/ && All filters cheatseet: https://beta.shodan.io/search/filters

* Threat Intel Tools: https://cyberfive.uk/threat-intel-tools/

* Email2PhoneNumber: https://github.com/martinvigo/email2phonenumber

* Honeypot or not: https://honeyscore.shodan.io/

https://talosintelligence.com/

https://osintframework.com/

https://centralops.net/co/

https://builtwith.com/

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

* Censys: https://censys.io/ipv4

* Zoomeye.org: https://www.zoomeye.org/

* Find email addresses related to a domain: https://hunter.io/

* Fofa search engine: https://fofa.so/ (Similar to Shodan)

* Graphical OSINT platform: https://www.spiderfoot.net/#

* HTTP headers of a domain: https://www.webconfs.com/http-header-check.php

## Forensics

* Online PCAP Analysis: https://packettotal.com/

* Wireshark. Cheat sheet: https://cdn.comparitech.com/wp-content/uploads/2019/06/Wireshark-Cheat-Sheet-1.jpg

* Volatility. Cheat sheet: https://digital-forensics.sans.org/media/volatility-memory-forensics-cheat-sheet.pdf

* Foremost

* Binwalk

* Autopsy

* Photo forensics: https://29a.ch/photo-forensics/#forensic-magnifier

* Recuva: https://www.ccleaner.com/recuva

* AccessData FTK Imager 

* EnCase 

* Testdisk: https://www.cgsecurity.org/wiki/TestDisk_Download

* Powershell Decoder: https://github.com/R3MRUM/PSDecode, https://github.com/JohnLaTwC/PyPowerShellXray and analysis info: https://darungrim.com/research/2019-10-01-analyzing-powershell-threats-using-powershell-debugging.html

* PDF analyzer: https://github.com/zbetcheckin/PDF_analysis, https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdfid.py, https://github.com/DidierStevens/DidierStevensSuite/blob/master/pdf-parser.py y https://eternal-todo.com/tools/peepdf-pdf-analysis-tool.

* Office analyzer: http://www.reconstructer.org/, https://github.com/unixfreak0037/officeparser, https://github.com/decalage2/oletools, https://github.com/bontchev/pcodedmp, https://github.com/decalage2/ViperMonkey && https://blog.didierstevens.com/programs/oledump-py/.

* Extract Unicode-encoded content from a file: https://github.com/DidierStevens/DidierStevensSuite/blob/master/base64dump.py

* DTMF telephone frecuency: https://unframework.github.io/dtmf-detect/

* To decrypt WPA keys: pyrit -r "capctura.pcap" analyze

* Diskeditor: https://www.disk-editor.org/index.html

* PhotoRec: https://www.cgsecurity.org/wiki/PhotoRec

* Passware encryption analyzer: https://www.passware.com/encryption-analyzer/

* Windows Registry Recovery: https://www.softpedia.com/get/Tweak/Registry-Tweak/Windows-Registry-Recovery.shtml

* xxd command

* Blue Team Cheat sheet: https://itblogr.com/wp-content/uploads/2020/04/The-Concise-Blue-Team-cheat-Sheets.pdf

* DFIR cheat sheet: https://www.jaiminton.com/cheatsheet/DFIR/#

* Parse a user agent: https://developers.whatismybrowser.com/useragents/parse/

* Grep cheat sheet: https://javiermartinalonso.github.io/linux/2018/01/15/linux-grep-patrones-debug.html

* Blog: https://www.osintme.com/

* Regular expressions for grep -Po " " https://regex101.com/

https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/

https://blog.didierstevens.com/programs/xorsearch/

## Web

* Wappalyzer

* Burpsuite

* OWASP ZAP, OpenVas, Sparta & Nikto. Cheat Sheet: https://redteamtutorials.com/2018/10/24/nikto-cheatsheet/ 

* Hydra. Cheat Sheet: https://redteamtutorials.com/2018/10/25/hydra-brute-force-techniques/

* Dirbuster. https://mundo-hackers.weebly.com/dirbuster.html

* Linkfinder: https://github.com/GerbenJavado/LinkFinder

* Gobuster. Cheat Sheet: https://redteamtutorials.com/2018/11/19/gobuster-cheatsheet/

* wfuzz. Cheat Sheet: https://book.hacktricks.xyz/pentesting-web/web-tool-wfuzz

* Dirsearch: https://github.com/maurosoria/dirsearch

* Nmap cheatsheet: https://scadahacker.com/library/Documents/Cheat_Sheets/Hacking%20-%20NMap%20Quick%20Reference%20Guide.pdf

* Automated All-in-One OS command injection and exploitation tool: https://github.com/commixproject/commix

* Automated XSS tool: https://xsser.03c8.net/

* SQL payload examples: https://github.com/payloadbox/sql-injection-payload-list

* Command injection: https://github.com/payloadbox/command-injection-payload-list

* WPscan

https://pentest-tools.com/home

https://book.hacktricks.xyz/

http://jsonviewer.stack.hu/

https://github.com/blaCCkHatHacEEkr/PENTESTING-BIBLE

https://jorgectf.gitbook.io/awae-oswe-preparation-resources/

## Reversing

* Binwalk

* Dotpeek (.NET)

* GameBoy debugger: https://bgb.bircd.org/

* IDA pro. Cheat Sheet: https://www.dragonjar.org/cheat-sheet-ida-pro-interactive-disassembler.xhtml

* Ollydbg. Cheat Sheet: http://www.ollydbg.de/quickst.htm

* GDB:  https://gist.github.com/rkubik/b96c23bd8ed58333de37f2b8cd052c30

* Radare2. Cheat Sheet: https://gist.github.com/williballenthin/6857590dab3e2a6559d7

* Ghidra. Cheat Sheet: https://hackersfun.com/wp-content/uploads/2019/03/Ghidra-Cheat-Sheet.pdf

* Immunity Debugger: https://www.immunityinc.com/products/debugger/

* x64dbg

* DnSpy https://github.com/dnSpy/dnSpy

* Regshot:  https://sourceforge.net/projects/regshot/ (before and after running a binary)

* CFF explorer: https://download.cnet.com/CFF-Explorer/3000-2383_4-10431156.html

* Online Disassembler: https://onlinedisassembler.com/static/home/index.html

* Online .JAR and .Class to Java decompiler:  http://www.javadecompilers.com/

* Android Decompiler: https://ibotpeaches.github.io/Apktool/

* Decompile Android files: https://github.com/skylot/jadx

* List Dynamic Dependencies: Ldd file

* Unpacking some binaries: Upx -d file

* Intel® 64 and IA-32 Architectures Software Developer’s Manual: https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf 

## Exploiting

* Ej1: python -c "print 'A'*150" >>> Then ./binario 150 A

* Ej2: (echo -e "\x31\xc0\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x89\xc1\x89\xc2\xb0\x0b\xcd\x80\x31\xc0\x40\xcd\x80"; cat-) | ./binario (Shellcode for x86 32 linux)

## Pentesting

* Metasploit. Cheat sheet: https://github.com/k1000o23/cheat_sheets/blob/master/metasploit_cheat_sheet.pdf

* https://www.exploit-db.com/

* Biggest DNS historical data: https://securitytrails.com/

* Nmap

* Ffuf: https://github.com/ffuf/ffuf

* SearchSploit. Cheat sheet: https://blog.ehcgroup.io/2018/11/27/01/00/39/4198/como-usar-searchsploit-para-encontrar-exploits/hacking/ehacking/

https://github.com/Leviathan36/kaboom

* Videos: https://www.youtube.com/c/s4vitar/featured
 
## Malware 

* Virustotal: https://www.virustotal.com/gui/home/search

* Joesandbox: https://www.joesandbox.com/#windows

* Hybrid Analysis: https://www.hybrid-analysis.com/?lang=es

* ANY.RUN https://any.run/

* Online Cuckoo Sandbox: https://sandbox.pikker.ee/

* All in one (NETWORK+REVERSING): https://www.procdot.com/

* Sandbox: https://github.com/CERT-Polska/drakvuf-sandbox

* https://virusscan.jotti.org/

* Ransomware decryption tools: https://www.nomoreransom.org/es/decryption-tools.html , https://www.avast.com/es-es/ransomware-decryption-tools , https://noransom.kaspersky.com/ , https://www.mcafee.com/enterprise/es-es/downloads/free-tools/ransomware-decryption.html. Overview: https://docs.google.com/spreadsheets/d/1TWS238xacAto-fLKh1n5uTsdijWdCEsGIM0Y0Hvmc5g/pubhtml#

* Analyze APK's: https://amaaas.com/

* Database of counterfeit-related webs: https://desenmascara.me/

* Sysinternals: https://docs.microsoft.com/en-us/sysinternals/

* RAT Decoder: https://github.com/kevthehermit/RATDecoders

* https://github.com/alexandreborges/malwoverview

* https://nodistribute.com/

* https://metadefender.opswat.com/?lang=en

* https://www.virscan.org/

* https://sandbox.anlyz.io/dashboard

* https://github.com/mindcrypt/powerglot

* Malware examples/binaries: https://github.com/ytisf/theZoo

* APT's: https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml# && https://github.com/StrangerealIntel/EternalLiberty/blob/main/EternalLiberty.csv

## Mobile

* Mobile Pentest Cheatsheet: https://github.com/tanprathan/MobileApp-Pentest-Cheatsheet

* Automated  Mobile tools: https://github.com/MobSF/Mobile-Security-Framework-MobSF, https://github.com/SUPERAndroidAnalyzer/super

## Utility

* Hexeditor

* nc URL port

* Grep

* rgrep (Recursive grep)

* awk

* perl

* tail / head 

* curl

* Identify -verbose 

* Hash-identifier

* cat 'file' | md5sum, sha1sum,sha256sum...

* echo "string" | base64 -d 

* Strings 

* File 

* Cewl. Cheat sheet: https://null-byte.wonderhowto.com/how-to/hack-like-pro-crack-passwords-part-5-creating-custom-wordlist-with-cewl-0158855/

* Password Recovery Online : https://www.lostmypass.com/try/

* Disk Image: https://www.datanumen.com/disk-image-download-thanks/

https://github.com/Xpykerz/CrackZip

https://github.com/openwall/john/blob/bleeding-jumbo/src/zip2john.c

* Common User Passwords Profiler: https://github.com/Mebus/cupp y https://github.com/r3nt0n/bopscrk. 

## Real World interaction Map

https://threatbutt.com/map/

## Wikis

https://uppusaikiran.github.io/hacking/Capture-the-Flag-CheatSheet/

https://github.com/JohnHammond/ctf-katana

https://github.com/uppusaikiran/awesome-ctf-cheatsheet#awesome-ctf-cheatsheet-

https://github.com/OpenToAllCTF/Tips

Reversing tutorial: https://github.com/mytechnotalent/Reverse-Engineering-Tutorial


## Write-Ups

https://ctftime.org/writeups

https://apsdehal.in/awesome-ctf/

https://ctf.courgettes.club/

https://jorgectf.gitlab.io/

https://github.com/0e85dc6eaf/CTF-Writeups

https://github.com/RazviOverflow/ctfs

https://github.com/DEKRA-CTF/CTFs/tree/main/2020


## Other tools

https://github.com/zardus/ctf-tools

https://github.com/apsdehal/awesome-ctf

