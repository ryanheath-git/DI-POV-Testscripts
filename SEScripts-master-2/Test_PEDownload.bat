@echo off
python malware_downloader.py -a d147ce212710591966d7fdcc00b27cb1ae228bb8571664c22f999102748ca9b0 -o ./MALWARE -r VT3 type:"peexe" AND NOT tag:"corrupt" positives:60+ size:3mb- -n 20
pause
