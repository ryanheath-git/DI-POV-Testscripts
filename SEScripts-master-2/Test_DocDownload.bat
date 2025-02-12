@echo off
python malware_downloader.py -a d147ce212710591966d7fdcc00b27cb1ae228bb8571664c22f999102748ca9b0 -o ./MALWARE -r VT3 type:"doc" AND NOT tag:"corrupt" positives:45+ size:3mb- -n 10
pause
