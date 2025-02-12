INTELLIGENCE_SEARCH_URL: str = 'https://www.virustotal.com/intelligence/search/programmatic/'
INTELLIGENCE_DOWNLOAD_URL: str = 'https://www.virustotal.com/intelligence/download/'
VT2_API_BASE_URL: str = 'https://www.virustotal.com/vtapi/v2'
VT3_API_BASE_URL: str = 'https://www.virustotal.com/api/v3'

VENDOR_LIST = ['Acronis', 'Ad-Aware', 'AegisLab', 'AhnLab-V3', 'Alibaba', 'ALYac', 'Antiy-AVL', 'APEX', 'Arcabit',
                  'Avast', 'Avast-Mobile', 'AVG', 'Avira', 'Baidu', 'BitDefender', 'Bkav', 'CAT_QuickHeal',	'ClamAV',
                  'CMC', 'Comodo', 'crowdstrike', 'Cybereason', 'Cylance', 'Cyren', 'DrWeb', 'eGambit', 'Emsisoft',
                  'Endgame', 'ESET-NOD32', 'FireEye', 'Fortinet', 'F-Prot', 'F-Secure', 'GData', 'Ikarus', 'Invincea',
                  'Jiangmin', 'K7AntiVirus', 'K7GW', 'Kaspersky', 'Kingsoft', 'Malwarebytes', 'MAX', 'MaxSecure',
                  'McAfee', 'McAfee-GW-Edition', 'microsoft', 'Microworld_eScan', 'NANO-Antivirus', 'Paloalto', 'Panda',
                  'Qihoo-360', 'Rising', 'Sangfor', 'SentinelOne', 'Sophos', 'SUPERAntiSpyware', 'Symantec', 'TACHYON',
                  'Tencent', 'TotalDefense', 'Trapmine', 'TrendMicro', 'TrendMicro-HouseCall', 'VBA32', 'VIPRE',
                  'ViRobot', 'Webroot', 'Yandex', 'Zillya', 'ZoneAlarm', 'Zoner']

REDUCED_VENDOR_LIST = ['bitdefender', 'clamav', 'crowdstrike', 'cybereason', 'cylance', 'cyren', 'endgame', 'eset-nod32',
                          'fireeye', 'fortinet', 'kaspersky', 'malwarebytes', 'mcafee', 'microsoft', 'paloalto',
                          'sentinelone', 'sophos', 'symantec', 'trendmicro', 'webroot']

'''
Executables: peexe, pedll, neexe, nedll, mz, msi, com, coff, elf, krnl, rpm, linux, macho, dmg.
Internet: html, xml, flash, fla, iecookie, bittorrent, email, outlook, cap.
Phones&tablets: symbian, palmos, wince, android, iphone.
Images: jpeg, emf, tiff, gif, png, bmp, gimp, indesign, psd, targa, xws, dib, jng, ico, fpx, eps, svg.
Video&audio: ogg, flc, fli, mp3, flac, wav, midi, avi, mpeg, qt, asf, divx, flv, wma, wmv, rm, mov, mp4, 3gp.
Documents: text, pdf, ps, doc, docx, rtf, ppt, pptx, xls, xlsx, odp, ods, odt, hwp, gul, ebook, latex.
Bundles: isoimage, zip, gzip, bzip, rzip, dzip, 7zip, cab, jar, rar, mscompress, ace, arc, arj, asd, blackhole, kgb.
Code: script, php, python, perl, ruby, c, cpp, java, shell, pascal, awk, dyalog, fortran, java-bytecode.
Apple: apple, mac, applesingle, appledouble, machfs, appleplist, maclib.
Miscellaneous: lnk, ttf, rom.
'''

FILETYPE_LIST = ['pe', 'macho', 'elf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pdf', 'compressed', 'zip', 'jar', 'rar']

REGEX_POSITIVES = r'^[0-6][0-9]?(\+|\-)?'
REGEX_SIZE = r'^[0-9][0-9]?(mb|kb)'