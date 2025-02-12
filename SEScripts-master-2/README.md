# SEScripts

## Prerequisites
All scripts tested with python 3.8 and above.  Install python 3.8 or later.
Make sure pip gets installed.  You'll need it to install other python modules.

### Install required modules 

Required modules are listing in the requirements.txt file.  They can be installed using pip and this file as follows:

- `pip install -r requirements.txt`

Note: each script requires some or all of these modules, i.e., some may only need the requests module.  

## Global configuration
All scripts below accept arguments for necessary configuration, such as, your Virus Total API key, testing folders and download folders.
As a convenience, there is a conf/config_template.json file, which you can copy, edit and save as config.json within that same directory.  
Here you can add configuration details, simply to avoid having to enter that information on the command line as arguments.  
Note that any arguments passed when running scripts will override configuration defined in the conf/config.json file.

Example:
```
{
  "virustotal": {
    "api_key": "fda123..."
  },

  "downloader": {
    "test_folder": "/Volumes/[C] Windows 10/Users/IEUser/Downloads/TestArea",
    "collection_folder": "/Volumes/[C] Windows 10/Users/IEUser/Downloads/CollectionArea"
  },
}
```

- *test_folder* is the default value for the --testpath argument used by test_detection and sample_collector scripts
- *collection_folder* is the default value for the --outpath argument used by malware_downloader, test_detection and sample_collector scripts

NOTE: For ease of use, use Unix-style filepaths ('/') even for Windows directories/folders, which the scripts handles even on Windows.
Single backlash ('\') will be interpreted as an escape to the next character, and will not work without double-backslash ('\\') 

This configuration file is read for default configuration for all the runnable scripts 
(malware_downloader, test_detection and sample_collector scripts).

These default values are overridden if commandline arguments are used.

## Script Help
Note that most scripts have help, which can be accessed via running the script with -h or –-help:
```
python3 malware_downloader.py --help
usage: malware_downloader.py [-h] [-a APIKEY] [-n NUMFILES] [-o OUTPATH] [-r {VT,VT3,MB}] [-f FILEFORMAT] [-z ZIP] samples [samples ...]

Download the top-n files returned by a given VirusTotal Intelligence search. Not limited to 100. Example: python %prog -a <Virus Total api key> -n 10 type:"peexe"
positives:5+

positional arguments:
  samples               or a list of hashes or a file with hashes

optional arguments:
  -h, --help            show this help message and exit
  -a APIKEY, --apikey APIKEY
                        API KEY, if needed (default: faf7adc6a15d12daf925293d2bde08b976d8db221a10b92434a9336f6d39cb11)
  -n NUMFILES, --numfiles NUMFILES
                        maximum number of files to download (default: 10)
  -o OUTPATH, --outpath OUTPATH
                        path for downloaded files (default: /Volumes/[C] Windows 10/Users/IEUser/Downloads/Collections)
  -r {VT,VT3,MB}, --repository {VT,VT3,MB}
                        choice of repository for malware searches and downloads (default: VT3)
  -f FILEFORMAT, --fileformat FILEFORMAT
                        using this switch will rename the downloaded file based on information returned from the repository. Options include {file_hash}, {file_name},
                        {first_seen}, {file_ext}, {file_class} and any other valid filename characters. For example: {file_name}_{file_seen}_{file_class}.{file_ext}
                        (default: {file_hash})
  -z ZIP, --zip ZIP     alternative to save downloaded files to an encrypted zipfile with the supplied name. (default: None)
```

## Running the Scripts
All scripts require python 3.7+.  In the following examples, I have only specified that to run the scripts via command such as:
```
python script_name.py ...
```
You should check on the environment's default python as many Linux/macOS based systems come preinstalled with python 2.7.  You can check with the following command:
```
python -V
```
If the version is anything less than 3.7, you will need to explicitly call python 3, which can be done like so:
```
python3
```
or
```
/usr/bin/env python3
```

## The Scripts
### demo_setup.py
Used to create bat files for use during demos.  Simply run the script and answer the questions (or choose the defaults). 

#### Run
```
python demo_script.py
```

This script will ask for the following and check that the answers are valid:
- Virus Total API key - the Virus Total API key to use
	- Depending on whether the key is a public or private key, some or all .bat files will be created
- User will then be asked if they will be testing behavioral analysis, which requires changing DI policy
- Deep Instinct Management Console URL
- Policy Name - For API connectors that can have more than one policy with the same name (e.g., "Windows Default Policy") this script will list the policies by MSP name and request the user for the ID to use.  
- API Connector - the DI API connector to use

Defaults for all of these questions can be supplied in the config.py file.


### malware_downloader.py
Search and download files via a search or a list of hashes supplied on the command line or in a file.

The option exists to download files straight to disk, or directly to an encrypted zipfile.
The former method means that malicious files downloaded will be caught by Deep Instinct.  The latter options will
download files straight to an encrypted zip which will not be detected by Deep Instinct.  This file can then be shared 
with a customer.  Note: need to use a tool like 7-zip to extract zip file, which is password protected with the password 
'infected'.


#### Examples

*Download 50 samples to disk from a search:*
Download files to the directory C:\User\IEUser\Downloads\Malware (specified with the -o option), with the api key (-a blahblahblah…), 
and the last part is the virus total search:

```
python malware_downloader.py -n 50 -o C:/Users/IEUser/Downloads/Malware -a <virus total api key> fs:2020-06-30+ type:pe p:30+ engines:ransomware
```
NOTE: this download of malware will trigger Deep Instinct if installed and enabled.  Output will display where the files (should be unless prevented) are downloaded:
```
The downloaded files have been saved in C:/Users/IEUser/Downloads/Malware
```

*Download files via command line argument of hashes (SHA256, SHA1, MD5):*
```
python malware_downloader.py -n 50 -o C:/Users/IEUser/Downloads -a <virus total api key> afakehash1 afakehash2 afakehash3
```
NOTE that the list of hashes should be delimited (i.e. spaces or commas between each hash), but generally it should not 
matter how it's delimited.

*Download files via a file of hashes (SHA256, SHA1, MD5):*
```
python malware_downloader.py -n 50 -o C:/Users/IEUser/Download -a <virus total api key> path/to/file_of_hashes.txt
```
NOTE that file of hashes typically does not need to be cleaned up.  As long as the hashes "standalone" (i.e. there's 
non-alphnumeric characters (space, symbols, comma, etc...) preceding or trailing the hash), then generally the hashes should 
be parsed correctly from the file.  See the file: examples/resources/hashes.txt for a file example. 

*Search and download files, but now the files go into an encrypted zipfile:*  
This zipfile uses the winzip AES 
standard. Unfortunately the default archive managers on Windows, Mac and Linux can not decrypt these files. 
You must use a tool like 7zip, winzip (Windows) or Unarchiver (Mac) to unzip this zipfile.

```
python malware_downloader.py -n 50 -o C:\Users\IEUser\Downloads -a <Virus Total API Key> -z zipfilename fs:2020-06-30+ type:pe p:30+ engines:ransomware
``` 

*Download samples to an encrypted zipfile:*  
Note that the input to this script is a CSV file of hashes.  
This is ideal for building POV datasets as the downloaded files go directly into an encrypted zipfile an 
undetectable by Deep Instinct (until extracted). Use extract_hashes_from_demo_dataset.py (shown above) 
to create the CSV file to use. 

NOTE: the encryption process greatly increases the time to download.  In cases of large data sets (> 50) it may be better to disable endpoint clients (that includes Defender of Windows) and download files direct to disk and zip and encrypt the files after.

```
python malware_downloader.py -n 50 -o C:/Users/IEUser/Download -a <Virus Total API Key> -z zipfilename PDF_2021-06-12_to_2021-06-12__500_hashes.csv
```


### monitor_folder.py
monitor_folder.py monitors a folder on the local system where this script is run, 
and sends files written to this folder to a prevention platform (agentless) RestAPI 
server listing on port 5000.  Files receiving malicious verdicts will be deleted.

#### Running the Script
To use the script, supply the arguments (which can be found by running: python monitor_folder.py --help) 
or use the defaults provided.

Example:
```
python monitor_folder.py -f /home/logangilbert/Downloads -c 127.0.0.1  
```

Which outputs:
```
URL in use: https://127.0.0.1:5000
Monitoring: /Users/logang/Downloads
Output:     /Users/logang/Desktop/monitor_folder_output_20211215T141854.csv
```
- URL in use - is the ip address:ip port of the server/docker container
- Monitoring - represents the local folder being monitored
- Output - is comma separated list of files scanned, verdict and filetype

The output is intended for use in collecting samples of hashes that can later be used to build sample 
datasets for POVs and tests.  You can override the default output file:

```
python monitor_folder.py -f C:/Users/IEUser/Downloads -c 127.0.0.1 -o filename.csv  
```
NOTE: For ease of use, use Unix-style filepaths ('/') even for Windows directories/folders, which the scripts handles even on Windows.
Single backlash ('\') will be interpreted as an escape to the next character, and will not work without double-backslash ('\\') 

Once run, the script will then wait for scans to occur and output any file detected and scan results.  
Files receiving malicious verdicts will be deleted.  This script will control the console from this 
point until a Ctrl-C or similar is issued to kill the process.

When a file is dropped on the Monitored folder:
- the file is sent to the agentless server,
- the file verdict is output to the console where the script is run 
- the file is deleted from the folder if the verdict is a malicious file
- Hash, verdict and file type is collected in the output file 

The most seamless way to use this script is to configure the monitored folder to the same path that a 
Virus Total download or a malware_downloader.py will download files to.  Otherwise, one can 
simply copy files over to the downloads_folder area.

'''
'''

### test_detection.py
This script uses malware_downloader.py to download files from VT and track what Deep Instinct does and does not detect on. 

#### Running the Script

```
python3 test_detection.py -n 50 -o C:/Users/IEUser/Downloads -a <virus total api key> fs:2020-06-30+ type:pe p:30+ engines:ransomware
```

In this case, the downloaded files are tracked what Deep Instinct does and does not detect on 
(assuming you are in prevent mode).  

The output will be written to stdout and as text files in a folder (either under where the script was run, or as specified by the -o argument).  When you look in the output folder you'll see three files: 
- query.txt - the query that was run
- detected.txt - hashes of all detected files
- undetected.txt - hashes of all undetected files

detected and undetected txt files can be feed to Virus Total directly, or as an input to malware_downloader.py.

Examples:

Run script and download files to a Windows virtual machine (example shows a shared folder from the guest VM to the host device).
Note p:15+ (more likely that samples are missed by other vendors)
```
-o "/Volumes/[C] Windows 10/Users/IEUser/Downloads" -n 125 fs:2021-10-05+ type:pe p:15+ size:1MB- AND NOT tag:corrupt
```

### sample_collector.py
Combines the functions of the test_detection and malware_downloader scripts into an interactive tool for collecting samples sets for use in POVs.  
sample_collector lets users create one or more sample datasets, where each dataset is created by downloading files from Virus Total based
on criteria supplied by the user, all files downloaded will be tested for prevention by Deep Instinct.  Files prevented by Deep Instinct are
then collected into a resulting sample collection. 

You will need a setup where the D-Client can scan files, and an area that's ignored by the D-Client.    

In my setup, I have a Windows VM, with the D-Client installed.  In this D-Client's policy, I have folder exclusion like so:
"C:\Users\IEUser\Downloads\Collections".  When running the sample_collector script, you will specify a "test" folder and a "collection" folder.
The test area is simply any folder that DI can scan, the collection area should be the excluded folder.


#### Running the Script

```
python sample_collector.py -a <virus total api key> -t '<path to test folder> -o '<path to collections folder>' 
```
- -a Virus Total API key
- -t Path for testing downloaded files - Deep Instinct should be able to scan this folder path.
- -o Path to save collected samples - Deep Instinct should NOT be able to scan this folder path.

Once the script is run, you will be asked a series of question; for each you can enter a value or hit enter to choose the default value:

*NOTE* each of these parameters can be configured in the conf/config.py file, if created (see Global Configuration above)

Example Interaction:
```
Enter the name for this sample collection or select an existing collection (default: sample_collection): 
        0.sample_collection 1.API_scripts_demo 2.samples-copy 3.SharpPack-master 
        Selection (default: 0): my_new_collection
Enter a name for this dataset or select an existing dataset to add more files (default: sample_dataset_1): 
        0.sample_dataset_1 
        Selection (default: 0): 0

        =======================================================
        Dataset: sample_dataset_1
        =======================================================
        Interactive mode? (default: yes): yes
        Entering interactive mode
                Search inputs:
                        First seen (in days ago) (default: 0): 
                        File type (either select from list or type entry) (default: pe): 
                                0.pe 1.macho 2.elf 3.doc 4.docx 5.xls 6.xlsx 7.ppt 
                                8.pdf 9.compressed 10.zip 11.jar 12.rar 
                                Selection (default: 0): 0
                        Positive verdicts (default: 35+): 
                        Size (0kb to 99mb) (default: 1mb-): 
                        Compare against vendor:clean? (default: no): yes
                        Vendor clean: 
                                0.bitdefender 1.clamav 2.crowdstrike 3.cybereason 4.cylance 5.cyren 6.endgame 7.eset-nod32 
                                8.fireeye 9.fortinet 10.kaspersky 11.malwarebytes 12.mcafee 13.microsoft 14.paloalto 15.sentinelone 
                                16.sophos 17.symantec 18.trendmicro 19.webroot 
                                Selection (default: 13): 2
                        Additional search attributes (note: NOT tag:corrupt automatically added))  (default: ): 
                Maximum files to test (default: 20): 50

        Dataset sample_dataset_1 will be tested and built on the search criteria:
                fs:2022-06-29+ type:pe p:35+ size:1mb- crowdstrike:clean  NOT tag:"corrupt" 
        with a maximum of 50 files
        =======================================================

Define another dataset (y/n) (default: n): 
```
Here, the first dataset will be called 'sample_dataset_1', and belongs to the collection 'my_new_collection'.

The script will continue to ask if you like to build another dataset.  Ultimately you will end up with a Collection and Datasets like this:
```
C:\Users\IEUser\Downloads\Collections   <-- this is the base folder for collections... this folder should be on a Folder Exclusion
            <collection name>
                    <dataset_1>
                    <dataset_2>
            POV_Billy_Bobs_BBQ
                    PEs_100samples_ransomware
                    Documents_100samples
                    Archives_10samples
```

#### Caveats and why didn't this work?
The first seen criteria defaults to "today".  Makes sure that the timespan will ensure 

#### Tricks to making a good sample collection:
* "Positive verdicts" p:number as low as 10+... since we are testing whether DI positively detects each sample, the results will be samples that DI prevents, and is missed by most other vendors
* When asked for "Additional search attributes" use size:1MB- (especially when testing executables).  All files tested 
will be under 1MB in size, which makes the sample collecting faster and also results in a manageable collection that can 
be shared with a customer.  Otherwise, you can end up with massive datasets can be well over a few GBs in size.
* Generally I would keep different file types separated from each other.   
* Remember that the defaults that work well for PEs, specifically first seen of only a day or so, and positive: set high, may not work as well for other file types  

### set_windows_policy.py
Provides an easy-to-use mechanism to set multiple policy switches simultaneously via the console API.  Useful for demos when client capabilities need to be quickly toggled on and off without having to go to the console.  There are a few preconfigured bat scripts available as well, to demonstrate how the script is run.

#### Prerequisites
- `pip install requests`

#### Running the Script

```
python set_windows_policy.py
```
