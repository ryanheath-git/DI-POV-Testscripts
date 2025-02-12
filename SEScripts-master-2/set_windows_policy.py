"""
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
import os

import requests
import argparse
import logging
import json

DI_API_URL = 'https://{console_url}/api/v1'


def commit_policy(console_api_url, api_connector, policyid, policydata):
    '''

    Args:
        api_base_url:
        api_connector:
        policyid:
        policydata:

    Returns:

    '''
    response = requests.get(f'{console_api_url}/policies/{policyid}',
                            headers={'Authorization': api_connector}).json()
    print(f'Attempting change to policy "{response["name"]}" on "{response["msp_name"]}"')

    response = requests.put(f'{console_api_url}/policies/{policyid}/data',
                            headers={'Authorization': api_connector},
                            json=policydata)

    if response.status_code == 204:
        response = requests.get(f'{console_api_url}/policies/{policyid}',
                                headers={'Authorization': api_connector}).json()
        currentPolicy = requests.get(f'{console_api_url}/policies/{policyid}/data',
                                     headers={'Authorization': api_connector}).json()['data']

        in_memory_protection = ("On" if currentPolicy["in_memory_protection"] else "Off")
        print(f'Successful policy change for "{response["name"]}" on "{response["msp_name"]}" updated.')
        print(f'  Using Deep Instinct Management Console API:')
        print(f'     {console_api_url}')
        print(f'=====Policy is now ================================================================')
        print(f'        Static Analysis \n'
              f'            Prevention: {currentPolicy["prevention_level"]} \n')
        print(f'        Behavioral Analysis\n'
              f'            Ransomware Behavior: {currentPolicy["ransomware_behavior"]}\n'
              f'            In Memory Protection: {in_memory_protection}\n'
              f'                Arbitrary Shellcode: {currentPolicy["arbitrary_shellcode_execution"]}\n'
              f'                Remote Code Injection: {currentPolicy["remote_code_injection"]}\n'
              f'                Credential Dumping: {currentPolicy["credentials_dump"]}\n'
              f'                Known Payload Execution: {currentPolicy["known_payload_execution"]}\n'
              '====================================================================================')

    elif response.status_code == 400:
        logging.error(f'Policy model invalid')
    elif response.status_code == 404:
        logging.error(f'Policy not found for policy id: {policyid}')
    elif response.status_code == 422:
        logging.error(f'Invalid value')
    elif response.status_code == 403:
        logging.error("API connector needs Full Access to change policy.")
    else:
        logging.error(f'{response.reason}')


def get_policy_id_from_policy_name(console_api_url, api_connector, policy_name):
    '''

    Args:
        console_api_url:
        api_connector:
        policy_name:

    Returns:

    '''
    policies = requests.get(f'{console_api_url}/policies',
                            headers={'Authorization': api_connector}).json()
    for policy in policies:
        if policy['name'] == policy_name:
            return policy['id']
    return -1


def read_policy(console_api_url, api_connector, policy_id):
    '''

    Args:
        console_api_url:
        api_connector:
        policy_id:

    Returns:

    '''
    current_policy = requests.get(f'{console_api_url}/policies/{policy_id}/data',
                                  headers={'Authorization': api_connector}).json()
    return current_policy


def main():
    """Download the top-n results of a given Intelligence search."""
    parser = argparse.ArgumentParser(description="""Sets Deep Instinct Windows policy.  This script will set policy to 
    'default' settings as defined in the file json/defaultwindowspolicydata.json.  Users of this script have two options
     to modify the settings: 1) sending this script a json file describing new policy via --pdmfile (e.g.:
     python set_windows_policy.py 37 --pdmfile json/testwindowspolicydata.json), or 2) changing 
     individual parameters using the optional arguments (e.g.: 
     python set_windows_policy.py 37 --prevention_level DISBALED --ransomware_behavior PREVENT). 
    """,
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)

    parser.add_argument("console_url", help="Console URL")
    parser.add_argument("policy_id", help="Policy ID to update")
    required_named = parser.add_argument_group('required named arguments')
    required_named.add_argument("-a", "--api_connector", dest="api_connector",
                                help='Deep Instinct API Connector')
    parser.add_argument("-f", "--pdmfile", dest="policydatamodelfile",
                        help="filepath to a policy data model JSON file ")
    parser.add_argument("-p", "--prevention_level", dest="prevention_level",
                        help="Sets Static Analysis Prevention level",
                        choices=['DISABLED', 'LOW', 'MEDIUM', 'HIGH', 'VERY_HIGH'])
    parser.add_argument("-r", "--ransomware_behavior", dest="ransomware_behavior",
                        help="Sets Ransomware Behavior ",
                        choices=['ALLOW', 'DETECT', 'PREVENT'])
    parser.add_argument("-i", "--in_memory_protection", dest="in_memory_protection",
                        help="Enable/disable In Memory Protection",
                        choices=['True', 'False'])
    parser.add_argument("-c", "--remote_code_injection", dest="remote_code_injection",
                        help="Sets Remote Code Injection ",
                        choices=['ALLOW', 'DETECT', 'PREVENT'])
    parser.add_argument("-k", "--known_payload_execution", dest="known_payload_execution",
                        help="Sets Known Payload Execution",
                        choices=['ALLOW', 'PREVENT'])
    parser.add_argument("-s", "--arbitrary_shellcode_execution", dest="arbitrary_shellcode_execution",
                        help="Sets Arbitrary Shellcode Execution",
                        choices=['ALLOW', 'DETECT', 'PREVENT'])
    parser.add_argument("-d", "--credentials_dump", dest="credentials_dump",
                        help="Sets Credentials Dumping",
                        choices=['ALLOW', 'DETECT', 'PREVENT'])

    args = parser.parse_args()
    prevention_level = args.prevention_level
    ransomware_behavior = args.ransomware_behavior
    in_memory_protection = args.in_memory_protection
    remote_code_injection = args.remote_code_injection
    known_payload_execution = args.known_payload_execution
    arbitrary_shellcode_execution = args.arbitrary_shellcode_execution
    credentials_dump = args.credentials_dump

    console_api_url = DI_API_URL.format(console_url=args.console_url)
    api_connector = args.api_connector

    policy_id = args.policy_id
    if not args.policy_id.isnumeric():
        policy_id = get_policy_id_from_policy_name(console_api_url, api_connector, policy_id)

    new_policy_data = None
    if (args.policydatamodelfile is not None) and os.path.isfile(args.policydatamodelfile):
        # a file was supplied for setting policy
        with open(args.policydatamodelfile, 'r') as policyfile:
            data = policyfile.read()
        # parse file
        new_policy_data = json.loads(data)
    else:
        # arguments were supplied to change individual policy settings
        # read current policy, makes changes and call API commit changes
        new_policy_data = read_policy(console_api_url, api_connector, policy_id)

        if prevention_level is not None:
            new_policy_data['data']['prevention_level'] = prevention_level
        if ransomware_behavior is not None:
            new_policy_data['data']['ransomware_behavior'] = ransomware_behavior
        if in_memory_protection is not None:
            new_policy_data['data']['in_memory_protection'] = in_memory_protection
        if remote_code_injection is not None:
            new_policy_data['data']['remote_code_injection'] = remote_code_injection
        if known_payload_execution is not None:
            new_policy_data['data']['known_payload_execution'] = known_payload_execution
        if arbitrary_shellcode_execution is not None:
            new_policy_data['data']['arbitrary_shellcode_execution'] = arbitrary_shellcode_execution
        if credentials_dump is not None:
            new_policy_data['data']['credentials_dump'] = credentials_dump

    commit_policy(console_api_url, api_connector, policy_id, new_policy_data)


if __name__ == '__main__':
    main()
