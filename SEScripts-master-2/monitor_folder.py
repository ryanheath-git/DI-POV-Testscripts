#!/usr/bin/python3
#
'''
See readme.md for information on this script.

Requirements: see requirements.txt

Disclaimer:
This code is provided as an example of how to build code against and interact
with the Deep Instinct Agentless Connector REST API. It is provided AS-IS/NO WARRANTY. It has
limited error checking and logging, and likely contains defects or other
deficiencies. Test thoroughly first, and use at your own risk. This is not a Deep Instinct
commercial product and is not officially supported, although the underlying REST API is.
'''
#from deepinstinct_rest_api_wrapper import deepinstinctagentless as dia

import argparse
import os
import sys
import time
import requests
import base64
from watchdog.observers import Observer
from watchdog.events import PatternMatchingEventHandler
import urllib3
import pathlib
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


AGENTLESS_CONNECTOR_PORT = 5000
protocol = 'https'
file_patterns = ["*"]

# borrowed from PVZ - needed this script to be a standalone
'''
equivalent curl command
curl -s -k -X POST -H 'Content-Type: application/octet-stream' --data-binary @filename.exe https://localhost.localdomain:5000/scan/binary

'''
def scan_file(file_name, scan_url, encoded=False):
    # read file from disk. rb means opens the file in binary format for reading
    with open(file_name, 'rb') as f:
        #read file
        data = f.read()
        #close file
        f.close()

    if encoded:
        #encode data and set URL to match
        data = base64.b64encode(data)
        request_url = f'{scan_url}/scan/base64'
    else:
        #leave data as-is and set URL to match
        request_url = f'{scan_url}/scan/binary'

    # send scan request, capture response
    response = requests.post(request_url, data=data, timeout=20, verify=False)

    # validate response code, return verdict as Python dictionary
    if response.status_code == 200:
        verdict = response.json()
        return verdict
    else:
        print('ERROR: Unexpected return code', response.status_code,
        'on POST to', request_url)
        return None


def scan_file_encoded(file_name, scan_url):
    return scan_file(file_name, scan_url, encoded=True)


class AgentlessFileEventHandler(PatternMatchingEventHandler):

    def __init__(self, file_patterns, ignore_patterns, ignore_directories, case_sensitive, scan_url, log_results):
        super(AgentlessFileEventHandler, self).__init__(file_patterns,ignore_patterns,ignore_directories,case_sensitive)
        self.scan_url = scan_url
        self.log_results = log_results


    def on_modified(self, event):
        filename = event.src_path
        if not os.path.isfile(filename):
            return

        print(f"{filename} has been detected... scanning ")
        result = scan_file(filename, self.scan_url)
        print(result)
        if (result["verdict"] == "Malicious"):
            if os.path.isfile(filename):
                print (f"Removing file: {filename}")
                os.remove(filename)
                with pathlib.Path(self.log_results).open('a') as f:
                    f.write(f'{result["file_hash"]},{result["verdict"]},{result["file_type"]}\n')


def main():
    parser = argparse.ArgumentParser(description="""Monitor folder for file creation/modification and send to agentless connector""",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter,
                                     epilog="")
    parser.add_argument("-f", "--folder", dest="folder", default=pathlib.Path.home() / 'Downloads', help='folder to monitor')
    parser.add_argument("-c", "--connector", dest="connector", default="127.0.0.1",
                        help='ipaddress of agentless connector')
    parser.add_argument("-o", "--output", dest="output",
                        default=pathlib.Path.cwd() / f'monitor_folder_output_{time.strftime("%Y%m%dT%H%M%S")}.csv',
                        help='csv output of malicious verdicts')
    parser.add_argument("-i", "--protocol", action='store_true',
                        help='use http instead of https')


    args = parser.parse_args()
    if args.protocol:
        protocol = 'http'
    else:
        protocol = 'https'

    scan_url = f'{protocol}://{args.connector}:{AGENTLESS_CONNECTOR_PORT}'

    ignore_patterns = None
    ignore_directories = False
    case_sensitive = True

    output = pathlib.Path(args.output)
    try:
        with output.open('w') as f:
            pass
    except Exception as e:
        print(f'Unable to direct output to file: {output}. Please supply a valid filename. {str(e)}')
        sys.exit(-1)


    # my_event_handler = PatternMatchingEventHandler(file_patterns, ignore_patterns, ignore_directories, case_sensitive)
    my_event_handler = AgentlessFileEventHandler(file_patterns, ignore_patterns, ignore_directories, case_sensitive,
                                                 scan_url, output)

    go_recursively = True
    my_observer = Observer()
    folder = pathlib.Path(args.folder)
    if not folder.is_dir():
        print(f'ERROR: {folder} is not a valid folder path to monitor')
        sys.exit(-1)

    my_observer.schedule(my_event_handler, folder, recursive=go_recursively)

    print(f'URL in use: {scan_url}')
    print(f"Monitoring: {folder}")
    print(f'Output:     {output}')
    my_observer.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        my_observer.stop()
        my_observer.join()

    
if __name__ == '__main__':
    main()
    
    
