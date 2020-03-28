import sys
import base64
import requests
import argparse
import json
import os
import time

parser = argparse.ArgumentParser(description='Import SIEM detection rules into Kibana')
parser.add_argument('--kibana', type=str)
parser.add_argument('--elasticsearch', type=str)
args = parser.parse_args()

kibana_api_test = args.kibana+'/api/features'
siem_url = args.kibana+'/api/detection_engine/rules/_import?overwrite=true'
headers = {
  'kbn-xsrf': 'kibana'
  }

artifacts_path = './es-rules-output/'
directory = os.fsencode(artifacts_path)

exit_code = 0

# This index (alias to be precise) must exist in order for Kibana to actually do the import, normally it is created by Kibana but that requires X-Pack Security to be configured, this hack will trick Kibana into doing the import
dummy_index_url = args.elasticsearch+'/.siem-signals-default'
response = requests.put(dummy_index_url)
print("Creating dummy .siem-signals-default")
if not response.ok:
    print("Error: Failed to create dummy .siem-signals-default index")
    sys.exit(1)

# Wait for Kibana service to start properly
for i in range(10):
    print("Waiting for Kibana API to become available")
    response = requests.get(kibana_api_test, headers=headers)
    if response.status_code == 503:
        print(response.text)
        time.sleep(10)
    else:
        print("Kibana API is ready")
        break

for sigma_rule in os.listdir(directory):
    filename = os.fsdecode(sigma_rule)
    if filename.endswith(".ndjson"):
        with open(os.path.join(artifacts_path, filename), 'rb') as ndjson_file:
            files = {'file': (filename, ndjson_file, 'application/octet-stream')}
            print("Importing " + filename, end=": ")
            response = requests.post(siem_url, headers=headers, files=files)
            if response.ok:
                response_json = json.loads(response.text)
                if response_json['success']:
                    print("Success")
                else:
                    print("Failed")
                    print(response.text)
                    exit_code = 1
            else:
                exit_code = 1
                print(response.text)
sys.exit(exit_code)
