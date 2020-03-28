import sys
import base64
import requests
import argparse
import json
import os

parser = argparse.ArgumentParser(description='Import SIEM detection rules into Kibana')
parser.add_argument('--kibana', type=str)
parser.add_argument('--elasticsearch', type=str)
args = parser.parse_args()

siem_url = args.kibana+'/api/detection_engine/rules/_import?overwrite=true'
headers = {
  'kbn-xsrf': 'kibana'
  }

artifacts_path = './es-rules-output/'
directory = os.fsencode(artifacts_path)

exit_code = 0

# This index (alias to be precise) must exist in order for Kibana to actually do the import, normally it is created by Kibana but that requires X-Pack Security to be configured, this hack will trick Kibana into doing the import
dummy_index_url = args.elasticsearch+'/.siem-signals-default'
print(dummy_index_url)
response = requests.put(dummy_index_url)
if not response.ok:
    print("Error: Failed to create dummy .siem-signals-default index")
    sys.exit(1)

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
