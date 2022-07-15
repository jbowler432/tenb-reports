import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import tenbSCcore as sc
import beautifyResults as br
import datetime
import time
import json

# file and directory locations
key_file="../../io_keys.json" # location of your key file
sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
output_file=results_dir+"statistics_by_tag.html"
results_file=results_dir+"vulns.json"

api_keys=tc.read_keys(key_file,"sandbox")

sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)
# provide the ids of the repos you want to include
filters= [{'filterName': 'repository', 'operator': '=', 'value': [{'id': '4'},{'id': '6'}]}]

decoded=sc.get_ip_list(sc_server,port,token,cookies,filters)
#print(decoded)

count=0
for x in decoded["response"]["results"]:
	print(x["ip"],x["uuid"],x["dnsName"],x["osCPE"])
	count+=1
print(str(count)+" records")

sc.close_session(sc_server,port,token,cookies)
