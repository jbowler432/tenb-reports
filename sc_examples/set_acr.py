import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import tenbSCcore as sc
import datetime
import time
import json

# file and directory locations
key_file="../../io_keys.json" # location of your key file
sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages

'''
Resets the ACR for a supplied hostname. Can be converted into a bulk update routine
by simply iterating through a list of hostnames.
'''

sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)
# provide the ids of the repos you want to include

querystring={
	'limit':9000
}

'''
Iterates through a list of assets and retrieves the uuid for a given hostname
'''
decoded=sc.get_hosts(sc_server,port,token,cookies,querystring)
id=''
uuid=''
hostname="pa200.dc.demo.io"
for x in decoded["response"]:
	name=x["name"]
	if name==hostname:
		id=x['id']
		uuid=x['uuid']
		print(x,"\n")

'''
Update the ACR for the supplied uuid
'''
new_acr=10
querystring = {
	"overwrittenScore": new_acr,
	"reasoning": [
	{
	  "id": 1,
	  "label": "Why score was changed"
	}
	],
	"notes": "Some details on the score change",
	"overwritten": "true"
}
decoded=sc.set_acr(uuid,sc_server,port,token,cookies,querystring)
print(decoded)

sc.close_session(sc_server,port,token,cookies)
