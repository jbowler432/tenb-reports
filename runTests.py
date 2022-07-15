import tenbIOcore as tc
import tenbSCcore as sc
import beautifyResults as br
import datetime
import time
import json

# file and directory locations
key_file="../io_keys.json" # location of your key file
sc_key_file="../sc_keys.json"
results_dir="results/" # the directory for your results
styles_dir="styles/" #style sheet location for web pages
output_file=results_dir+"statistics_by_tag.html"
results_file=results_dir+"vulns.json"

api_keys=tc.read_keys(key_file,"sandbox")

sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)
#filters= [{'filterName': 'repository', 'operator': '=', 'value': [{'id': '4'},{'id': '6'}]}]
#filters=[]

decoded=sc.add_sc_asset_static(sc_server,port,token,cookies,"tag9","192.168.50.45,10.0.23.99,")
print(decoded)
'''
print(" ")
for x in decoded["response"]["manageable"]:
	id=str(x["id"])
	name=str(x["name"])
	if name=='tag1':
		asset=sc.call_sc_asset_id(sc_server,port,token,cookies,id)
		print(id,name)
		print(asset)
'''

sc.close_session(sc_server,port,token,cookies)
