import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import utilities as ut
import htmlRoutines as hr
import pandas as pd
import datetime
import time
import json
import chart
import csv

'''
This Python script analyses data for fixed vulnerabilities.
'''

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

results_file=results_dir+"fixed_vulns.json"
results_file2=results_dir+"4powerBI_io.json"
csv_file=results_dir+"4powerBI_io.csv"

api_keys=tc.read_keys(key_file,"sandbox")

get_new_data = 0

if get_new_data==1:
	# export fixed data for last 90 days
	unixtime=ut.unix_time(90)
	num_assets=1000
	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"],
		"last_fixed":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,results_file)

# process the saved json files and generate html report
decoded=ut.read_json_file(results_file)
results=[]
for x in decoded:
	ip=x['asset']['ipv4']
	hostname=x['asset']['hostname']
	desc=x['plugin']['description']
	family=x['plugin']['family']
	pid=x['plugin']['id']
	pname=x['plugin']['name']
	try: patch_pub_date=x['plugin']['patch_publication_date']
	except: patch_pub_date=''
	fseen=x['first_found']
	lseen=x['last_found']
	lfixed=x['last_fixed']
	ttfix=ut.date_diff(fseen,lfixed)
	severity=x['severity']
	state=x['state']
	exploitable=x["plugin"]["exploit_available"]
	asset_id=x['asset']['uuid']
	try: pout=x['output']
	except: pout=''
	mydct={
		'ip':ip,
		'hostname':hostname,
		'desc':desc,
		'family':family,
		'pid':pid,
		'pname':pname,
		'patch_pub_date':patch_pub_date,
		'fseen':fseen,
		'lseen':lseen,
		'lfixed':lfixed,
		'ttf':ttfix,
		'asset_id':asset_id,
		'pout':pout,
		'severity':severity,
		'state':state,
		'exploitable':exploitable
	}
	results.append(mydct)

with open(results_file2,'w') as outfile:
	json.dump(results,outfile)

keys = results[0].keys()

with open(csv_file, 'w', newline='') as output_file:
    dict_writer = csv.DictWriter(output_file, keys)
    dict_writer.writeheader()
    dict_writer.writerows(results)
