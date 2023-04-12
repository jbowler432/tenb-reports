import tenbIOcore as tc
import tenbSCcore as sc
import htmlRoutines as hr
import reportTemplates as rt
import datetime
import time
import json
import utilities as ut


# file and directory locations
key_file="../io_keys.json" # location of your key file
sc_key_file="../sc_keys.json"
results_dir="results/" # the directory for your results
reports_dir="report_samples/" # the directory for your results
styles_dir="styles/" #style sheet location for web pages
html_file=reports_dir+"runtests.html"
json_file=results_dir+"runtests_vulns.json"

'''
#SC
decoded=ut.read_json_file("powerBI/raw/vulns_2.json")
#ut.print_pretty_dict(decoded,0,1)
#print(decoded)
for x in decoded["response"]["results"]:
	print(x["pluginID"],x["ip"],hr.clean_string(x["pluginText"]))
'''

#IO
decoded=ut.read_json_file("powerBI/raw/vulns_1.json")
ut.print_pretty_dict(decoded,0,1)
#print(decoded)

for x in decoded:
	output=""
	if "output" in x:
		output=hr.clean_string(x["output"])
	print(x["plugin"]["id"],x["asset"]["ipv4"],output)


'''
sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)
#decoded=sc.call_sc_query(sc_server,port,token,cookies)
decoded=sc.call_sc_hosts(sc_server,port,token,cookies)
print(decoded)
count=0
for x in decoded['response']:
	count+=1
print(count)
sc.close_session(sc_server,port,token,cookies)
'''

'''
api_keys=tc.read_keys(key_file,"sandbox")

get_new_data=0

if get_new_data==1:
	# export some vuln data
	num_assets=50
	filters={"cidr_range": "192.168.16.0/24"}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,json_file)


produce html report off downloaded data
rt.vulns_summary(json_file,html_file,styles_dir)
'''
