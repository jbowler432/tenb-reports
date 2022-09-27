import tenbIOcore as tc
import tenbSCcore as sc
import htmlRoutines as hr
import reportTemplates as rt
import datetime
import time
import json


# file and directory locations
key_file="../io_keys.json" # location of your key file
sc_key_file="../sc_keys.json"
results_dir="results/" # the directory for your results
reports_dir="report_samples/" # the directory for your results
styles_dir="styles/" #style sheet location for web pages
html_file=reports_dir+"runtests.html"
json_file=results_dir+"runtests_vulns.json"

sc_keys=sc.read_SC_keys(sc_key_file)

sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)
decoded=sc.call_sc_query(sc_server,port,token,cookies)
print(decoded)
sc.close_session(sc_server,port,token,cookies)




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
