import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import utilities as ut
import reportTemplates as rt
import datetime
import json

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

get_new_data=0
results_file=results_dir+"software_bom_io.json"
html_file=reports_dir+"software_bom_io.html"

if get_new_data==1:
	# export some vuln data
	num_assets=5000
	#plugin_id=[10180] # Ping the remote host
	#plugin_id=[19506] # Nessus Scan Information
	plugin_id=[22869,20811,83991] # installed software
	filters={"plugin_id":plugin_id}
	include_unlicensed=True
	#filters={}
	payload={
		"filters": filters,
		"num_assets": num_assets,
		"include_unlicensed": include_unlicensed
	}
	api_keys=tc.read_keys(key_file,"sandbox")
	decoded=tc.check_and_download_vuln_chunks(api_keys,payload,results_file)
	software=[]
	for results in decoded:
		os=""
		if len(results["asset"]["operating_system"])>0:
			os=results["asset"]["operating_system"][0]
		software.append({"os":os,"hostname":results["asset"]["hostname"],"ipv4":results["asset"]["ipv4"],"pluginID":results["plugin"]["id"],"output":results["output"]})
	with open(results_file,'w') as outfile:
		json.dump(software,outfile)

'''
Generate the html report from the downloaded data
'''
rt.software_bom(results_file,html_file,styles_dir)
