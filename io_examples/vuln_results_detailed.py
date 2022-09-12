import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import reportTemplates as rt
import pandas as pd
import utilities as ut
import datetime

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

json_file=results_dir+"vulns.json"
html_file=reports_dir+"vulns_detailed.html"

get_new_data=0

if get_new_data==1:
	# export some vuln data
	num_assets=50
	filters={}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	results_file=results_dir+"vulns.json"
	api_keys=tc.read_keys(key_file,"restricted")
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,results_file)

'''
produce html report off downloaded data
'''
rt.vulns_detailed(json_file,html_file,styles_dir)
