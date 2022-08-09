import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import beautifyResults as br
import datetime

'''
Uses the export APIs to download the vulnerabilty database as
a json file. Reads the downloaded json file to produce to custom
html reports. One is a summary and the other a detailed report.
The detailed report can be dynamically expanded to show all the
vulnerability details.
'''

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

get_new_data=1

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

# produce html report off downloaded data
br.vuln_result_summary(results_dir+"vulns.json",reports_dir+"vulns_summary.html",styles_dir)
br.vuln_result_detailed(results_dir+"vulns.json",reports_dir+"vulns_detailed.html",styles_dir)
