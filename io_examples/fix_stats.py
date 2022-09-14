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
'''
This Python script analyses data for fixed vulnerabilities.
'''

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

html_file=reports_dir+"ttfix_stats.html"
json_file=results_dir+"fixed_vulns.json"

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
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,json_file)

# process the saved json files and generate html report
decoded=ut.calculate_fix_times(json_file)
results=[]
for x in decoded:
	data_subset=ut.dict_subset(x,('date','ttfix'))
	results.append(data_subset)
	

img_tag=chart.bar(results,[])

hr.gen_html_report(img_tag,html_file,styles_dir)

