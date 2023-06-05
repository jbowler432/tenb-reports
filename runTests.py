import tenbIOcore as tc
import tenbSCcore as sc
import htmlRoutines as hr
import reportTemplates as rt
from datetime import datetime
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

api_keys=tc.read_keys(key_file,"sandbox")
decoded=tc.list_scanners(api_keys)
for x in decoded['scanners']:
	lc=x['last_connect']
	if lc != None:
		dt = datetime.fromtimestamp(lc)
		print(x['name'],lc,dt)
