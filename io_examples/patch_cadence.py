import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import tenbSCcore as sc
import beautifyResults as br
import datetime
import time
import json

# file and directory locations
key_file="../../io_keys.json" # location of your key file
sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"
output_file=reports_dir+"patching_cadence.html"

fixed30=results_dir+"fixed30.json"
fixed90=results_dir+"fixed90.json"

sc_keys=sc.read_SC_keys(sc_key_file)
api_keys=tc.read_keys(key_file,"uni")

get_new_data = 0

if get_new_data==1:
	# export fixed data for last 30 days
	num_assets=500
	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"]
	#	"last_fixed":1648249791
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,fixed30)

	# export fixed data for last 90 days
	unixtime=tc.unix_time(90)
	num_assets=500
	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"],
		"last_fixed":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,fixed90)

# process the saved json files and generate html report

#patch90=br.get_ttf_averages(fixed90)
patch90=br.get_ttf_averages_vpr(fixed90)

#patch30=br.get_ttf_averages(fixed30)
#patch30=br.get_ttf_averages_vpr(fixed30)

#br.patch_cadence_report(patch30,patch90,output_file,styles_dir)
