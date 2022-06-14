import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import beautifyResults as br
import datetime

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages

# export some vuln data
num_assets=5000
#plugin_id=[10180] # Ping the remote host
#plugin_id=[19506] # Nessus Scan Information
plugin_id=[10863] # Certificate information
filters={"plugin_id":plugin_id}
include_unlicensed=True
#filters={}
payload={
	"filters": filters,
	"num_assets": num_assets,
	"include_unlicensed": include_unlicensed
}
results_file=results_dir+"vulns_by_plugin.json"
api_keys=tc.read_keys(key_file,"sandbox")
chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,results_file)

# produce html report off downloaded data
#br.vuln_result_summary(results_dir+"vulns.json",results_dir+"vulns_summary.html",styles_dir)
#br.vuln_result_detailed(results_dir+"vulns.json",results_dir+"vulns_detailed.html",styles_dir)
