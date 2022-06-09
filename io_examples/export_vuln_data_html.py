import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import beautifyResults as br
import datetime

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages

# export some vuln data
num_assets=50
filters={}
results_file=result_dir+"vulns.json"
api_keys=tc.read_keys(key_file,"sandbox")
chunk_results=tc.check_and_download_vuln_chunks(api_keys,filters,num_assets,results_file)

# produce html report off downloaded data
br.vuln_result_summary(results_dir+"vulns.json",results_dir+"vulns_summary.html",styles_dir)
