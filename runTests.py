import tenbIOcore as tc
import tenbSCcore as sc
import beautifyResults as br
import datetime
import time
import json

# file and directory locations
key_file="../io_keys.json" # location of your key file
sc_key_file="../sc_keys.json"
results_dir="results/" # the directory for your results
styles_dir="styles/" #style sheet location for web pages
output_file=results_dir+"statistics_by_tag.html"
results_file=results_dir+"vulns.json"

sc_keys=sc.read_SC_keys(sc_key_file)
api_keys=tc.read_keys(key_file,"sandbox")

# export some vuln data
num_assets=100
filters={
	"state":["fixed"],
	"severity":["critical","high","medium","low"]
#	"last_fixed":1648249791
	}
payload={
	"filters": filters,
	"num_assets": num_assets
}
chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,results_file)

results=br.read_json_file(results_file)
count=0
for x in results:
	ff=x["first_found"]
	lf=x["last_fixed"]
	ipv4=x["asset"]["ipv4"]
	pid=x["plugin"]["id"]
	sev=x["severity"]
	ttfix=tc.date_diff(ff,lf)
	print(ipv4,sev,ttfix)
	count+=1
print(count)

now=datetime.datetime.now()
date_delta=datetime.timedelta(90)
back90=now-date_delta
unixtime90=datetime.datetime.timestamp(back90)
print(now)
print(back90)
print(unixtime90)
