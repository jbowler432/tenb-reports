import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
#import beautifyResults as br
import utilities as ut
import datetime
import json
import pandas as pd
import re
import base64
import time
import chart
import htmlRoutines as hr

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

get_new_data=1
results_file=results_dir+"scan_stats.json"
html_file=reports_dir+"scan_stats.html"
image_file=results_dir+"scan_stats.png"

api_keys=tc.read_keys(key_file,"uni")

decoded=tc.list_scans(api_keys)
counter=0
for x in decoded['scans']:
	type=''
	uuid=''
	if 'type' in x:
		type=x['type']
	if 'uuid' in x:
		uuid=x['uuid']
	if x['status']=='completed':
		counter+=1
		print(x['name'],x['id'],type,x['status'],uuid,x['enabled'],x['owner'])
print(counter)

uuid="cebc4056-3b4f-4cd0-828e-2f88e15afa04"
id='817'
decoded=tc.list_scan_details(api_keys,id)
#print(decoded)
for (k,v) in decoded.items():
	print(k)
print(decoded['info'])
print(decoded['hosts'])

if get_new_data==1:
	# export some vuln data
	num_assets=5000
	unixtime=ut.unix_time(90)
	#plugin_id=[10180] # Ping the remote host
	#plugin_id=[19506] # Nessus Scan Information
	plugin_id=[19506]
	filters={
		"plugin_id":plugin_id,
		"scan_uuid":uuid
		}
	include_unlicensed=False
	#filters={}
	payload={
		"filters": filters,
		"num_assets": num_assets,
		"include_unlicensed": include_unlicensed,
		"last_found": unixtime
	}
	decoded=tc.check_and_download_vuln_chunks(api_keys,payload,results_file)
	print(decoded)

results=[]
decoded=ut.read_json_file(results_file)
for x in decoded:
	ipv4=""
	if 'ipv4' in x['asset']:
		ipv4=x['asset']['ipv4']
	output=x['output']
	scan_date=x['scan']['started_at'].split("T")[0]
	#print(scan_date,"\n",output,"\n")
	#for (k,v) in x.items():
	#	print(k,"\n",v)
	output_lines=output.split("\n")
	for y in output_lines:
		if "Scan Start Date" in y:
			#print(y)
			date_array=y.split("Scan Start Date : ")
			if len(date_array)>1:
				scan_date=date_array[1].split(" ")[0]
		if "Scan duration" in y:
			scan_times=re.findall(r'\b\d+\b',y)
			if len(scan_times)>0:
				#print(scan_time)
				scan_time=int(scan_times[0])
				mydct={'date':pd.to_datetime(scan_date),'scan_time':scan_time}
				results.append(mydct)

df=pd.DataFrame(results)
df=df.set_index('date')
print(df)

monthly_averages=df.resample('D').mean()
monthly_counts=df.resample('D').count()
print(monthly_averages)
print(monthly_counts)

colors={'scan_time':'#0070b6'}
img_tag=chart.bar2(monthly_averages,colors,90,['Average Scan Time'])
img_tag2=chart.bar2(monthly_counts,colors,90,['Hosts Scanned'])

# generate the html report
body_txt="\n<h1>Scan Statistics</h1>"
today=datetime.date.today()
report_desc="Shows the number of hosts scanned and the average scan time per host."
report_desc+="\n<br>("+str(today)+")"
body_txt+="<div class=reportdesc>"+report_desc+"</div>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Average Scan Times</h2>(per host in secs)<br>\n"
body_txt+=img_tag
body_txt+="</div>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Number of Hosts Scanned</h2>\n"
body_txt+=img_tag2
body_txt+="</div>"

hr.gen_html_report(body_txt,html_file,styles_dir)
