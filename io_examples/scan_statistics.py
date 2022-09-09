import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import beautifyResults as br
import utilities as ut
import datetime
import json
import pandas as pd
import re
import matplotlib.pyplot as plt
import base64
import time

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

get_new_data=0
results_file=results_dir+"scan_stats.json"
html_file=reports_dir+"scan_stats.html"
image_file=results_dir+"scan_stats.png"

if get_new_data==1:
	# export some vuln data
	num_assets=5000
	unixtime=ut.unix_time(90)
	#plugin_id=[10180] # Ping the remote host
	#plugin_id=[19506] # Nessus Scan Information
	plugin_id=[19506]
	filters={"plugin_id":plugin_id}
	include_unlicensed=False
	#filters={}
	payload={
		"filters": filters,
		"num_assets": num_assets,
		"include_unlicensed": include_unlicensed,
		"last_found": unixtime
	}
	api_keys=tc.read_keys(key_file,"sandbox")
	decoded=tc.check_and_download_vuln_chunks(api_keys,payload,results_file)

results=[]
decoded=ut.read_json_file(results_file)
for x in decoded:
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
#print(df.resample('D').mean())
#print(df.resample('D').count())

#df.resample('D').mean().plot()
#plt.savefig('output.png')

grouped=df.groupby(['date'])

results2=[]
j=0
for i in grouped.mean().index:
	#print(i,int(grouped.count().values[j][0]),int(grouped.mean().values[j][0]))
	results2.append({'date':i,'count':int(grouped.count().values[j][0]),'mean':int(grouped.mean().values[j][0])})
	j+=1

df2=pd.DataFrame(results2)
df2=df2.set_index('date')
df2.index.name="Date"
print(df2)
df2["count"].plot(label="Hosts Scanned", legend=True, marker='.')
df2["mean"].plot(secondary_y=True,label="Mean Scan Time/Host (sec)",legend=True,marker='.')
plt.savefig(image_file)

time.sleep(2)
today=datetime.date.today()

data_uri = base64.b64encode(open(image_file, 'rb').read()).decode('utf-8')
img_tag = '<img src="data:image/png;base64,{0}">'.format(data_uri)
table_str="\n<h1>Scan Statistics</h1>"
report_desc="Shows the number of hosts scanned and the average scan time per host."
report_desc+="\n<br>("+str(today)+")"
table_str+="<div class=reportdesc>"+report_desc+"</div>"
table_str+="<div class=page_section>\n"
table_str+=img_tag
table_str+="</div>"
br.gen_html_report(table_str,html_file,styles_dir)