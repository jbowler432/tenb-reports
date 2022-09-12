import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import datetime
import utilities as ut
import pandas as pd
from datetime import datetime
from datetime import date

'''
Produces a summary report on compliance findings. The summary report is not expandable whereas
the detailed report is expandable interactively. If get_new_data is set, then it downloads a
fresh set of asset and compliance data. The saved json files are used to produce the report.
'''

# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

assets_file=results_dir+"assets.json"
compliance_file=results_dir+"compliance.json"
output_file=reports_dir+"compliance_summary.html"

get_new_data=0

# get new asset and compliance data. Asset data is used in the compliance report
# to turn asset uuids into more meaningful information
if get_new_data==1:
	# export some asset data
	api_keys=tc.read_keys(key_file,"sandbox")
	filters={}
	chunk_size=300
	payload = {
		"filters":filters,
		"chunk_size": chunk_size
	}
	tc.check_and_download_assets_chunks(api_keys,payload,assets_file)

	# export some compliance data
	asset_lst=[]
	last_seen="01/01/2021"
	int_date=int(datetime.datetime.strptime(last_seen,'%d/%m/%Y').strftime("%s"))
	#filter_dct={"last_seen":int_date}
	filter_dct={}
	num_findings=250
	assets=asset_lst
	api_keys=tc.read_keys(key_file,"sandbox")
	payload = {
		"asset":asset_lst,
		"filters":filter_dct,
		"num_findings": num_findings
		}
	chunk_results=tc.check_and_download_compliance_chunks(api_keys,payload,compliance_file)

# produce the html reports from the downloaded data

'''
Generates a html report showing a summary of all audit scan findings.
Needs both asset and compliance json input files generated from the
/compliance/export and /assets/export api. Files can be downloaded using
check_and_download_compliance_chunks(api_keys,payload,compliance_file)
check_and_download_assets_chunks(api_keys,payload,assets_file)
'''

decoded=ut.read_json_file(compliance_file)
#print(decoded)
if len(decoded) ==0:
	sys.exit("\nThe export query returned no data")
results=[]
for x in decoded:
	if 'audit_file' in x:
		data_subset=ut.dict_subset(x,('asset_uuid','audit_file','status','check_name'))
		results.append(data_subset)
	#print(data_subset)
myTable=pd.DataFrame(results)
print(myTable)
grouped=myTable.groupby(['asset_uuid','audit_file','status'])
print(grouped.count())
grouped_counts=grouped.count().values
#print(grouped_counts)
counter=0
new_uuid=""
old_uuid=""
asset_dct={}
for (asset,audit,status), group in grouped:
	new_uuid=asset
	if new_uuid!=old_uuid:
		asset_dct.update({asset:{'audit':audit,'failed':0,'passed':0,'warning':0,'error':0}})
		asset_dct[asset].update({status.lower():grouped_counts[counter][0]})
	else:
		asset_dct[asset].update({status.lower():grouped_counts[counter][0]})
	old_uuid=asset
	counter+=1
today=date.today()
table_str="\n<h1>Audit Findings Summary</h1>"
report_desc="This report shows a summary of the audit findings per host scan."
report_desc+="\n<br>("+str(today)+")"
table_str+="<div class=reportdesc>"+report_desc+"</div>"
table_str+="<div class=page_section>\n<table class=table1 width=100%>"
table_str+="<tr><td width=500px>Hostname</td><td>IP Address</td><td>Last Seen</td><td width=500px>Audit Type</td><td width=80px align=center>Failed</td><td width=80px align=center>Passed</td><td width=80px align=center>Warning</td>"
for (k,v) in asset_dct.items():
	hostname,ipv4,last_seen=ut.get_hostname(k,assets_file)
	last_seen=last_seen.split("T")[0]
	if hostname=="":
		hostname=k
	table_str+="<tr><td>"+hostname+"</td><td>"+ipv4+"</td><td>"+last_seen+"</td>\n"
	table_str+="<td>"+v['audit']+"</td><td class=critical>"+str(v['failed'])+"</td><td class=low>"+str(v['passed'])+"</td><td class=high>"+str(v['warning'])+"</td>"
	#for (j,p) in v.items():
	#	table_str+="<td>"+str(j)+"</td><td>"+str(p)+"</td>"
table_str=table_str+"</table></div>"
hr.gen_html_report(table_str,output_file,styles_dir)
