import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import utilities as ut
import pandas as pd
import datetime


# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"
#asset_file=results_dir+"licensed_assets.json"
asset_file=results_dir+"assets_with_os.json"
output_file=reports_dir+"os_summary.html"

get_new_data=1

if get_new_data==1:
	# export some asset data
	# make sure the tag is actuially defined in IO
	api_keys=tc.read_keys(key_file,"sandbox")
	filters={"tag.Operating-Systems": "has-os"}
	chunk_size=1000
	payload = {
		"filters":filters,
		"chunk_size": chunk_size
	}
	decoded=tc.check_and_download_assets_chunks(api_keys,payload,asset_file)

'''
Generate the html report from the downloaded data
'''
decoded=ut.read_json_file(asset_file)
if len(decoded) ==0:
	sys.exit("\nThe export query returned no data")
#print(decoded)
results=[]
for x in decoded:
	ipv4=""
	hostname=""
	operating_system=""
	if len(x['ipv4s']) > 0:
		ipv4=x['ipv4s'][0]
	if len(x['hostnames']) > 0:
		hostname=x['hostnames'][0]
	if len(x['operating_systems']) > 0:
		operating_system=x['operating_systems'][0]
	#data_subset=dict_subset(x,('id','ipv4s','hostnames','operating_systems'))
	#results.append(data_subset)
	results.append({'ipv4':ipv4,'hostname':hostname,'operating_system':operating_system})
myTable=pd.DataFrame(results)
print(myTable)
grouped=myTable.groupby(['operating_system'])
print(grouped.count())
grouped_counts=grouped.count().values
#print(grouped_counts)
counter=0
asset_count=0
today=datetime.date.today()
table_str="\n<h1>Operating System Summary</h1>"
report_desc="This report shows all discovered operating systems."
report_desc+="\n<br>("+str(today)+")"
table_str+="<div class=reportdesc>"+report_desc+"</div>"
table_str+="<div class=page_section>\n"
table_str+="<table class=table1 width=800px>\n"
for (operating_system), group in grouped:
	print(operating_system,grouped_counts[counter][0])
	asset_count+=grouped_counts[counter][0]
	table_str+="<tr><td>"+str(operating_system)+"</td><td>"+str(grouped_counts[counter][0])+"</td>"
	counter+=1
print(asset_count)
table_str+="<tr><td align=right>Total</td><td>"+str(asset_count)+"</td>"
hr.gen_html_report(table_str,output_file,styles_dir)
