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

html_file=reports_dir+"vuln_ages.html"
json_file=results_dir+"vuln_ages.json"

api_keys=tc.read_keys(key_file,"sandbox")

get_new_data = 0

if get_new_data==1:
	# export fixed data for last 90 days
	unixtime=ut.unix_time(180)
	num_assets=1000
	filters={
		"state":["open","reopened"],
		"severity":["critical","high","medium","low"],
		"last_found":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,json_file)

# process the saved json files and generate html report
decoded=ut.calculate_vuln_ages(json_file)
#print(decoded)
# extract only the data we want
#results=[]
#for x in decoded:
#	mydct={'date':x['date'],'ttfix':x['ttfix']}
#	results.append(mydct)

df=pd.DataFrame(decoded)
df=df.set_index('date')
df.index.name="Date"
#print(df.to_string())
#df.to_csv('../report_samples/df.csv', encoding='utf-8',index=True)

df2=df[['total','critical','high','medium','low']]
monthly_averages=df2.resample('M').mean()
monthly_counts=df2.resample('M').count()
print(monthly_averages)
print(monthly_counts)
#sept_df=df.loc['2022-09-01':'2022-09-30']
#sept_averages=sept_df.resample('D').mean()
colors={'total':'#0070b6','critical':'#f63442','high':'#ff9757','medium':'#f9c23b','low':'#7bb147'}
legend_labels=[]
xlabel_rot=0
img_tag=chart.bar(monthly_averages,colors,xlabel_rot,legend_labels)
img_tag2=chart.bar(monthly_counts,colors,xlabel_rot,legend_labels)

# generate the html report
body_txt="\n<h1>Vulnerability Ages - Active Vulnerabilities</h1>"
today=datetime.date.today()
report_desc="Shows the average vulnerabilty ages by severity for all current vulnerabilities. "
report_desc+="Monthly groupings are based on the last_found date."
report_desc+="\n<br>("+str(today)+")"
body_txt+="<div class=reportdesc>"+report_desc+"</div>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Average Vulnerability Ages</h2>(days)<br>\n"
body_txt+=img_tag
body_txt+="</div>"
body_txt+="<div class=page_section>\n"
body_txt+="<h2>Number of Active Vulnerabilities</h2>\n"
body_txt+=img_tag2
body_txt+="</div>"

hr.gen_html_report(body_txt,html_file,styles_dir)
