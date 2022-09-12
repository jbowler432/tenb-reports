import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import tenbSCcore as sc
import htmlRoutines as hr
import datetime
import time
import json


# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
reports_dir="../report_samples/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
output_file=reports_dir+"user_permissions_single.html"
api_keys=tc.read_keys(key_file,"sandbox")


users=tc.list_users(api_keys)

today=datetime.date.today()

user_to_find="api_restricted@sandbox.io"

# gen html  report
table_str="\n<h1>User Permission Report</h1>"
report_desc="Shows granted permissions for the specified user - "+user_to_find
table_str+="<div class=reportdesc>"+report_desc
table_str+="\n<br>("+str(today)+")</div>"
for x in users["users"]:
	#print(x)
	uuid=x["uuid"]
	uname=x["user_name"]
	if uname==user_to_find:
		table_str+="<div class=page_section>"
		table_str+="<h2>"+uname+"</h2>"
		table_str+="\n<table class=table2 width=800px>"
		print(uname,uuid)
		for (k,v) in x.items():
			table_str+="\n<tr><td>"+str(k)+"</td><td>"+str(v)+"</td>"
		table_str+="</table>"
		table_str+="<h2>Granted Permissions</h2>"
		user_permissions=tc.list_user_permissions(api_keys,uuid)
		for x in user_permissions["permissions_granted"]:
			table_str+="\n<table class=table3 width=800px>"
			for (k,v) in x.items():
				table_str+="\n<tr><td>"+str(k)+"</td><td>"+str(v)+"</td>"
			table_str+="</table>"
		time.sleep(1)
		table_str+="</div>"
		#force new line
		table_str+="<table width=100%><tr><td>&nbsp;</td></table>"
hr.gen_html_report(table_str,output_file,styles_dir)
