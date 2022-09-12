import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbSCcore as sc
import reportTemplates as rt
import json

# file and directory locations
sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
reports_dir="../report_samples/"

'''
The sc_keys.json file is a text file with the following format.
It contains a single disctionary object
{"server":"sc server IP","port":"sc server port","user":"secmanager user","password":"user password"}
'''


get_new_data=1
results_file=results_dir+"software_bom_sc.json"
html_file=reports_dir+"software_bom_sc.html"

if get_new_data==1:
	sc_keys=sc.read_SC_keys(sc_key_file)
	sc_server,port,token,cookies=sc.get_token(sc_keys)
	pluginID="22869,20811,83991" # SSH software enumeration
	decoded=sc.get_vulns_by_pluginID(sc_server,port,token,cookies,pluginID,results_file)

	#print(decoded)
	sc.close_session(sc_server,port,token,cookies)
	software=[]
	for results in decoded["response"]["results"]:
		software.append({"os":results["operatingSystem"],"hostname":results["dnsName"],"ipv4":results["ips"],"pluginID":results["pluginID"],"output":results["pluginText"]})
	with open(results_file,'w') as outfile:
		json.dump(software,outfile)



rt.software_bom(results_file,html_file,styles_dir)
