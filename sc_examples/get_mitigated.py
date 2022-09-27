import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbSCcore as sc
import utilities as ut
import pandas as pd
import reportTemplates as rt
import htmlRoutines as hr
import csv
import json

# file and directory locations
sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
reports_dir="../report_samples/"
styles_dir="../styles/" #style sheet location for web pages

'''
The sc_keys.json file is a text file with the following format.
It contains a single disctionary object
{"server":"sc server IP","port":"sc server port","user":"secmanager user","password":"user password"}
'''
results_file=results_dir+"mitigated_raw.json"
results_file2=results_dir+"4powerBI_sc.json"
csv_file=results_dir+"4powerBI_sc.csv"
get_new_data=0
vuln_tool="vulndetails"

if get_new_data==1:
	sc_keys=sc.read_SC_keys(sc_key_file)
	sc_server,port,token,cookies=sc.get_token(sc_keys)
	decoded=sc.get_mitigated(sc_server,port,token,cookies,results_file,vuln_tool)
	#print(decoded)
	sc.close_session(sc_server,port,token,cookies)

decoded=ut.read_json_file(results_file)
results=[]
for x in decoded['response']['results']:
	#for (k,v) in x.items():
	#	print(k)
	pid=x['pluginID']
	pname=x['pluginName']
	family=x['family']
	severity=x['severity']['name']
	ip=x['ip']
	fseen=x['firstSeen']
	lseen=x['lastSeen']
	exploitable=x['exploitAvailable']
	ttf=ut.date_diff_unix(fseen,lseen)
	try: vpr=x['vprScore']
	except: vpr=''
	try: desc=x['description']
	except: desc=''
	try: synopsis=x['synopsis']
	except: synopsis=''
	try: dns=x['dnsName']
	except: dns=''
	try: repo=x['repository']
	except: repo=''
	try: poutput=x['pluginText']
	except: poutput=''
	try: patch_pub_date=x['patchPubDate']
	except: patch_pub_date=''
	try: vuln_pub_date=x['vulnPubDate']
	except: vuln_pub_date=''
	try: plug_pub_date=x['pluginPubDate']
	except: plug_pub_date=''
	try: plug_mod_date=x['pluginModDate']
	except: plug_mod_date=''
	try: sol=x['solution']
	except: sol=''
	try: netbios=x['netbiosName']
	except: netbios=''
	try: check=x['checkType']
	except: check=''
	try: arisk=x['acceptRisk']
	except: arisk=''
	try: rrisk=x['recastRisk']
	except: rrisk=''
	mydct={
		'pid':pid,
		'pname':pname,
		'family':family,
		'severity':severity,
		'vpr':vpr,
		'desc':desc,
		'synopsis':synopsis,
		'dns':dns,
		'repo':repo,
		'poutput':poutput,
		'patch_pub_date':patch_pub_date,
		'vuln_pub_date':vuln_pub_date,
		'plug_pub_date':plug_pub_date,
		'ip':ip,
		'plug_mod_date':plug_mod_date,
		'fseen':fseen,
		'lseen':lseen,
		'ttf':ttf,
		'sol':sol,
		'netbios':netbios,
		'check':check,
		'arisk':arisk,
		'rrisk':rrisk,
		'exploitable':exploitable
	}
	results.append(mydct)

with open(results_file2,'w') as outfile:
	json.dump(results,outfile)

keys = results[0].keys()

with open(csv_file, 'w', newline='') as output_file:
    dict_writer = csv.DictWriter(output_file, keys)
    dict_writer.writeheader()
    dict_writer.writerows(results)
