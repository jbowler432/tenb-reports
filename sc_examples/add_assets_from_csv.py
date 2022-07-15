import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbSCcore as sc
import glob
import csv
import utilities as ut

# file and directory locations
sc_key_file="../../sc_keys.json"
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
csv_dir="csv_files/"
'''
The sc_keys.json file is a text file with the following format.
It contains a single disctionary object
{"server":"sc server IP","port":"sc server port","user":"secmanager user","password":"user password"}

Reads csv files from the directory csv_dir. Each csv file contains a list of IP addresses
that are used to create static Assets (lists) in tenable.sc. Name of the file is used
for the name of the Asset (list). If the Asset (list) already exists, then the record is updated.
If the Asset does not exist, then its created
'''

# read the files containing the IP lists
file_lst=glob.glob(csv_dir+"*.csv")
ip_lsts=[]
column_index=0 # the column in the csv file that contains the IP address
for fname in file_lst:
	ip_lst_str=ut.get_ip_lst(fname,column_index)
	asset_lst_name=fname.split("/")[1].split(".")[0]
	ip_lsts.append({"name":asset_lst_name,"definedIPs":ip_lst_str})

# make connection to tenable.sc
sc_keys=sc.read_SC_keys(sc_key_file)
sc_server,port,token,cookies=sc.get_token(sc_keys)

# get list of asset (lists) and their names, ids
existing_assets={}
decoded=sc.call_sc_asset(sc_server,port,token,cookies)
for x in decoded["response"]["manageable"]:
	id=str(x["id"])
	name=str(x["name"])
	existing_assets.update({name:id})

# update or create assets (lists) in tenable.sc
for x in ip_lsts:
	if x["name"] in existing_assets:
		print(x["name"]+" exists so appending record")
		name=x["name"]
		definedIPs=x["definedIPs"]
		id=existing_assets[name]
		sc.patch_sc_asset_static(sc_server,port,token,cookies,id,definedIPs)
	else:
		print(x["name"]+" does not exist so creating new record")
		name=x["name"]
		definedIPs=x["definedIPs"]
		sc.add_sc_asset_static(sc_server,port,token,cookies,name,definedIPs)

sc.close_session(sc_server,port,token,cookies)
