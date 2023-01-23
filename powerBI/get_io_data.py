import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import htmlRoutines as hr
import reportTemplates as rt
import pandas as pd
import utilities as ut
import datetime
import json
import funcs as fc
import normalise_vuln_data as nvd
import normalise_asset_data as nad
import normalise_mitigated_data as nmd
import e8slas as e8
import sev_slas as ss

key_file="../../io_keys.json" # location of your key file
api_keys=tc.read_keys(key_file,"sandbox")
region_id='1'
# tags for Internet facing systems
tag_cat_ifacing="Essential8"
tag_val_ifacing="Internet-Facing"


# file and directory locations
raw_dir="raw/" # the directory for your results
vulns_dir="vulns/"
mitigated_dir="mitigated/"
e8slas_dir="e8slas/"
e8mitigated_dir="e8mitigated/"
sev_slas_dir="sev_slas/"
sev_mitigated_dir="sev_mitigated/"
# raw downloaded data from APIs
vulns_raw_fname=raw_dir+"vulns_"+region_id+".json"
assets_raw_fname=raw_dir+"assets_"+region_id+".json"
mitigated_raw_fname=raw_dir+"mitigated_"+region_id+".json"
mitigated_ifacing_raw_fname=raw_dir+"mitigated_ifacing_"+region_id+".json"
# converted data using raw files as the input
vulns_converted_fname=vulns_dir+"vulns_"+region_id+".json"
vulns_plugins_fname="vulns_plugins.json"
assets_converted_fname="assets.json"
mitigated_converted_fname=mitigated_dir+"mitigated_"+region_id+".json"
mitigated_plugins_fname="mitigated_plugins.json"
e8sla_summary_fname=e8slas_dir+"e8slas_"+region_id+".json"
e8sla_detailed_fname=e8mitigated_dir+"e8mitigated_"+region_id+".json"
sla_summary_fname=sev_slas_dir+"slas_"+region_id+".json"
sla_detailed_fname=sev_mitigated_dir+"mitigated_"+region_id+".json"

'''
Main Program Loop
'''

get_asset_data=1
get_vuln_data=1
get_fix_data=1
get_ifacing_data=1

time_period=180

'''
Download the raw data
'''

if get_vuln_data==1: # raw vuln data
	unixtime=ut.unix_time(time_period)
	num_assets=200
	filters={
		"severity":["critical","high","medium","low"],
		"last_found":unixtime
	}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,vulns_raw_fname)

if get_fix_data==1: # Raw mitigated data
	unixtime=ut.unix_time(time_period)
	num_assets=250
	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"],
		"last_fixed":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,mitigated_raw_fname)

if get_asset_data==1: # Raw Asset Data
	filters={}
	chunk_size=500
	payload = {
		"filters":filters,
		"chunk_size": chunk_size
	}
	tc.check_and_download_assets_chunks(api_keys,payload,assets_raw_fname)

if get_ifacing_data==1: # Internet Facing Raw Data
	unixtime=ut.unix_time(time_period)
	num_assets=250
	filters={
		"state":["fixed"],
		"severity":["critical","high","medium","low"],
		"tag."+tag_cat_ifacing:[tag_val_ifacing],
		"last_fixed":unixtime
		}
	payload={
		"filters": filters,
		"num_assets": num_assets
	}
	chunk_results=tc.check_and_download_vuln_chunks(api_keys,payload,mitigated_ifacing_raw_fname)

'''
Process the raw data
'''

nvd.process_vuln_data(region_id,vulns_raw_fname,vulns_converted_fname,vulns_plugins_fname)
nad.process_asset_data(region_id,assets_raw_fname,assets_converted_fname)
mitigated_results,mitigated_plugins_results=nmd.process_fix_data(region_id,mitigated_raw_fname,mitigated_converted_fname,mitigated_plugins_fname)
mitigated_ifacing_results=fc.process_ifacing(region_id,mitigated_ifacing_raw_fname)

'''
Calculate some Essential 8 SLAs
'''
e8slas={
	"exploitable":2,
	"common_apps":14,
	"operating_systems":14,
	"internet_facing":14
}
e8.calc_e8slas(e8slas,region_id,mitigated_results,mitigated_plugins_results,mitigated_ifacing_results,e8sla_summary_fname,e8sla_detailed_fname)

'''
Calculate some severity based SLAs
'''

slas={
	"critical":14,
	"high":30,
	"medium":60,
	"low":90
}
ss.calc_slas(slas,region_id,mitigated_results,mitigated_plugins_results,sla_summary_fname,sla_detailed_fname)
