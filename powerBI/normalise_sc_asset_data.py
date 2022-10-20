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

def process_asset_data(region_id,assets_raw,assets_converted):
	decoded=ut.read_json_file(assets_raw)
	#print(decoded)
	results=[]
	asset_dct={}
	count=0
	for x in decoded['response']:
		#for (k,v) in x.items():
		#	print(k)
		# will just use the ip address for the uuid
		#print(x)
		id=str(x['id'])
		uuid=x['uuid']
		tenableUUID=x['tenableUUID']
		agent_uuid=''
		network_name=''
		ipv4s=[]
		ipv4=x['ipAddress']
		# set id back to ip address
		id=ipv4
		hostnames=[]
		hostname=x['name']
		operating_systems=[]
		operating_system=x['os']
		acr_score=''
		exposure_score=''
		tmp_dct={
			id:{'agent_uuuid':agent_uuid,
				'network_name':network_name,
				'ipv4s':ipv4s,
				'ipv4':ipv4,
				'hostnames':hostnames,
				'hostname':hostname,
				'acr_score':acr_score,
				'exposure_score':exposure_score,
				'operating_systems':operating_systems,
				'operating_system':operating_system,
				'rid':region_id}
		}
		count+=1
		asset_dct.update(tmp_dct)
	print(count)
	try: # see if asset file already exists
		decoded=ut.read_json_file(assets_converted)
		decoded.update(asset_dct)
		with open(assets_converted,'w') as outfile:
			json.dump(decoded,outfile)
	except:
		with open(assets_converted,'w') as outfile:
			json.dump(asset_dct,outfile)
