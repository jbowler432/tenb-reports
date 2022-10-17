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
	results=[]
	asset_dct={}
	for x in decoded:
		#for (k,v) in x.items():
		#	print(k)
		id=str(x['id'])
		agent_uuid=x['agent_uuid']
		network_name=x['network_name']
		ipv4s=x['ipv4s']
		ipv4=''
		if len(ipv4s)>0: ipv4=ipv4s[0]
		hostnames=x['hostnames']
		hostname=''
		if len(hostnames)>0: hostname=hostnames[0]
		operating_systems=x['operating_systems']
		operating_system=''
		if len(operating_systems)>0: operating_system=operating_systems[0]
		acr_score=x['acr_score']
		exposure_score=x['exposure_score']
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
		asset_dct.update(tmp_dct)

	try: # see if asset file already exists
		decoded=ut.read_json_file(assets_converted)
		decoded.update(asset_dct)
		with open(assets_converted,'w') as outfile:
			json.dump(decoded,outfile)
	except:
		with open(assets_converted,'w') as outfile:
			json.dump(asset_dct,outfile)
