import tenbCore as tc
import datetime
'''
Easy to use yet more complex functions that leverage the
basic building blocks in tenbCore.py
'''

def ip_lst_to_asset_lst(key_file_location,io_instance_name,ip_lst):
    api_keys = tc.read_keys(key_file_location,io_instance_name)
    assets=tc.list_assets(api_keys)
    asset_lst=[]
    for x in assets["assets"]:
        ipv4=x["ipv4"]
        asset_uuid=x["id"]
        for ip in ip_lst:
            if ip==ipv4:
                asset_lst.append(asset_uuid)
    return asset_lst

def asset_compliance_export_json(key_file_location,io_instance_name,asset_lst,last_seen,results_file):
	api_keys = tc.read_keys(key_file_location,io_instance_name)
	int_date=int(datetime.datetime.strptime(last_seen,'%d/%m/%Y').strftime("%s"))
	filter_dct={"last_seen":int_date}
	num_findings=50
	assets=asset_lst
	chunk_results=tc.check_and_download_compliance_chunks(api_keys,assets,filter_dct,num_findings,results_file)

def ip_vuln_report_html(key_file_location,io_instance_name,host_ip_filter,results_file):
    # uses a host target filter to produce a html report of
    # vulnerability findings. Report is grouped by host
    api_keys = tc.read_keys(key_file_location,io_instance_name)
    filter={
    "filter.0.filter":"host.target",
    "filter.0.quality":"eq",
    "filter.0.value":host_ip_filter,
    }
    report_type="html"
    tc.check_and_download_workbench(api_keys,filter,results_file,report_type)

def cidr_vuln_export_json(key_file_location,io_instance_name,cidr_range,results_file):
    # uses a cidr range filter to export vulnerability findings
    # into a json file. Default behaviour is last 30 days only.
    # json file is an array of dictionary records. Each dictionary
    # record is a distinct vulnerability finding per host
    api_keys = tc.read_keys(key_file_location,io_instance_name)
    filters={"cidr_range":cidr_range}
    num_assets=50
    chunk_results=tc.check_and_download_vuln_chunks(api_keys,filters,num_assets,results_file)

def tag_vuln_export_json(key_file_location,io_instance_name,tag_category,tag_list,results_file):
    # uses a tag value filter to export vulnerability findings
    # into a json file. Default behaviour is last 30 days only.
    # json file is an array of dictionary records. Each dictionary
    # record is a distinct vulnerability finding per host
    api_keys = tc.read_keys(key_file_location,io_instance_name)
    filters={tag_category:tag_list}
    num_assets=50
    chunk_results=tc.check_and_download_vuln_chunks(api_keys,filters,num_assets,results_file)
