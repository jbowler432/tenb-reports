import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import beautifyResults as br
import datetime


# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
asset_file=results_dir+"assets.json"
compliance_file=results_dir+"compliance.json"

# export some asset data
api_keys=tc.read_keys(key_file,"sandbox")
filters={}
chunk_size=300
payload = {
	"filters":filters,
	"chunk_size": chunk_size
}
tc.check_and_download_assets_chunks(api_keys,payload,asset_file)

# export some compliance data
asset_lst=[]
last_seen="01/01/2021"
int_date=int(datetime.datetime.strptime(last_seen,'%d/%m/%Y').strftime("%s"))
#filter_dct={"last_seen":int_date}
filter_dct={}
num_findings=250
assets=asset_lst
api_keys=tc.read_keys(key_file,"sandbox")
payload = {
	"asset":asset_lst,
	"filters":filter_dct,
	"num_findings": num_findings
	}
chunk_results=tc.check_and_download_compliance_chunks(api_keys,payload,compliance_file)

# produce the html reports from the downloaded data
br.compliance_result_summary(asset_file,compliance_file,results_dir+"compliance_summary.html",styles_dir)
br.compliance_result_detailed(asset_file,compliance_file,results_dir+"compliance_detailed.html",styles_dir)
