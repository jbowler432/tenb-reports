import os.path, sys
sys.path.append(os.path.join(os.path.dirname(os.path.realpath(__file__)), os.pardir))
import tenbIOcore as tc
import beautifyResults as br
import datetime


# file and directory locations
key_file="../../io_keys.json" # location of your key file
results_dir="../results/" # the directory for your results
styles_dir="../styles/" #style sheet location for web pages
asset_file=results_dir+"unlicensed_assets.json"
#asset_file=results_dir+"licensed_assets.json"
#asset_file=results_dir+"assets_with_os.json"
output_file=results_dir+"subnet_summary_unlicensed.html"
'''
# export some asset data
api_keys=tc.read_keys(key_file,"cars_api_user")
filters={"is_licensed": False}
#filters={"tag.Operating-Systems": "has-os"}
chunk_size=5000
decoded=tc.check_and_download_assets_chunks(api_keys,filters,chunk_size,asset_file)
'''

br.assets_subnet_summary(asset_file,output_file,styles_dir)
