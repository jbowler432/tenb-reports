import tenbIOcore as tc
import beautifyResults as br
import datetime

# There is no direct update acr api by tag so
# the process is a three step process
# - download the asset info for a tag
# - read the asset info file and produce a list of asset ids
# - update the acrs for the list of asset ids

# Download asset info for a certain tag.
# You specify the tag_category and tag_value
api_keys=tc.read_keys("../io_keys.json","sandbox")
tag_category="tag.Hosts"
tag_value="group1"
filters={tag_category:tag_value}
chunk_size=300
results_file="../results/assets.json"
tc.check_and_download_assets_chunks(api_keys,filters,chunk_size,results_file)

# Now we have the list of assets, update the acr values
# THe acr score needs to be an integer
asset_lst=br.extract_assetids("../results/assets.json")
acr_score=9
response=tc.update_acr_scores(api_keys,asset_lst,acr_score)
