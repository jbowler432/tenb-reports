# tenb-reports
All code is written for python3. You will need to install the requests and pandas modules

The expected format for license key file is

```
{'IO instance name 1':{'tio_AK':'xxx-yyyy','tio_SK':'xxx-yyyy'},
'IO instance name 2':{'tio_AK':'xxx-yyyy','tio_SK':'xxx-yyyy'}}
```

tenbIOcore.py contains the core functions to interface with the tenable.IO rest API. Most of these functions download the data and save the results in json format

beautifyResults.py is used to process the saved json files and turn them into prettier html formats

filenames starting with 'example..' provide examples of using the code
