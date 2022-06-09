# tenb-reports
All code is written for python3. You will need to install the requests and pandas modules

The expected format for IO license key file is

```
{'IO instance name 1':{'tio_AK':'xxx-yyyy','tio_SK':'xxx-yyyy'},
'IO instance name 2':{'tio_AK':'xxx-yyyy','tio_SK':'xxx-yyyy'}}
```

The expected format for the SC license file is

```
{"server":"sc server IP","port":"sc server port","user":"secmanager user","password":"user password"}
```

tenbIOcore.py contains the core functions to interface with the tenable.IO rest API. Most of these functions download the data and save the results in json format

tenbSCcore.py contains the core functions to interface with tenable.sc.

beautifyResults.py is used to process the saved json files and turn them into prettier html formats

look at the examples dir for some examples
