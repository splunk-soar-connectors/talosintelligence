[comment]: # "Auto-generated SOAR connector documentation"
# Talos Intelligence

Publisher: Splunk  
Connector Version: 1\.0\.1  
Product Vendor: Cisco  
Product Name: Talos Intelligence  
Product Version Supported (regex): "\.\*"  
Minimum Product Version: 4\.2\.7532  

This app implements investigative actions by integrating with the Talos Intelligence cloud reputation service

### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Talos Intelligence asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**base\_url** |  optional  | string | Talos Base URL

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate the asset configuration for connectivity using supplied configuration  
[lookup ip](#action-lookup-ip) - Queries IP info  

## action: 'test connectivity'
Validate the asset configuration for connectivity using supplied configuration

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'lookup ip'
Queries IP info

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**ip** |  required  | IP to query | string |  `ip` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.ip | string |  `ip` 
action\_result\.data\.\*\.blacklists\.bl\.spamcop\.net\.lookup\_uri | string |  `url` 
action\_result\.data\.\*\.blacklists\.cbl\.abuseat\.org\.lookup\_uri | string |  `url` 
action\_result\.data\.\*\.blacklists\.pbl\.spamhaus\.org\.lookup\_uri | string |  `url` 
action\_result\.data\.\*\.blacklists\.sbl\.spamhaus\.org\.lookup\_uri | string |  `url` 
action\_result\.data\.\*\.category\.description | string | 
action\_result\.data\.\*\.category\.long\_description | string | 
action\_result\.data\.\*\.cidr | boolean | 
action\_result\.data\.\*\.classifications\.\*\.classification | string | 
action\_result\.data\.\*\.daily\_mag | numeric | 
action\_result\.data\.\*\.daily\_spam\_level | numeric | 
action\_result\.data\.\*\.daily\_spam\_name | string | 
action\_result\.data\.\*\.daychange | numeric | 
action\_result\.data\.\*\.display\_ipv6\_volume | boolean | 
action\_result\.data\.\*\.dnsmatch | numeric | 
action\_result\.data\.\*\.domain | string |  `domain` 
action\_result\.data\.\*\.email\_score | string | 
action\_result\.data\.\*\.email\_score\_name | string | 
action\_result\.data\.\*\.expiration | string | 
action\_result\.data\.\*\.first\_seen | string | 
action\_result\.data\.\*\.hostname | string |  `host name` 
action\_result\.data\.\*\.ip | string |  `ip` 
action\_result\.data\.\*\.monthly\_mag | numeric | 
action\_result\.data\.\*\.monthly\_spam\_level | numeric | 
action\_result\.data\.\*\.monthly\_spam\_name | string | 
action\_result\.data\.\*\.organization | string | 
action\_result\.data\.\*\.web\_score | string | 
action\_result\.data\.\*\.web\_score\_name | string | 
action\_result\.summary\.response | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 