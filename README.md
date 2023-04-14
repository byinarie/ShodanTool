# ShodanTool

Search an organization name on Shodan, returning vulnerabilities and exploits.

## Get an API key

https://developer.shodan.io/api/requirements

## Installation

```bash
git clone https://github.com/byinarie/ShodanTool.git
pip3 install -r requirements.txt

or

pip3 install click && pip3 install termcolor && pip3 install shodan
```

# Usage/Examples

#### To use the --search function you must have searchsploit installed. 
See: https://gitlab.com/exploit-database/exploitdb

## Search and output host information, cross reference results with Searchsploit into a CSV
```
python3 ShodanTool.py --api-key KEY --orgname "ORG" --output ORG.csv --search 
```
## Search and output host information into a CSV
```
python3 ShodanTool.py --api-key KEY --orgname "ORG" --output ORG.csv
```

## Check your Query credits
```
python3 ShodanTool.py --api-check --api-key 
```

## Help

```
Usage: ShodanTool.py [OPTIONS]

Options:
  -on, --orgname TEXT  The name of the organization.
  -op, --output TEXT   Name of the output file.
  -ak, --api-key TEXT  Shodan API key.  [required]
  -s, --search         Search for exploits using searchsploit.
  --api-check          Check Shodan API limits.
  --help               Show this message and exit.
 ```
