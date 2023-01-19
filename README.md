# ShodanTool

Search an organization name on Shodan, returning vulnerabilities.

## Get an API key

https://developer.shodan.io/api/requirements

## Installation

```bash
git clone https://github.com/byinarie/ShodanTool.git
pip3 install -r requirements.txt
```

## Usage/Examples

```
# Dont forget to add your API key.
python3 ShodanTool.py --orgname NAME 
python3 ShodanTool.py --orgname Consoto
python3 ShodanTool.py --orgname "Consoto, LLC"
```
