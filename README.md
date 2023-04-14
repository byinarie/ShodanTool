# ShodanTool

Search an organization name on Shodan, returning vulnerabilities.

## Get an API key

https://developer.shodan.io/api/requirements

## Installation

```bash
git clone https://github.com/byinarie/ShodanTool.git
pip3 install -r requirements.txt

or

pip3 install click && pip3 install termcolor && pip3 install shodan
```

## Usage/Examples

```
# Dont forget to add your API key.
python3 ShodanTool.py --api-key KEY --orgname "NAME" --output OUT.csv
python3 ShodanTool.py --orgname NAME --output OUT.csv
python3 ShodanTool.py --orgname Consoto --output OUT.csv
python3 ShodanTool.py --orgname "Consoto, LLC"  --output OUT.csv
```
