import shodan
import click
from termcolor import colored
import os
import csv
import subprocess
import time


@click.command()
@click.option('--orgname', '-on', help='The name of the organization.')
@click.option('--output', '-op', default='shodan_output.csv', help='Name of the output file.')
@click.option('--api-key', '-ak', required=True, help='Shodan API key.')
@click.option('--search', '-s', is_flag=True, help='Search for exploits using searchsploit.')
@click.option('--api-check', is_flag=True, help='Check Shodan API limits.')
def search(orgname, output, api_key, search, api_check=False):
    # Initialize Shodan API with provided API key
    api = shodan.Shodan(api_key)

    # Check API rate limits
    if api_check:
        try:
            api_info = api.info()
            print(colored(f'Shodan API plan: {api_info["plan"]}', 'green'))
            print(colored(f'Query credits available: {api_info["query_credits"]}', 'green'))
            print(colored(f'Scan credits available: {api_info["scan_credits"]}', 'green'))
            if "scan_credits_reset" in api_info:
                print(colored(
                    f"Scan limit reset: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(api_info['scan_credits_reset']))}",
                    'green'))
            else:
                print(colored("Scan limit reset information not available", 'yellow'))
            return  # add this line to return immediately
        except shodan.APIError as e:
            print(colored(f'Error: {e}', 'red'))

    try:
        # Check if API credits are available
        api_info = api.info()
        if api_info["query_credits"] < 1:
            print(colored(f'Error: no API credits available. Wait or get more credits.', 'red'))
            return

        # Search for devices related to the input organization
        results = api.search(f'org:"{orgname}"')

        # Print the number of devices found
        print(colored(f'Results found: {results["total"]}', 'green'))

        # Create a dictionary to store vulnerabilities by host
        vuln_dict = {}

        # Iterate through the results and store vulnerabilities by host
        for result in results['matches']:
            ip_str = result["ip_str"]
            port = result["port"]
            if 'vulns' in result:
                for vuln in result['vulns']:
                    if ip_str in vuln_dict:
                        vuln_dict[ip_str].append(vuln)
                    else:
                        vuln_dict[ip_str] = [vuln]

        # Search Shodan for the org's IP address(es)
        results = api.search("org:{}".format(orgname))

        # Output to CSV file
        file_name = output

        # Check if file already exists
        if os.path.exists(file_name):
            print(colored(f'WARNING: {file_name} already exists and will be overwritten.', 'yellow'))

        # Write output to CSV file
        with open(file_name, "w", newline="") as csvfile:
            fieldnames = ['IP', 'OS', 'Port', 'Hostnames', 'Vulnerabilities', 'Exploit Location']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            # Write header row if file is new
            if not os.path.exists(file_name) or os.path.getsize(file_name) == 0:
                writer.writeheader()

            # Write data to file
            for result in results['matches']:
                ip_str = result['ip_str']
                row_dict = {'IP': ip_str, 'OS': result.get('os', 'N/A'), 'Port': result['port'],
                            'Hostnames': result.get('hostnames', 'N/A')}
                if ip_str in vuln_dict:
                    row_dict['Vulnerabilities'] = vuln_dict[ip_str]
                else:
                    row_dict['Vulnerabilities'] = 'None Found'

                # Search for exploits using searchsploit
                if search and 'vulns' in result:
                    exploit_paths = []
                    for vuln in result['vulns']:
                        cve = vuln.split(':')[0]
                        cmd = f'searchsploit --cve {cve} -p'
                        output = subprocess.check_output(cmd, shell=True).decode().strip()
                        if 'Path:' in output:
                            exploit_path = output.split('Path:')[1].strip()
                            exploit_paths.append(exploit_path)
                            print(colored(f'Exploit found for CVE {cve} on {ip_str}:{result["port"]} at {exploit_path}',
                                          'yellow'))
                        else:
                            print(colored(f'No exploit found for CVE {cve} on {ip_str}:{result["port"]}', 'red'))
                    # Join the list of exploit paths using a delimiter
                    exploit_paths_str = ';'.join(exploit_paths)

                    # Add the exploit paths to the row dictionary
                    row_dict['Exploit Location'] = exploit_paths_str if exploit_paths else 'N/A'

                # Write data to file with or without exploit path
                writer.writerow(row_dict)


    except shodan.APIError as e:
        print(colored(f'Error: {e}', 'red'))

if __name__ == '__main__':
    search()

