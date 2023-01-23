import shodan
import click
from termcolor import colored
import os
#from tqdm import tqdm
import csv
#import time

@click.command()
@click.option('--orgname', '-on', prompt='Enter the name of the organization', help='The name of the organization.')
@click.option('--output', '-op', default='shodan_output.csv', help='Name of the output file.')

def search(orgname, output):
    # Replace with your actual Shodan API key
    api = shodan.Shodan('API-KEY')
    try:
        # Search
        results = api.search(f'org:"{orgname}"')
        file_name = output

        # Print the number of devices found
        print(colored(f'Results found: {results["total"]}', 'green'))

        # Iterate through the results and print vulnerabilities
        for result in results['matches']:
            print(colored(f'Device: {result["ip_str"]}:{result["port"]}', 'yellow'))
            if 'vulns' in result:
                for vuln in result['vulns']:
                    print(colored(f'\tVulnerability: {vuln}', 'red'))
            else:
                print(colored(f'\tVulnerability: None Found', 'green'))
        # Search Shodan for the orgs IP address(s)
        results = api.search("org:{}".format(orgname))

        # File Creation
        if not os.path.exists(file_name):
            open(file_name, "w").close()

        # Output
        with open(file_name, "w", newline="") as csvfile:
            fieldnames = ['IP', 'OS', 'Port', 'Hostnames']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

        # Write output to CSV
            for result in results['matches']:
                writer.writerow({'IP': result['ip_str'], 'OS': result.get('os', 'N/A'), 'Port': result['port'],
                                    'Hostnames': result.get('hostnames', 'N/A')})
        print(f"Data exported successfully to {file_name}")

    except shodan.APIError as e:
        print(colored(f'Error: {e}', 'red'))

if __name__ == '__main__':
    search()