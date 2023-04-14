import shodan
import click
from termcolor import colored
import os
import csv



@click.command()
@click.option('--orgname', '-on', prompt='Enter the name of the organization', help='The name of the organization.')
@click.option('--output', '-op', default='shodan_output.csv', help='Name of the output file.')
@click.option('--api-key', '-ak', required=True, help='Shodan API key.')
@click.option('--exploit', '-ex', is_flag=True, help='Check vulnerabilities against Shodan Exploit API.')


def search(orgname, output, api_key, exploit):
    # Initialize Shodan API with provided API key
    api = shodan.Shodan(api_key)

    try:
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
            fieldnames = ['IP', 'OS', 'Port', 'Hostnames', 'Vulnerabilities']
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
                writer.writerow(row_dict)

        print(f"Data exported successfully to {file_name}")
        # Check for exploits
        if exploit:
            with open(file_name, "r", newline="") as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    cves = row['Vulnerabilities']
                    if cves != 'None Found':
                        print(colored(f'Exploits found for {row["IP"]} on ports {row["Port"]}:', 'green'))
                        for cve in cves:
                            try:
                                exploit_results = api.exploits.search(cve)
                                if exploit_results['total'] > 0:
                                    print(colored(f'- {cve}: {exploit}', 'green'))
                                    break
                                else:
                                    print(colored(f'- {cve}: No exploit available', 'red'))
                            except Exception as e:
                                print(colored(f'Error: {e}', 'red'))

    except shodan.APIError as e:
        print(colored(f'Error: {e}', 'red'))


if __name__ == '__main__':
    search()

if __name__ == '__main__':
    search()
