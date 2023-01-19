import shodan
import click
from termcolor import colored

@click.command()
@click.option('--orgname', prompt='Enter the name of the organization', help='The name of the organization')
def search(orgname):
    # Replace YOUR_API_KEY with your actual Shodan API key
    api = shodan.Shodan('api-key')
    try:
        # Perform the search
        results = api.search(f'org:"{orgname}"')

        # Print the number of devices found
        print(colored(f'Results found: {results["total"]}', 'green'))
        # Iterate through the results and print vulnerabilities
        for result in results['matches']:
            print(colored(f'Device: {result["ip_str"]}:{result["port"]}', 'yellow'))
            if 'vulns' in result:
                for vuln in result['vulns']:
                    print(colored(f'\tVulnerability: {vuln}', 'red'))
            else:
                print(colored(f'\tVulnerability: None Found', 'red'))
    except shodan.APIError as e:
        print(colored(f'Error: {e}', 'red'))


if __name__ == '__main__':
    search()
