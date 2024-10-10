import xml.etree.ElementTree as ET

class resultParser:
    def __init__(self):
        pass

    def parse_nmap_results(self, file_path):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            results = []  # List to store the results (it's a list of dictionaries)
            for host in root.findall('host'):
                host_info = {}
                address = host.find('address').get('addr')
                host_info['address'] = address
                host_info['ports'] = []
                for port in host.findall('.//port'):
                    port_info = {
                        'portid': port.get('portid'),
                        'protocol': port.get('protocol'),
                        'state': port.find('state').get('state'),
                        'service': port.find('service').get('name')
                    }
                    host_info['ports'].append(port_info)
                results.append(host_info)
            return results
        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}")
            return []
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return []

    def parse_openvas_results(self, file_path):
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            results = []
            for result in root.findall('result'):
                ip = result.find('host').text
                port = result.find('port').text
                severity = result.find('severity').text
                description = result.find('description').text
                results.append({'IP': ip, 'Port': port, 'Severity': severity, 'Description': description})
            return results
        except ET.ParseError as e:
            print(f"Error parsing XML file: {e}")
            return []
        except FileNotFoundError:
            print(f"File not found: {file_path}")
            return []

    def aggregate_results(self, nmap_results, openvas_results):
        aggregated_results = nmap_results + openvas_results
        return aggregated_results

    def print_console(self, results):
        for host in results:
            print('IP:', host['address'])
            for port in host['ports']:
                print('Port:', port['portid'])
                print('Protocol:', port['protocol'])
                print('State:', port['state'])
                print('Service:', port['service'])

if __name__ == "__main__":
    parser = resultParser()
    nmap_results = parser.parse_nmap_results('../../data/scanresults/nmap2.xml')
    if nmap_results:
        parser.print_console(nmap_results)
    else:
        print("No results to display.")