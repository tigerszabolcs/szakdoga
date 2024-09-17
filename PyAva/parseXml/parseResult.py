import xml.etree.ElementTree as ET


class resultParser():
    def __init__(self):
        pass

    # def parse_nmap_results(self, file_path):
    #     tree = ET.parse(file_path)
    #     root = tree.getroot()
    #     results = []
    #     for host in root.findall('host'):
    #         ip = host.find('address').get('addr')
    #         for port in host.findall('ports/port'):
    #             port_id = port.get('portid')
    #             state = port.find('state').get('state')
    #             results.append({'IP': ip, 'Port': port_id, 'State': state})
    #     return results
    def parse_nmap_results(self, file_path):
        tree = ET.parse(file_path)
        root = tree.getroot()
        results = [] # List of store the results (its a list of dictionaries)
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

    def parse_openvas_results(self, file_path):
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

    def aggregate_results(self, nmap_results, openvas_results):
        aggregated_results = nmap_results + openvas_results
        return aggregated_results
    
    def print_console (self, results):
        for host in results:
            print('IP:', host['address'])
            for port in host['ports']:
                print('Port:', port['portid'])
                print('Protocol:', port['protocol'])
                print('State:', port['state'])
                print('Service:', port['service'])
# Parse results
parser = resultParser()
nmap_results = parser.parse_nmap_results('../../data/nmap.xml')
# openvas_results = parser.parse_openvas_results('../../data/ovas_tesKt.xml')
# aggregated_results = parser.aggregate_results(nmap_results, openvas_results)

parser.print_console(nmap_results)
