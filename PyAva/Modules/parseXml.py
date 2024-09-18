import lxml.etree as ET
import configparser
####OLD CODE####
class XMLParser:
    # Default XSLT paths
    xslt_nmap = '../../data/xslt/nmap.xsl'
    xslt_openvas = '../../data/xslt/openvas.xsl'
    xslt_nmap_result = '../../data/xslt/nmapresult.xsl'
    xslt_report = '../../data/xslt/html.xsl'

    def __init__(self):
        pass

    @staticmethod
    def read_file(file_name):
        with open(file_name, 'r') as file:
            return file.read()

    def transform_xml(self, xml_path, scan_type='nmap'):
        print("Simplifying XML tree")
        xml_tree = ET.parse(xml_path)
        xslt_path = self.get_xslt_path(scan_type)
        xslt_doc = ET.parse(xslt_path)
        xslt_transformer = ET.XSLT(xslt_doc)
        print("Transforming XML structure")
        transformed_tree = xslt_transformer(xml_tree)
        return transformed_tree

    def get_xslt_path(self, scan_type):
        if scan_type == 'nmap':
            return self.xslt_nmap
        elif scan_type == 'nmap_info':
            return self.xslt_nmap_info
        elif scan_type in ('openvas', 'ovas'):
            return self.xslt_openvas
        elif scan_type == 'result':
            return self.xslt_nmap_result
        else:
            return self.xslt_nmap

    @staticmethod
    def parse_openvas(root):
        results = []
        for item in root:
            result = {}
            if item.tag == "ip":
                result["IP"] = item.text
            elif item.tag == "port":
                result["PORT"] = item.text.split("/")[0]
            elif item.tag == "vulnerability":
                result["VULNERABILITY"] = item.text
            elif item.tag == "severity":
                try:
                    result["SEVERITY"] = float(item.text)
                except ValueError:
                    print("Cannot convert severity to float")
            elif item.tag == "description":
                result["DESCRIPTION"] = item.text
                results.append(result)
        return results

    @staticmethod
    def parse_nmap(root):
        results = []
        for elem in root:
            result = {}
            if elem.tag == "ip":
                result["IP"] = elem.text
            elif elem.tag == "port":
                result["PORT"] = elem.text.split("/")[0]
            elif elem.tag == "state":
                result["STATE"] = elem.text
                results.append(result)
        return results

    @staticmethod
    def parse_nmap_info(root):
        results = []
        for elem in root:
            result = {
                'IP': '',
                'NAME': '',
                'NETWORK': '',
                'OS': '',
                'APPLICATION': ''
            }
            if elem.tag == "ip":
                result["IP"] = elem.text
            elif elem.tag == "name":
                result["NAME"] = elem.text
            elif elem.tag == "network":
                result["NETWORK"] = elem.text
            elif elem.tag == "os":
                result["OS"] = elem.text
            elif elem.tag == "application":
                result["APPLICATION"] = elem.text
                results.append(result)
        return results

    def convert_tree_to_list(self, root, scan_type='nmap'):
        print("Parsing result tree into list")
        if scan_type == 'nmap':
            return self.parse_nmap(root)
        elif scan_type == 'nmap_info':
            return self.parse_nmap_info(root)
        elif scan_type in ('openvas', 'ovas'):
            return self.parse_openvas(root)
        return []

    @staticmethod
    def remove_duplicates(data_list):
        print("Removing duplicate entries from list")
        unique_list = []
        for item in data_list:
            if item not in unique_list:
                unique_list.append(item)
        return unique_list

    def parse(self, file_path, scan_type):
        try:
            xml_tree = self.transform_xml(file_path, scan_type)
            data_list = self.convert_tree_to_list(xml_tree.getroot(), scan_type)
            # Debugging: Print data_list to verify its structure
            print("Data List:", data_list)
            sorted_list = sorted(data_list, key=lambda d: d['IP'])
            return self.remove_duplicates(sorted_list)
        except ET.XMLSyntaxError as error:
            print("Error occurred while parsing XML files: " + str(error))
        except KeyError as key_error:
            print("KeyError: Missing key in data list - " + str(key_error))
        return []

def test_parse_xml(xml_file_path, scan_type):
    parser = XMLParser()
    result = parser.parse(xml_file_path, scan_type)
    print(result)

if __name__ == "__main__":
    test_parse_xml('../../data/test/nmap_test.xml', 'nmap')
    test_parse_xml('../../data/test/ovas_test.xml', 'openvas')
    
# TODO: proper test file beszerzése 