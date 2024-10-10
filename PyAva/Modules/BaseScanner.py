# PyAva/Modules/base_scanner.py
import os
import uuid
import xml.etree.ElementTree as ET

class BaseScanner:
    def __init__(self):
        self.id = self.generate_uid()
        self.scan_completed = False
        self.temp_results: list[dict] = []
        self.scanresults_path = os.path.join('..', 'data', 'scanresults')

    def generate_uid(self):
        return str(uuid.uuid4())

    def save_scan_result(self, host, scan_result):
        file_path = os.path.join(self.scanresults_path, f'scan_{self.id}.xml')
        if os.path.exists(file_path):
            tree = ET.parse(file_path)
            root = tree.getroot()
        else:
            root = ET.Element("ScanResults")
            tree = ET.ElementTree(root)

        result_element = ET.SubElement(root, "Result")
        for key, value in scan_result.items():
            child = ET.SubElement(result_element, key)
            child.text = str(value)

        tree.write(file_path, encoding='utf-8', xml_declaration=True)
                    

    def is_scanning(self):
        raise NotImplementedError("Subclasses should implement this method")

    def stop(self):
        raise NotImplementedError("Subclasses should implement this method")