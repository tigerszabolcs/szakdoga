# PyAva/Modules/ScriptsScanner.py

import os
import asyncio
import nmap
import xml.etree.ElementTree as ET
import logging
from PyAva.Modules.BaseScanner import BaseScanner

logger = logging.getLogger(__name__)

class ScriptsScanner(BaseScanner):
    def __init__(self):
        super().__init__()
        self.script_name = 'vulners'
        self.scn = nmap.PortScanner()
        self.scan_completed = False

    async def do_scan(self, ip_range, arguments: list):
        """Run an nmap scan with a specified script on the given IP range and ports."""
        logger.info(f"starting scan on {ip_range}, with arguments: {arguments}")
        self.scan_completed = False
        joined_arguments = self.join_arguments(arguments)
        # Perform the scan asynchronously
        loop = asyncio.get_event_loop()
        await loop.run_in_executor(None, self.run_scan, ip_range, joined_arguments)
        self.scan_completed = True

    def run_scan(self, ip_range, arguments: str):
        """Directly executes the scan using PortScanner and processes results."""
        try:
            logger.info("scanning...")
            self.scn.scan(hosts=ip_range, arguments=f'{arguments}')
            # Process and save the scan results once the scan is complete
            self.parse_and_save_results(ip_range)
        except nmap.PortScannerError as e:
            logger.error(f"Scan failed: {e}")
            print(f"Scan failed: {e}")

    def join_arguments(self, arguments: list) -> str:
        """Join list of port arguments for scanning."""
        return ' '.join(arguments)

    def parse_and_save_results(self, ip_range):
        """Parse nmap scan results and save to XML file format."""
        logger.info("Parsing result")
        file_path = os.path.join(self.scanresults_path, f'scan_{self.id}.xml')
        root = ET.Element("ScanResults")
        result_element = ET.SubElement(root, "Result")

        for host in self.scn.all_hosts():
            host_element = ET.SubElement(result_element, "Host")
            ET.SubElement(host_element, "IP").text = host
            ET.SubElement(host_element, "State").text = self.scn[host].state()

            for protocol in self.scn[host].all_protocols():
                proto_element = ET.SubElement(host_element, "Protocol", name=protocol)

                for port in self.scn[host][protocol].keys():
                    port_element = ET.SubElement(proto_element, "Port", number=str(port))
                    port_state = self.scn[host][protocol][port]['state']
                    ET.SubElement(port_element, "State").text = port_state
                    if 'script' in self.scn[host][protocol][port]:
                        script_element = ET.SubElement(port_element, "ScriptOutput")
                        script_element.text = str(self.scn[host][protocol][port]['script'])

        # Write to file
        tree = ET.ElementTree(root)
        tree.write(file_path, encoding='utf-8', xml_declaration=True)
        logger.info(f"Scan results saved to {file_path}")
        print(f"Scan results saved to {file_path}")

    def is_scanning(self):
        """Return True if scan has not completed."""
        return not self.scan_completed

    def stop(self):
        """Stop scanning (not directly implemented with PortScanner)"""
        print("Stopping nmap.PortScanner scan is limited; consider subprocess approach if needed.")
