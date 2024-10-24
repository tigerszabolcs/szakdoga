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
        self.results = []

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
        for host in self.scn.all_hosts():
            result = {
                "IP": host,
                "State": self.scn[host].state(),
                "Protocols": []
            }
            for protocol in self.scn[host].all_protocols():
                proto_data = {
                    "name": protocol,
                    "ports": []
                }
                for port in self.scn[host][protocol].keys():
                    port_data = {
                        "number": port,
                        "state": self.scn[host][protocol][port]['state'],
                        "script": self.scn[host][protocol][port].get('script', '')
                    }
                    proto_data["ports"].append(port_data)
                result["Protocols"].append(proto_data)
            self.results.append(result)

    def write_results_to_file(self, filename):
        root = ET.Element("ScanResults")
        # Assuming `self.results` is a list of dictionaries containing scan results
        for result in self.results:
            result_element = ET.SubElement(root, "Result")
            for key, value in result.items():
                child = ET.SubElement(result_element, key)
                child.text = str(value)  # Ensure the value is a string

        tree = ET.ElementTree(root)
        tree.write(filename, encoding='utf-8', xml_declaration=True)
        logger.info(f"Scan results saved to {filename}")
        print(f"Scan results saved to {filename}")

    def is_scanning(self):
        """Return True if scan has not completed."""
        return not self.scan_completed

    def stop(self):
        """Stop scanning (not directly implemented with PortScanner)"""
        print("Stopping nmap.PortScanner scan is limited; consider subprocess approach if needed.")