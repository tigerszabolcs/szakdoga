# PyAva/Modules/nmapScanner.py
import platform
from time import sleep
import os
import nmap
import subprocess
from PyAva.Modules.BaseScanner import BaseScanner
import logging

logger = logging.getLogger(__name__)

class Scanner(BaseScanner):
    def __init__(self):
        super().__init__()
        print("Nmap scanner created")
        self.scn = nmap.PortScannerAsync()
        self.is_async = True
        self.scan_completed = False

    def do_scan(self, ip_range, arguments: list):
        self.scan_completed = False
        joined_arguments = self.join_arguments(arguments)
        print(f"Scanning {ip_range} with arguments: {joined_arguments} id: {self.id}")
        if self.is_async:
            self.scn.scan(hosts=ip_range, arguments=joined_arguments, callback=self.scan_callback)

    def scan_callback(self, host, scan_result):
        self.save_scan_result(host, scan_result)
        print(f"Host: {host} scanned: {scan_result['scan']}")
        # if not self.scn.still_scanning():
        #     print("Scan completed id: ", self.id)
        #     self.scan_completed = True
        # else:
        #     print("Scan still in progress id: ", self.id)

    def is_scanning(self):
        return self.scn.still_scanning()

    def stop(self):
        if self.is_async:
            self.scn.stop()

    def join_arguments(self, arguments: list) -> str:
        return_str = ' '.join([f'{val}' for val in arguments])
        print(return_str)
        return return_str