from xml.etree import ElementTree as ET
import os
from nicegui import ui
import json
import sqlite3
import logging
from PyAva.Modules.Database import Database

logger = logging.getLogger(__name__)
SCAN_DIR = "../data/scanresults/"

class resultsUI:
    def __init__(self):
        self.db = Database()

    def parse_nmap_scan(self, nmap_scan_id):
        filepath = os.path.join(SCAN_DIR, f'scan_{nmap_scan_id}.xml')
        if not os.path.exists(filepath):
            return None

        tree = ET.parse(filepath)
        root = tree.getroot()
        nmap_results = {}

        for result in root.findall('Result'):
            ip = result.find('nmap').text
            scan_text = result.find('scan').text
            if scan_text:
                try:
                    # Replace single quotes with double quotes
                    scan_text = scan_text.replace("'", '"')
                    scan_data = json.loads(scan_text)
                    nmap_results[ip] = scan_data
                except json.JSONDecodeError as e:
                    logger.error(f"Error decoding JSON for IP {ip}: {e}")
            else:
                logger.error(f"Scan text is missing or empty for IP {ip}")

        return nmap_results

    # Parsing script scan XML
    def parse_script_scan(self, script_scan_id):
        filepath = os.path.join(SCAN_DIR, f'scan_{script_scan_id}.xml')
        if not os.path.exists(filepath):
            return None

        tree = ET.parse(filepath)
        root = tree.getroot()
        script_results = {}

        for result in root.findall('Result'):
            ip = result.find('IP').text
            state = result.find('State').text
            protocols_text = result.find('Protocols').text
            try:
                # Replace single quotes with double quotes
                protocols_text = protocols_text.replace("'", '"')
                protocols = json.loads(protocols_text)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON for IP {ip}: {e}")
                continue
            script_results[ip] = {'state': state, 'protocols': protocols}

        return script_results

    # Merging nmap and script scan results
    def merge_results(self, nmap_results, script_results):
        merged_results = {}
        for ip, nmap_data in nmap_results.items():
            merged_results[ip] = {'nmap': nmap_data, 'script': script_results.get(ip, {})}
            
        for ip, script_data in script_results.items():
            if ip not in merged_results:
                merged_results[ip] = {'nmap': {}, 'script': script_data}

        return merged_results

    # Querying from the SQLite database to retrieve scan data
    def get_scan_ids(self, date):
        result = self.db.get_results_by_date(date)
        if result:
            nmap_scan_id_str, script_scan_id_str = result[0]
            nmap_scan_id = nmap_scan_id_str.strip("[]'\"")
            script_scan_id = script_scan_id_str.strip("[]'\"")
            return nmap_scan_id, script_scan_id
        else:
            return None, None

    # Function to display results using NiceGUI
    def display_results(self, results):
        for ip, data in results.items():
            if not data['nmap'] and not data['script']:
                continue  # Skip if both nmap and script results are empty
            with ui.card().tight():
                ui.label(f'IP: {ip}')
                with ui.column():
                    ui.label(f"Nmap Results: {json.dumps(data['nmap'], indent=2)}")
                    ui.label(f"Script Results: {json.dumps(data['script'], indent=2)}")

    # Function to create the UI layout
    def create_layout(self):
        # List available scan dates from the database
        dates = self.db.get_scan_dates()
        ui.label('Select a scan date:')
        date_dropdown = ui.select([d for d in dates])
        ui.button('Load Results', on_click=lambda : self.load_result(date_dropdown.value))

    def load_result(self, value):
        selected_date = value
        nmap_scan_id, script_scan_id = self.get_scan_ids(selected_date)
        if nmap_scan_id and script_scan_id:
            nmap_results = self.parse_nmap_scan(nmap_scan_id)
            script_results = self.parse_script_scan(script_scan_id)
            merged_results = self.merge_results(nmap_results, script_results)
            self.display_results(merged_results)
        else:
            ui.notify('No scan data available for the selected date', level='error')