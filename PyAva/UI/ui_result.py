from xml.etree import ElementTree as ET
import os
from nicegui import ui
import json
import sqlite3
import logging
import ast
from PyAva.Modules.Database import Database
import matplotlib.pyplot as plt
import io
import base64
import pdfkit  # Make sure to install pdfkit
import tempfile

logger = logging.getLogger(__name__)
SCAN_DIR = "../data/scanresults/"


class resultsUI:
    def __init__(self):
        self.db = Database()
        self.current_results = {}  # To store results for PDF export
        self.chart_image_base64 = ''  # To store chart image data for PDF export

    def parse_nmap_scan(self, nmap_scan_id):
        logger.info(f"Processing nmap scan: {nmap_scan_id}")
        filepath = os.path.join(SCAN_DIR, f'scan_{nmap_scan_id}.xml')
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return {}

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Error parsing XML file {filepath}: {e}")
            return {}

        nmap_results = {}
        # Loop through each result in the ScanResults element
        for result in root.findall('Result'):
            ip_element = result.find('nmap')
            scan_element = result.find('scan')

            if ip_element is None or scan_element is None:
                logger.error("Missing 'nmap' or 'scan' element in a 'Result' node.")
                continue

            ip = ip_element.text.strip() if ip_element.text else ''
            scan_text = scan_element.text.strip() if scan_element.text else '{}'

            if scan_text:
                try:
                    # Safely evaluate the string to a Python dictionary
                    scan_data = ast.literal_eval(scan_text)
                    nmap_results[ip] = scan_data.get(ip, {})
                except Exception as e:
                    logger.error(f"Error processing scan data for IP {ip}: {e}")
                    nmap_results[ip] = {}
            else:
                logger.warning(f"No scan data found for IP {ip}")
                nmap_results[ip] = {}

        return nmap_results

    def parse_script_scan(self, script_scan_id):
        logger.info(f"Processing script scan: {script_scan_id}")
        filepath = os.path.join(SCAN_DIR, f'scan_{script_scan_id}.xml')
        if not os.path.exists(filepath):
            logger.error(f"File not found: {filepath}")
            return {}

        try:
            tree = ET.parse(filepath)
            root = tree.getroot()
        except ET.ParseError as e:
            logger.error(f"Error parsing XML file {filepath}: {e}")
            return {}

        script_results = {}

        for result in root.findall('Result'):
            ip_element = result.find('IP')
            state_element = result.find('State')
            protocols_element = result.find('Protocols')

            if ip_element is None or state_element is None or protocols_element is None:
                logger.error("Missing elements in a 'Result' node.")
                continue

            ip = ip_element.text.strip()
            state = state_element.text.strip()
            protocols_text = protocols_element.text.strip()

            try:
                protocols_text = protocols_text.replace("'", '"')
                protocols = json.loads(protocols_text)
            except json.JSONDecodeError as e:
                logger.error(f"Error decoding JSON for IP {ip}: {e}")
                continue
            script_results[ip] = {'state': state, 'protocols': protocols}

        return script_results

    def merge_results(self, nmap_results, script_results):
        merged_results = {}

        for ip, nmap_data in nmap_results.items():
            merged_results[ip] = {'nmap': nmap_data, 'script': script_results.get(ip, {})}

        for ip, script_data in script_results.items():
            if ip not in merged_results:
                merged_results[ip] = {'nmap': {}, 'script': script_data}

        return merged_results

    def get_scan_ids(self, date):
        result = self.db.get_results_by_date(date)
        if result:
            nmap_scan_id_str, script_scan_id_str = result[0]
            nmap_scan_id = nmap_scan_id_str.strip("[]'\"")
            script_scan_id = script_scan_id_str.strip("[]'\"")
            return nmap_scan_id, script_scan_id
        else:
            return None, None

    def display_results(self, results):
        self.current_results = results  # Store results for PDF export
        ip_list = []
        open_port_counts = []

        for ip, data in results.items():
            if not data['nmap'] and not data['script']:
                continue  # Skip if both nmap and script results are empty

            nmap_data = data.get('nmap', {})
            tcp_ports = nmap_data.get('tcp', {})
            # Count open ports
            open_ports = [port for port, port_data in tcp_ports.items() if port_data.get('state') == 'open']
            open_port_counts.append(len(open_ports))
            ip_list.append(ip)

            with ui.card().tight():
                ui.label(f'IP: {ip}')
                with ui.column():
                    if nmap_data:
                        # Display general host info
                        status = nmap_data.get('status', {})
                        state = status.get('state', 'unknown')
                        reason = status.get('reason', '')
                        ui.label(f"Host Status: {state} ({reason})")
                        # Display open ports and their details
                        if tcp_ports:
                            ui.label("Open TCP Ports:")
                            # Prepare columns and rows for the table
                            columns = [
                                {'name': 'port', 'label': 'Port'},
                                {'name': 'state', 'label': 'State'},
                                {'name': 'service', 'label': 'Service'},
                                {'name': 'product', 'label': 'Product'},
                                {'name': 'version', 'label': 'Version'},
                                {'name': 'extrainfo', 'label': 'Extra Info'},
                            ]
                            rows = []
                            for port, port_data in tcp_ports.items():
                                port_state = port_data.get('state', '')
                                service = port_data.get('name', '')
                                product = port_data.get('product', '')
                                version = port_data.get('version', '')
                                extrainfo = port_data.get('extrainfo', '')
                                row = {
                                    'port': str(port),
                                    'state': port_state,
                                    'service': service,
                                    'product': product,
                                    'version': version,
                                    'extrainfo': extrainfo,
                                }
                                rows.append(row)
                            ui.table(columns=columns, rows=rows).classes('w-full')
                        else:
                            ui.label("No open TCP ports found.")
                    else:
                        ui.label("No Nmap data available.")

                    script_data = data.get('script', {})
                    if script_data:
                        # Display script scan results
                        ui.label("Script Scan Results:")
                        ui.label(f"State: {script_data.get('state', '')}")
                        protocols = script_data.get('protocols', {})
                        if protocols:
                            ui.label(f"Protocols: {json.dumps(protocols, indent=2)}")
                    else:
                        ui.label("No Script data available.")
                        
        # Create a graphic using matplotlib
        if ip_list and open_port_counts:
            plt.figure(figsize=(10, 6))
            plt.bar(ip_list, open_port_counts, color='blue')
            plt.xlabel('IP Address')
            plt.ylabel('Number of Open Ports')
            plt.title('Open Ports per Host')
            plt.xticks(rotation=90)
            plt.tight_layout()
            # Save the plot to a BytesIO object
            buf = io.BytesIO()
            plt.savefig(buf, format='png')
            plt.close()
            buf.seek(0)
            # Encode the image to base64 to display in NiceGUI
            img_base64 = base64.b64encode(buf.read()).decode('utf-8')
            self.chart_image_base64 = img_base64  # Store image data for PDF export
            with ui.card().tight():
                ui.label("Open Ports per Host")
                ui.image(f'data:image/png;base64,{img_base64}')

        # Add a button to export to PDF
        ui.button('Export to PDF', on_click=self.export_to_pdf)

    def export_to_pdf(self):
        # Implement functionality to export the current view to a PDF
        # Generate HTML content
        html_content = '<html><head><meta charset="UTF-8"></head><body>'
        html_content += '<h1>Scan Results Report</h1>'

        for ip, data in self.current_results.items():
            if not data['nmap'] and not data['script']:
                continue
            html_content += f'<h2>IP: {ip}</h2>'
            nmap_data = data.get('nmap', {})
            if nmap_data:
                status = nmap_data.get('status', {})
                state = status.get('state', 'unknown')
                reason = status.get('reason', '')
                html_content += f"<p>Host Status: {state} ({reason})</p>"
                tcp_ports = nmap_data.get('tcp', {})
                if tcp_ports:
                    html_content += "<h3>Open TCP Ports:</h3>"
                    html_content += '<table border="1" cellpadding="5" cellspacing="0"><tr><th>Port</th><th>State</th><th>Service</th><th>Product</th><th>Version</th><th>Extra Info</th></tr>'
                    for port, port_data in tcp_ports.items():
                        port_state = port_data.get('state', '')
                        service = port_data.get('name', '')
                        product = port_data.get('product', '')
                        version = port_data.get('version', '')
                        extrainfo = port_data.get('extrainfo', '')
                        html_content += f'<tr><td>{port}</td><td>{port_state}</td><td>{service}</td><td>{product}</td><td>{version}</td><td>{extrainfo}</td></tr>'
                    html_content += '</table>'
                else:
                    html_content += "<p>No open TCP ports found.</p>"
            else:
                html_content += "<p>No Nmap data available.</p>"

            script_data = data.get('script', {})
            if script_data:
                html_content += "<h3>Script Scan Results:</h3>"
                html_content += f"<p>State: {script_data.get('state', '')}</p>"
                protocols = script_data.get('protocols', {})
                if protocols:
                    protocols_formatted = json.dumps(protocols, indent=2).replace('\n', '<br>').replace(' ', '&nbsp;')
                    html_content += f"<pre>{protocols_formatted}</pre>"
            else:
                html_content += "<p>No Script data available.</p>"

        # Add the chart image
        if self.chart_image_base64:
            html_content += '<h2>Open Ports per Host</h2>'
            html_content += f'<img src="data:image/png;base64,{self.chart_image_base64}" />'

        html_content += '</body></html>'

        # Convert HTML to PDF
        try:
            # Use a temporary file
            with tempfile.NamedTemporaryFile(suffix='.pdf', delete=False) as tmp_file:
                pdf_file_path = tmp_file.name
                pdfkit.from_string(html_content, pdf_file_path)

            # Provide a download link
            with ui.dialog() as dialog:
                with ui.card():
                    ui.label('PDF Report is ready for download.')
                    ui.button('Download', on_click=lambda: ui.download(pdf_file_path, 'scan_results_report.pdf'))
                    ui.button('Close', on_click=dialog.close)
            dialog.open()
        except Exception as e:
            logger.error(f"Error generating PDF: {e}")
            ui.notify('Failed to generate PDF report.', level='error')

    def create_layout(self):
        # List available scan dates from the database
        dates = self.db.get_scan_dates()
        date_dropdown = ui.select([d for d in dates], label='Select a scan date:')
        ui.button('Load Results', on_click=lambda: self.load_result(date_dropdown.value))

    def load_result(self, value):
        selected_date = value
        nmap_scan_id, script_scan_id = self.get_scan_ids(selected_date)
        print(nmap_scan_id, script_scan_id)
        nmap_results = self.parse_nmap_scan(nmap_scan_id) if nmap_scan_id else {}
        script_results = self.parse_script_scan(script_scan_id) if script_scan_id else {}

        if nmap_results or script_results:
            merged_results = self.merge_results(nmap_results, script_results)
            self.display_results(merged_results)
        else:
            ui.notify('No scan data available for the selected date', level='error')
