from nicegui import ui
# PyAva/UI/ui_results.py
import os
import datetime
from nicegui import ui
from xml.etree import ElementTree as ET
from PyAva.Modules.Database import Database
import logging
import pdfkit

logger = logging.getLogger(__name__)

class resultsUI:

    def __init__(self):
        self.db = Database()
        self.scan_results = []
        self.selected_scan_id = None

    def create_layout(self):
        with ui.grid():
            with ui.column():
                with ui.row():
                    self.scan_dropdown = ui.select(options=[], on_change=self.on_scan_select)
                    ui.button('Download PDF', on_click=self.download_pdf)
                self.results_table = ui.table(columns=['IP', 'Open Ports'], rows=[])
                self.results_chart = ui.highchart()
                self.load_scan_options()

    def load_scan_options(self):
        scan_times = self.db.get_scan_times()
        self.scan_dropdown.options = [str(scan_time) for scan_time in scan_times]

    def on_scan_select(self, event):
        selected_time = event.value
        self.selected_scan_id = self.db.get_scan_id_by_time(selected_time)
        self.display_results()

    def display_results(self):
        if self.selected_scan_id:
            self.scan_results = self.db.get_scan_results(self.selected_scan_id)
            self.update_table()
            self.update_chart()

    def update_table(self):
        self.results_table.rows = [
            {'IP': result['ip'], 'Open Ports': ', '.join(map(str, result['open_ports']))}
            for result in self.scan_results
        ]

    def update_chart(self):
        data = {
            'labels': [result['ip'] for result in self.scan_results],
            'datasets': [{
                'label': 'Open Ports',
                'data': [len(result['open_ports']) for result in self.scan_results]
            }]
        }
        self.results_chart.update(data)

    def download_pdf(self):
        html_content = self.generate_html_report()
        pdfkit.from_string(html_content, 'scan_results.pdf')
        ui.download('scan_results.pdf')

    def generate_html_report(self):
        html = '<html><head><title>Scan Results</title></head><body>'
        html += '<h1>Scan Results</h1>'
        html += '<table border="1"><tr><th>IP</th><th>Open Ports</th></tr>'
        for result in self.scan_results:
            html += f'<tr><td>{result["ip"]}</td><td>{", ".join(map(str, result["open_ports"]))}</td></tr>'
        html += '</table></body></html>'
        return html