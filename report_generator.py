# report_generator.py
import json

def generate_report(hosts, nm, openvas_reports, output_path):
    report = {
        'hosts': hosts,
        'nmap': nm.csv(),
        'openvas_reports': openvas_reports
    }
    with open(output_path, 'w') as file:
        json.dump(report, file)
