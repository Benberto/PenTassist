# app.py
from flask import Flask, render_template, request, redirect, url_for, abort
from scanner import load_config, scan_network
from vuln_scanner import get_openvas_token, start_openvas_scan, get_openvas_report
from report_generator import generate_report
import os
import json

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    config = load_config('config.json')
    hosts, nm = scan_network(config['nmap_target'])

    openvas_token = get_openvas_token(config['openvas_host'], config['openvas_port'], config['openvas_user'], config['openvas_password'])
    if openvas_token is None:
        return "Failed to connect to OpenVAS", 500

    openvas_reports = {}
    for host in hosts:
        scan_result = start_openvas_scan(config['openvas_host'], config['openvas_port'], openvas_token, host)
        scan_id = scan_result['id']
        report = get_openvas_report(config['openvas_host'], config['openvas_port'], openvas_token, scan_id)
        openvas_reports[host] = report

    output_path = 'report.json'
    generate_report(hosts, nm, openvas_reports, output_path)

    return redirect(url_for('report'))

@app.route('/report')
def report():
    if not os.path.exists('report.json'):
        abort(404, description="Resource not found")
    with open('report.json', 'r') as file:
        report = json.load(file)
    return render_template('report.html', report=report)

if __name__ == "__main__":
    app.run(ssl_context=('cert.crt', 'cert.key'))
