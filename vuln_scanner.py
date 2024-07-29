# vuln_scanner.py
import requests
from xml.etree import ElementTree as ET

def get_openvas_token(host, port, user, password):
    url = f"https://{host}:{port}/gmp"
    headers = {
        'Content-Type': 'application/xml',
        'Accept': 'application/xml'
    }
    envelope = ET.Element('envelope')
    cmd = ET.SubElement(envelope, 'authenticate')
    ET.SubElement(cmd, 'username').text = user
    ET.SubElement(cmd, 'password').text = password
    data = ET.tostring(envelope, encoding='utf8', method='xml').decode()

    try:
        print("Request URL:", url)
        print("Request data:", data)
        response = requests.post(url, data=data, headers=headers, verify=False)
        print("Response status code:", response.status_code)  # Debugging output
        print("Response content:", response.content)  # Debugging output
        response.raise_for_status()  # Raise an exception for HTTP errors

        response_xml = ET.fromstring(response.content)
        token = response_xml.find('.//token').text
        return token
    except requests.exceptions.RequestException as e:
        print(f"An error occurred: {e}")
        return None


def start_openvas_scan(host, port, token, target):
    url = f"https://{host}:{port}/start_scan"
    headers = {'Authorization': f'Bearer {token}'}
    data = {'target': target}
    response = requests.post(url, headers=headers, json=data, verify=False)
    return response.json()

def get_openvas_report(host, port, token, scan_id):
    url = f"https://{host}:{port}/get_report"
    headers = {'Authorization': f'Bearer {token}'}
    data = {'scan_id': scan_id}
    response = requests.post(url, headers=headers, json=data, verify=False)
    return response.json()
