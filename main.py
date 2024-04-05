import requests
from config import *
import subprocess
import time
import base64
import json
from PIL import Image

# based on user input pass argument into parameter of a function
# format the API json data and output to console or text file
    # formatting for different inputs will be different so we can have 1 function per API but have different formatting capabilities after we receive the JSON data.
# eventually send to website flask/django etc.

def process_input(selection, user_input):
    if selection == "IP Address":
        return IP_call(VT_api_key, Abuse_api_key, IPInfoIO_api_key, OTX_api_key, user_input)
    elif selection == "URL":
        return domain_call(VT_api_key, URLScan_api_key, user_input)
    elif selection == "Hash Value":
        return hash_call(VT_api_key, OTX_api_key, Hybrid_api_key, user_input)
    else:
        print("Invalid selection")
        # Return an empty report and None for the screenshot path in case of an invalid selection
        return ("Invalid selection", None)


#################################################################################################################

def hash_call(VT_api_key, OTX_api_key, Hybrid_api_key, hashValue):
   
    # VT call
    VTurl = 'https://www.virustotal.com/vtapi/v2/file/report'
    params = {'apikey': VT_api_key, 'resource': hashValue}
    VTresponse = requests.get(VTurl, params=params)

    if VTresponse.status_code != 200:
        return f"Error: {VTresponse.status_code}"

    VTreport = VTresponse.json()

    # Formatting the report
    if VTreport.get('response_code') != 1:
        return f"No information available for {hashValue}"

    positives = VTreport.get('positives', 0)
    total = VTreport.get('total', 0)
    scan_date = VTreport.get('scan_date', 'Unknown')
    scans = VTreport.get('scans', {})

    VTreadable_report = f"VirusTotal Information \n\nFile Hash: {hashValue}\nScan Date: {scan_date}\nDetection Ratio: {positives}/{total}\n\nDetailed Results:\n"
    for engine, result in scans.items():
        if result['detected']:
            VTreadable_report += f"- {engine}: {result['result']} (Detected)\n"


    # OTX call
    OTXurl = f'https://otx.alienvault.com/api/v1/indicators/file/{hashValue}/general'
    OTXheaders = {'X-OTX-API-KEY': OTX_api_key}
    OTXresponse = requests.get(OTXurl, headers=OTXheaders)

    if OTXresponse.status_code != 200:
        return f"Error: {OTXresponse.status_code}"

    OTXdata = OTXresponse.json()

    # Formatting the output
    formatted_output = f"\nAlienVault OTX Information \n\nFile Hash: {hashValue}\n"


    # Including Pulse information
    if 'pulse_info' in OTXdata:
        pulses = OTXdata['pulse_info'].get('pulses', [])[:5]
        formatted_output += f"Pulse Count: {len(pulses)}\n"
        for pulse in pulses:
            pulse_id = pulse.get('id', 'N/A')
            pulse_url = f"https://otx.alienvault.com/pulse/{pulse_id}" if pulse_id != 'N/A' else 'N/A'
            formatted_output += f"- Pulse Name: {pulse.get('name', 'N/A')}\n"
            formatted_output += f"  Description: {pulse.get('description', 'N/A')}\n"
            formatted_output += f"  Pulse ID: {pulse_id}\n"
            formatted_output += f"  Pulse URL: {pulse_url}\n"
            formatted_output += f"  Created: {pulse.get('created', 'N/A')}\n"
            formatted_output += f"  Modified: {pulse.get('modified', 'N/A')}\n\n"

    
    combined_report = formatted_output + "\n\n" + VTreadable_report

    # Write the combined report to a single file
    with open(f'OSINT_Report_{hashValue}.txt', 'w') as file:
        file.write(combined_report)

    return (combined_report, None) 

    # Hybrid Call
    # Hybridurl = f'https://www.hybrid-analysis.com/api/v2/search/hash'

    # Headers for the API request
    # Hybridheaders = {
    #     'api-key': Hybrid_api_key,
    #     'accept': 'application/json',
    #     'user-agent': 'Falcon Sandbox'  # Hybrid Analysis requires a specific user-agent
    # }

    # Parameters for the API request
    # Hybridparams = {
    #     'hash': hashValue
    # }

    # Make the API request
    # Hybridresponse = requests.get(Hybridurl, headers=Hybridheaders, params=Hybridparams)

    # Check if the request was successful
    # if Hybridresponse.status_code == 200:
        # Parse the response
    #     Hybridreport = Hybridresponse.json()
    #     print(Hybridreport)
    # else:
    #     print("Error:", Hybridresponse.status_code, Hybridresponse.text)


    
    # Fix Hybrid analysis or go different direction
    # format the above data
    # return singular variable
   



def domain_call(VT_api_key, URLScan_api_key, domainValue):
    VTreport = f'VirusTotal Results for {domainValue}:\n\n'

    headers = {
        'x-apikey': VT_api_key
    }

    url_id = base64.urlsafe_b64encode(f"{domainValue}".encode()).decode().strip("=")
    report_response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url_id}', headers=headers)

    if report_response.status_code == 200:
        response_data = report_response.json()
        data = response_data['data']
        attributes = data['attributes']
        total_votes = attributes['total_votes']
        last_analysis_stats = attributes['last_analysis_stats']

        VTreport += f"Site: {domainValue}\n"
        total_reports = sum(last_analysis_stats.values())
        VTreport += f"Total Reports: {total_reports}\n"
        malicious_reports = last_analysis_stats['malicious']
        VTreport += f"Malicious Reports: {malicious_reports}\n"
        VTreport += "Reported as Malicious by:\n"
        for scanner, result in attributes['last_analysis_results'].items():
            if result['category'] == 'malicious':
                VTreport += f"  - {scanner}\n"
    else:
        VTreport += 'Error retrieving report.\n'

    # urlscan
    VTreport += f"\nPlease see attached .png for screenshot of {domainValue}"
    urlScanHeaders = {
        'Content-Type': 'application/json',
        'API-Key': URLScan_api_key
    }

    data = {
        'url': domainValue,
        'visibility': 'private'
    }

    response = requests.post('https://urlscan.io/api/v1/scan/', headers=urlScanHeaders, data=json.dumps(data))
    if response.status_code == 200:
        scan_id = response.json()['uuid']
    else:
        print('Error submitting URL:', response.text)
        return VTreport, None

    # Wait for the scan to complete
    time.sleep(10)

    # Retrieve the screenshot
    screenshot_url = f'https://urlscan.io/screenshots/{scan_id}.png'
    screenshot_response = requests.get(screenshot_url)

    splitDomain = domainValue.split('.')[0]
    screenshot_filename = f'{splitDomain}_screenshot.png'

    if screenshot_response.status_code == 200:
        # Save the screenshot
        with open(screenshot_filename, 'wb') as file:
            file.write(screenshot_response.content)
    else:
        print('Error retrieving screenshot:', screenshot_response.text)
        screenshot_filename = None

    return (VTreport, screenshot_filename)
#################################################################################################################

def IP_call(VT_api_key, Abuse_api_key, IPInfoIO_api_key, OTX_api_key, ipAddress):
    # xforce call

    ipReport = f'OSINT results on IP: {ipAddress}\n\n'

    # VT call
    VTurl = f'https://www.virustotal.com/api/v3/ip_addresses/{ipAddress}'

    VTheaders = {
        'x-apikey': VT_api_key
    }

    # Make the API request
    VTresponse = requests.get(VTurl, headers=VTheaders)

    # Check the response
    if VTresponse.status_code == 200:
        VTdata = VTresponse.json()
        attributes = VTdata['data']['attributes']

        # Extracting the required information
        total_reports = attributes['last_analysis_stats']['harmless'] + \
                        attributes['last_analysis_stats']['malicious'] + \
                        attributes['last_analysis_stats']['suspicious'] + \
                        attributes['last_analysis_stats']['undetected']

        malicious_reports = attributes['last_analysis_stats']['malicious']

        # Names of reports where detected as malicious
        malicious_detections = [key for key, value in attributes['last_analysis_results'].items() if value['category'] == 'malicious']

        # Display the formatted data
        ipReport += 'VirusTotal: \n'
        ipReport += f'IP Address: {ipAddress}\n'
        ipReport += f'Total Reports: {total_reports}\n'
        ipReport += f'Times Reported Malicious: {malicious_reports}\n'
        ipReport += 'Malicious Detections:\n'
        for detection in malicious_detections:
            ipReport += f'  - {detection}\n'
    else:
        ipReport += f'Error: {VTresponse.status_code}\n'

    # abuseIPDB call
    # URL for the AbuseIPDB API
    AIPDBurl = f'https://api.abuseipdb.com/api/v2/check'

    AIPDBheaders = {
        'Key': Abuse_api_key,
        'Accept': 'application/json'
    }

    AIPDBparams = {
        'ipAddress': ipAddress,
        'maxAgeInDays': '90'  # Number of days for which to check the history
    }

    # Make the API request
    AIPDBresponse = requests.get(AIPDBurl, headers=AIPDBheaders, params=AIPDBparams)

    # Check the response
    if AIPDBresponse.status_code == 200:
        AIPDBdata = AIPDBresponse.json()['data']

        # Extracting the required fields
        AIPDBformatted_data = {
            'IP Address': AIPDBdata['ipAddress'],
            'Is Whitelisted': AIPDBdata['isWhitelisted'],
            'Abuse Confidence Score': AIPDBdata['abuseConfidenceScore'],
            'Country Code': AIPDBdata['countryCode'],
            'Usage Type': AIPDBdata.get('usageType', 'N/A'),  # Usage type might not be always available
            'ISP': AIPDBdata['isp'],
            'Total Reports': AIPDBdata['totalReports'],
            'Last Reported': AIPDBdata['lastReportedAt']
        }

        # Display the formatted data
        ipReport += '\nAbuseIPDB:\n'
        for key, value in AIPDBformatted_data.items():
            ipReport += f'{key}: {value}\n'
    else:
        ipReport += f'Error: {AIPDBresponse.status_code}\n'

    # geoIP call
    GEOurl = f'https://ipinfo.io/{ipAddress}/json'

    GEOresponse = requests.get(GEOurl)

    if GEOresponse.status_code == 200:
        GEOdata = GEOresponse.json()

        # Extracting the required fields
        GEOformatted_data = {
            'IP Address': GEOdata['ip'],
            'City': GEOdata.get('city', 'N/A'),  # City might not be always available
            'Region': GEOdata.get('region', 'N/A'),
            'Country': GEOdata['country'],
            'Location': GEOdata['loc']
        }

        # Display the formatted data
        ipReport += '\nIPInfo.io Geolocation:\n'
        for key, value in GEOformatted_data.items():
            ipReport += f'{key}: {value}\n'
    else:
        ipReport += f'Error: {GEOresponse.status_code}\n'

    # OTX call
    OTXurl = f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ipAddress}/general'

    OTXheaders = {
        'X-OTX-API-KEY': OTX_api_key
    }

    # Make the API request
    OTXresponse = requests.get(OTXurl, headers=OTXheaders)

    # Check the response
    if OTXresponse.status_code == 200:
        OTXdata = OTXresponse.json()

        whois_info = OTXdata.get('whois', 'N/A')

        # Extract reputation information
        reputation_info = OTXdata.get('reputation', 'N/A')

        # Extract and format up to 5 pulses
        pulses = OTXdata.get('pulse_info', {}).get('pulses', [])[:5]
        formatted_pulses = [{'Name': pulse['name'], 'Description': pulse['description'],'ID': pulse['id'],
        'URL': f'https://otx.alienvault.com/pulse/{pulse["id"]}'} for pulse in pulses]

        # Display the formatted data
        ipReport += "\nAlienVault OTX:\n"
        ipReport += f'IP Address: {ipAddress}\n'
        ipReport += f'WHOIS Information: {whois_info}\n'
        ipReport += f'Reputation Information: {reputation_info}\n'
        ipReport += 'Pulses:\n'
        for idx, pulse in enumerate(formatted_pulses, start=1):
            ipReport += f'  Pulse {idx}:\n'
            ipReport += f'    Name: {pulse["Name"]}\n'
            ipReport += f'    ID: {pulse["ID"]}\n'
            ipReport += f'    Description: {pulse["Description"]}\n'
            ipReport += f'    URL: {pulse["URL"]}\n'
    else:
        print('Error:', OTXresponse.status_code, OTXresponse.text)

    return (ipReport,None)
