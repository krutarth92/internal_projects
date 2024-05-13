import requests
import json
import datetime
import time
from defang import defang
from api_request_manager import request_manager as request_manager

# Get IP Address Report from VirusTotal v2

def format_data_for_multiple_ip_enrichment_vt(ip_addresses_list, base_url, apikey, report_date):
    
    ip_enrichment_result = []
    ip_enrichment_result_dict = {}
    ip_enrichment_table_data = """"""
    
    table_data_start = ip_enrichment_table_data + """<p>Enrichment Report of Hight Risk IP Addresses from Abuse IPDB - {}</p>
<table style="border-collapse: collapse; width: 100%;" border="1"> \
<tr style="background-color: grey; color: white;"> \
<th style="text-align: center; vertical-align: middle;">IP Address</th> \
<th style="text-align: center; vertical-align: middle;">VT Score</th> \
<th style="text-align: center; vertical-align: middle;">Country</th> \
<th style="text-align: center; vertical-align: middle;">Detected URLs</th> \
<th style="text-align: center; vertical-align: middle;">Undected URLs</th> \
</tr> \
    """.format(report_date)
    
    table_data_end = """</table>"""
    table_data_row = """"""
    for ip in ip_addresses_list:
        ip_data = action_vt_enrich_ip_addresses(ip, base_url, apikey)
        ip_enrichment_result.append(ip_data.get("ip_enrichment_data").get("action_response"))
        ip_enrichment_result_dict[ip] = ip_data.get("ip_enrichment_data").get("action_response")
        table_data_row += ip_data.get("ip_data_table_row")

        time.sleep(15.1)        ## to prevent more than 4 requests in a minute for VT Free version API calls

    ip_enrichment_table_data += table_data_start + table_data_row + table_data_end
 
    response = {
        "ip_data_table_format": ip_enrichment_table_data,
        "ip_enrichment_data_dict": ip_enrichment_result_dict,
        "ip_enrichment_list": ip_enrichment_result,
    }
    return response

def action_vt_enrich_ip_addresses(ip_address, base_url, api_key):
    """
    Variables:
    ip_addresses: URL identifier or base64 representation of URL to scan (w/o padding) :: MANDATORY
    """        
    
    ## Variable Declaration
    action_endpoint = "{}/ip-address/report".format(base_url)
    country_name = ""
    vt_score = 0
    detected_urls = []
    undetected_urls = []
    detected_downloaded_samples = []
    undetected_downloaded_samples = []
    response = {}
    headers = {
            'Accept': 'application/json',
        }
    table_row = """<tr> \
<td style="text-align: center; vertical-align: middle;">{ip_address}</td> \
<td style="text-align: center; vertical-align: middle;">{vt_score}</td> \
<td style="text-align: center; vertical-align: middle;">{country}</td> \
<td style="text-align: center; vertical-align: middle;">{detected_urls}</td> \
<td style="text-align: center; vertical-align: middle;">{undetected_urls}</td> \
</tr> \
    """

    ## API Request portion
    params = {
        "apikey":api_key,
        "ip": ip_address
    }

    get_req_response = request_manager(
        action_endpoint=action_endpoint,
        request_type="GET",
        params=params,
        headers=headers
    )

    response_keys = list(get_req_response.get("action_response").keys())

    ## Format the response based on requirement        
    defanged_detected_urls = []     ## Store defanged URLS for detected URLs to share as HTML table in email
    defanged_undetected_urls = []   ## Store defanged URLS for undetected URLs to share as HTML table in email
    act_response = get_req_response.get("action_response")

    country_name = act_response.get("country") if "country" in response_keys else "NA"
    if "detected_urls" in response_keys:
        ip_detected_urls = act_response.get("detected_urls")
        if ip_detected_urls:
            detected_urls = [d["url"] for d in ip_detected_urls]
            vt_score = ip_detected_urls[0]["positives"]
        else:
            detected_urls = ["Not Found"]
    else:
        detected_urls = "Not found"

    if "undetected_urls" in response_keys:
        ip_undetected_urls = act_response.get("undetected_urls")
        list_urls = [ip_undetected_urls[i][0] for i in range(len(ip_undetected_urls))]
        undetected_urls += list_urls
        
    else:
        undetected_urls.append("Not found")
    
    
    ## Defang URLs for HTML Table
    defanged_detected_urls = [defang(url) for url in detected_urls]
    defanged_undetected_urls = [defang(url) for url in undetected_urls]
    
    # defanged_detected_urls = [url.toString() for url in detected_urls]
    # defanged_undetected_urls = [url.toString() for url in undetected_urls]

    
    table_row = table_row.format(
        ip_address=ip_address,
        vt_score=vt_score,
        country=country_name,
        detected_urls="<br/>".join(defanged_detected_urls),
        undetected_urls="<br/>".join(defanged_undetected_urls)
    )

    if "detected_referrer_samples" in response_keys:
        detected_downloaded_samples = get_req_response.get("detected_referrer_samples")            

    if "undetected_referrer_samples" in response_keys:
        undetected_downloaded_samples = get_req_response.get("undetected_downloaded_samples")
    
    response = {
        "ip_data_table_row": table_row,
        "ip_enrichment_data": get_req_response,
        "ip_address": ip_address
    }
    return response
