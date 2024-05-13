import requests
import json
import openpyxl
import datetime
from api_request_manager import request_manager as request_manager
from vt_enrichment import format_data_for_multiple_ip_enrichment_vt
from mongodb_collection_add_data import store_enrichment_to_db
from send_email_to_user import send_email_with_attachment

### (receiver_email, enrichment_content_html, files_to_attach)
class Abuseipdb_enrichment():
    
    def __init__(
            self,
            abuse_ipdb_base_url,
            abuse_ipdb_api_key,
            virustotal_base_url,
            vt_apikey,
            report_share_with_email_id
        ):
        self.abuseipdb_base_url = abuse_ipdb_base_url
        self.abuse_ipdb_api_key = abuse_ipdb_api_key
        self.vt_basse_url = virustotal_base_url
        self.vt_apikey = vt_apikey
        self.receiver_email_id = report_share_with_email_id
    
        now = datetime.datetime.now()
        self.date_str = now.strftime("%Y-%m-%d %H:%M:%S")
        self.report_date = now.strftime("%Y-%m-%d")


    ### Action 1                                                                ###
    # Get list of the most reported IP addresses having Abuse IPDB score  >= 95   #
    ###                                                                         ###
    def action_get_most_reported_ip_addresses(
                    self,
                    minimum_confidence = 100,
                    limit = 10000,
                    ):
        
        action_endpoint = "{}/blacklist".format(self.abuseipdb_base_url)
        params = {
            "confidenceMinimum":  str(minimum_confidence),
            "limit": str(limit)
        }
        headers = {
            'Accept': 'application/json',
            'Key': self.abuse_ipdb_api_key
        }
        response = request_manager(
            action_endpoint=action_endpoint,
            request_type="GET",
            params=params,
            headers=headers
        )

        tmp_response = response["action_response"]["data"]
        ip_address_list = [d["ipAddress"] for d in tmp_response]
        
        abuse_ipdb_enrichment = self.action_prepare_ipdb_enrichment_report(ip_address_list)
        
        
        ###                                                                     ###
        #       Enrich the highly reported IP Addresses with Virustotal           #
        #       Also create the HTML table to share the details in email          #
        ###                                                                     ###
        
        virustotal_enrichment_report = self.action_virustotal_enrichment_report(ip_address_list)
        
        ###                                                                                                     ###
        #       Now its time to share the Enrichment details over an email                                        #
        #       The emial will contain:                                                                           #
        #       - Virustotal Enrichment details as HTML Table                                                     #
        #       - Abuse IPDB Highly reported IP Addresses details as EXCEL file attached with email body.         #
        ###                                                                                                     ###

        ## Get HTML table and excel file created for enrichment
        html_table_formatted_report = virustotal_enrichment_report["ip_data_table_format"]
        enrichment_Report_filename = abuse_ipdb_enrichment["enrichment_report_name"]
        
        share_report_over_email = send_email_with_attachment(
                                        self.receiver_email_id,
                                        enrichment_content_html=html_table_formatted_report,
                                        files_to_attach=[enrichment_Report_filename],
                                        report_date=self.report_date
                                        )
        response = {
            "abuse_ipdb_updates": abuse_ipdb_enrichment,
            "virustotal_updates": virustotal_enrichment_report
        }
        return response

    def action_virustotal_enrichment_report(self, list_ip_addresses):
        
        vt_enrichment_data = format_data_for_multiple_ip_enrichment_vt(list_ip_addresses, self.vt_basse_url, self.vt_apikey, self.report_date)
        response = {}
                
        ## Add Virutaotal enrichment data to MongoDB Collection
        
        virustotal_enrichment_data = vt_enrichment_data["ip_enrichment_list"]      ## Extract IP Enrichment data to add as Insert many to Collection
        collection_name = f"AbuseVT_{self.date_str}"

        ## Adding data to MongoDB Database collection
        add_data_to_mongodb_collection = store_enrichment_to_db(virustotal_enrichment_data, collection_name)
        
        response = vt_enrichment_data
        response["mongodb_message"] = add_data_to_mongodb_collection["message"]
                        
        return response


    def action_prepare_ipdb_enrichment_report(
                    self,
                    list_ip_addresses):
        
        """
        Input Parameters:
        - List IP Addresses : list of IPs from action_get_most_reported_ip_addresses action
        - report_name : name of the excel report to generate

        """
        
        dict_keys = [
            "ipAddress",
            "isPublic",
            "ipVersion",
            "isWhitelisted",
            "abuseConfidenceScore",
            "countryCode",
            "usageType",
            "isp",
            "domain",
            "hostnames",
            "isTor",
            "totalReports",
            "numDistinctUsers",
            "lastReportedAt"
        ]
        get_enrichment_data = []
        
        report_name = f"IP Enrichment Report {self.date_str}.xlsx"
        minimum_confidence = 100,
        limit = 10000
             
        ## Creating empty dictionary to store the enrichemnt data for creating Excel report
        try:            
            # ## Get list of the most reported IP addresses having Abuse IPDB score  >= 95
            # high_confidenc_ip_list = self.action_get_most_reported_ip_addresses(minimum_confidence, limit)
                
            ## Enrich IP Address with Abuse IPDB for single IP Addresses
            for enrich_ip in list_ip_addresses:
                get_enrichment_data.append(self.action_check_ip_enrichment(enrich_ip).get("action_response").get("data"))

            create_excel_file = self.action_excel_report_for_enrichment_data(get_enrichment_data, dict_keys, report_name)
            
            response = {
                "enricment_data": get_enrichment_data,
                "enrichment_report_name": report_name,
                "Status": "SUCCESS"
                
            }
        except Exception as e:
            response = {
                "enrichment_data": str(e),
                "enrichment_report_name": "Not Created! Some Error Occurred.",
                "status": "ERROR"      
            }
        return response

    ## Enrich IP Address with Abuse IPDB for single IP Addresses
    def action_check_ip_enrichment(self, ip_address, no_of_days=15):
        
        action_endpoint = "{}/check".format(self.abuseipdb_base_url)
        params = {
            "maxAgeInDays":  no_of_days,
            "ipAddress": ip_address
        }
        
        headers = {
            'Accept': 'application/json',
            'Key': self.abuse_ipdb_api_key
        }
        response = request_manager(
            action_endpoint=action_endpoint,
            request_type="GET",
            params=params,
            headers=headers
        )

        ## manage empty list resposne for Hostname data from Abuse IPDB
        
        tmp_response = response.get("action_response").get("data")        
        if not tmp_response.get("hostnames"):
            tmp_response["hostnames"] = ""
        else:
            tmp_response["hostnames"] = "\n".join(response.get("action_response").get("data").get("hostnames"))
        
        return response

    def action_excel_report_for_enrichment_data(self, enrichment_data, field_names, report_name):

        column_names = [
            "IP Address",
            "is Public",
            "IP Version",
            "is Whitelisted",
            "Abuse Confidence Score",
            "Country Code",
            "Usage Type",
            "ISP",
            "Domain",
            "Hostnames",
            "is Tor",
            "Total Reports",
            "num Distinct Users",
            "Last Reported At"
        ]

        workbook = openpyxl.Workbook()
        workbook.create_sheet("Abuse IPDB report")
        worksheet = workbook.active
        worksheet.append(column_names)

        for details in enrichment_data:
            values = (details[k] for k in field_names)
            # append the `generator values`
            worksheet.append(values)
        
        workbook.save(report_name)
        response = {
            "message": "Report {} is generated.".format(report_name)
        }
        return response
