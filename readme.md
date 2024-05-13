## project OP

This project helps to generate enrichment report for High Risk IP Addresses listed by Abuse IPDB.

### 1. High Level Steps:

1. Get the list of Blacklisted IP Addresses from Abuse IPDB.
2. Check IP Addresses' report from Abuse IPDB.
3. Enrich the IP Addresses with Virustotal.
4. Create the Excel file for the IP Address report received from Abuse IPDB (from step 2).
5. Store Virustotal enrichment details of blacklist IP Addresses in MongoDB. Also send the enrichment details in email in Tabular Format.

### 2. Prerequisites

Keep the below details handy to save your time and work quickly:

- Abuse IPDB API engpoint & Public API Key.
- Virustotal API Endpoint (v2 or v3, I tested for v2 endpoint) & Public API Key.
- MongoDB URI, **Database Name** to update/create and **Collection Name** to create into Database.
- SMTP credentials to send a report (smtp host, port, tls, username, password)
- Excel Report name to generate

**Other Details**

- Email subject name
- Email sender Email ID
- Email recipient email id

**Python packages to be installed**

- openpyxl (For creating Excel file)
- pymongo and certifi (for mongodb database and collection)
- smtplib, email, os (for sending the report)
- defang (for defanging the URLs for virustotal table format to share in email)

<br/>
Please go through each and every file before running it directly.<br/>
Prequisites details are not added into the files. Put your effort and master the process for better understanding.<br/><br/>

**Good Luck!**
