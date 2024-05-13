import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from mimetypes import guess_type
from email.encoders import encode_base64
import os


def send_email_with_attachment(receiver_email, enrichment_content_html, files_to_attach, report_date):
    hostname = "ADD YOUR HOSTNAME"  ## ADD Hostname here
    port_no = 587
    password = "ADD PASSWORD"       ## ADD PASSWORD HERE

    sender_mail = "ADD EMAIL ID HERE"   ## ADD SENDER EMIAIL ID HERE
    # files_to_attach = ["OP project/IP Enrichment Report.xlsx"]
    # smtpObj = smtplib.SMTP("gmail.com", 587)
    
    # enrichment_content_html = """<table style="border-collapse: collapse; width: 100%;" border="1">         <tr style="background-color: grey; color: white;">         <th>IP Address</th>         <th>VT Score</th>         <th>Country</th>         <th>Detected URLs</th>         <th>Undected URLs</th>         </tr>     <tr>     <td>171.251.17.22</td>     <td>2</td>     <td>VN</td>     <td>https://171.251.17.22/<br/>http://171.251.17.22/</td>     <td></td>     </tr>     <tr>     <td>94.156.71.247</td>     <td>9</td>     <td>BG</td>     <td>https://94.156.71.247/<br/>http://94.156.71.247/</td>     <td></td>     </tr>     <tr>     <td>82.156.171.188</td>     <td>9</td>     <td>CN</td>     <td>http://82.156.171.188/<br/>https://82.156.171.188/</td>     <td></td>     </tr>     </table> """
    message = """  
    Subject: Sending SMTP e-mail   
    This is a test e-mail message.
    """    

    # Record the MIME types of both parts - text/plain and text/html.
    part1 = MIMEText(message, 'plain')
    part2 = MIMEText(enrichment_content_html, 'html')

    try:
        # Create message container - the correct MIME type is multipart/alternative.
        msg = MIMEMultipart('alternative')
        msg['Subject'] = "ADD SUBJECT HERE"     ## ADD EMAIL SUBJECT HERE
        msg['From'] = sender_mail
        msg['To'] = receiver_email
        msg.attach(part1)
        msg.attach(part2)

        for filename in files_to_attach:
            mimetype, encoding = guess_type(filename)
            mimetype = mimetype.split('/', 1)
            fp = open(filename, 'rb')
            attachment = MIMEBase(mimetype[0], mimetype[1])
            attachment.set_payload(fp.read())
            fp.close()
            encode_base64(attachment)
            attachment.add_header('Content-Disposition', 'attachment',
                                    filename=os.path.basename(filename))
            msg.attach(attachment)
        
        server = smtplib.SMTP(hostname, port_no)
        server.ehlo()
        server.starttls()
        server.ehlo()
        server.login(sender_mail, password)
        server.sendmail(sender_mail, receiver_email, msg.as_string())
        server.quit()

        response = {
            "message": "Enrichment report is Successfully sent."
        }
    except Exception as e:
        response = {
            "message": "Error: unable to send email {}".format(str(e))
        }
    
    return response
