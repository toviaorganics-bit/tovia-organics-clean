import os
import ssl
import smtplib
from email.message import EmailMessage
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Email configuration
GMAIL_OAUTH_REFRESH_TOKEN = os.getenv('GMAIL_OAUTH_REFRESH_TOKEN')
GMAIL_OAUTH_CLIENT_ID = os.getenv('GMAIL_OAUTH_CLIENT_ID')
GMAIL_OAUTH_CLIENT_SECRET = os.getenv('GMAIL_OAUTH_CLIENT_SECRET')
SMTP_HOST = os.getenv('SMTP_HOST')
SMTP_PORT = int(os.getenv('SMTP_PORT', '587'))
SMTP_USER = os.getenv('SMTP_USER')
SMTP_PASS = os.getenv('SMTP_PASS')
FROM_EMAIL = os.getenv('FROM_EMAIL')

# Import the OAuth function
from gmail_oauth import send_via_gmail_oauth

def send_new_email(subject, recipient, body, html=None):
    """Send an email using configured email system."""
    print("\n=== Starting Email Send Process ===")
    print("Subject:", subject)
    print("Recipient:", recipient)
    print("Has HTML content:", bool(html))
    
    try:
        # Try to send via Gmail OAuth first
        if GMAIL_OAUTH_REFRESH_TOKEN and GMAIL_OAUTH_CLIENT_ID and GMAIL_OAUTH_CLIENT_SECRET:
            print("Attempting to send via Gmail OAuth...")
            return send_via_gmail_oauth(subject, recipient, body, html, GMAIL_OAUTH_REFRESH_TOKEN)
        # Fallback to regular SMTP if OAuth fails
        elif SMTP_HOST and SMTP_USER and SMTP_PASS:
            print("Attempting to send via SMTP...")
            message = EmailMessage()
            message['Subject'] = subject
            message['From'] = FROM_EMAIL
            message['To'] = recipient
            
            if html:
                message.add_alternative(html, subtype='html')
            else:
                message.set_content(body)
            
            context = ssl.create_default_context()
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                server.starttls(context=context)
                server.login(SMTP_USER, SMTP_PASS)
                server.send_message(message)
                print("Email sent successfully via SMTP")
                return True
        else:
            print("No email configuration available. Email would have been:")
            print("To:", recipient)
            print("Subject:", subject)
            print("Body:", body)
            return False
                
    except Exception as e:
        print("Error sending email:", str(e))
        import traceback
        print("Full traceback:")
        print(traceback.format_exc())
        return False
