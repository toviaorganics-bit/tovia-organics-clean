from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import json
import os
import base64
from googleapiclient.discovery import build

def get_gmail_service(refresh_token):
    """Create a Gmail API service using OAuth credentials."""
    # Load client configuration from oauth token file
    creds = None
    if os.path.exists('gmail_oauth_token.json'):
        with open('gmail_oauth_token.json', 'r') as token:
            token_data = json.load(token)
            creds = Credentials.from_authorized_user_info(token_data)

    # If credentials are not valid, refresh them
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
            # Save the refreshed credentials
            with open('gmail_oauth_token.json', 'w') as token:
                token.write(creds.to_json())

    # Build and return the Gmail service
    return build('gmail', 'v1', credentials=creds)

def create_message(sender, to, subject, body, html=None):
    """Create a message for an email."""
    if html:
        message = MIMEMultipart('alternative')
        message.attach(MIMEText(body, 'plain'))
        message.attach(MIMEText(html, 'html'))
    else:
        message = MIMEText(body)

    message['to'] = to
    message['from'] = sender
    message['subject'] = subject
    return {'raw': base64.urlsafe_b64encode(message.as_bytes()).decode()}

def send_via_gmail_oauth(subject, recipient, body, html, refresh_token):
    """Send an email using Gmail OAuth."""
    try:
        service = get_gmail_service(refresh_token)
        sender = service.users().getProfile(userId='me').execute()['emailAddress']
        message = create_message(sender, recipient, subject, body, html)
        
        # Send the email
        sent_message = service.users().messages().send(
            userId='me',
            body=message
        ).execute()
        
        print(f"Email sent successfully via Gmail OAuth. Message ID: {sent_message['id']}")
        return True
        
    except Exception as e:
        print(f"Error sending email via Gmail OAuth: {str(e)}")
        return False
