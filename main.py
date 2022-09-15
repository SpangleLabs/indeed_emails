import datetime
import json
import os
import pickle
import re
import sys

import requests
import time
from typing import List
# Gmail API utils
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
# for encoding/decoding messages in base64
from base64 import urlsafe_b64decode
# Metrics
from prometheus_client import Gauge, start_http_server
# For retrying
from tenacity import Retrying, stop_after_attempt, wait_fixed
# For bypassing forwarding pages
from selenium import webdriver
from webdriver_manager.chrome import ChromeDriverManager


# Request all access (permission to read/send/receive emails, manage the inbox, and more)
SCOPES = ['https://mail.google.com/']
with open("config.json", "r") as f:
    CONFIG = json.load(f)
our_email = CONFIG["email"]
BOT_TOKEN = CONFIG["telegram"]["bot_token"]
CHAT_ID = CONFIG["telegram"]["chat_id"]
WAIT_BETWEEN_CHECKS = 300
PROM_PORT = 7369


LATEST_STARTUP = Gauge(
    "indeed_emails_latest_startup_unixtime",
    "Time the script was last started up"
)
LATEST_SCAN = Gauge(
    "indeed_emails_latest_scan_unixtime",
    "Time the script last scanned for emails"
)
LATEST_EMAIL = Gauge(
    "indeed_emails_latest_email_unixtime",
    "Time the script last found an email to check"
)
LATEST_ALERT = Gauge(
    "indeed_emails_latest_alert_unixtime",
    "Time the script last sent an alert to telegram"
)
EMAILS_IN_STORE = Gauge(
    "indeed_emails_emails_in_store_count",
    "Count of how many emails have been stored"
)
JOBS_IN_STORE = Gauge(
    "indeed_emails_jobs_in_store_count",
    "Count of how many job alerts have been stored"
)


class SeleniumHandler:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "DNT": "1",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }

    def __init__(self):
        op = webdriver.ChromeOptions()
        op.add_argument('--headless')
        self.driver = webdriver.Chrome(ChromeDriverManager().install(), options=op)
        self.last_request = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)

    def url_after_redirect(self, original_url: str) -> str:
        while datetime.datetime.now(datetime.timezone.utc) < self.last_request + datetime.timedelta(seconds=10):
            time.sleep(0.1)
        self.last_request = datetime.datetime.now(datetime.timezone.utc)
        self.driver.get(original_url)
        time.sleep(3)
        self.last_request = datetime.datetime.now(datetime.timezone.utc)
        return self.driver.current_url


SELENIUM_HANDLER = SeleniumHandler()


def gmail_authenticate():
    creds = None
    # the file token.pickle stores the user's access and refresh tokens, and is
    # created automatically when the authorization flow completes for the first time
    if os.path.exists("token.pickle"):
        with open("token.pickle", "rb") as token:
            creds = pickle.load(token)
    # if there are no (valid) credentials available, let the user log in.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=0)
        # save the credentials for the next run
        with open("token.pickle", "wb") as token:
            pickle.dump(creds, token)
    return build('gmail', 'v1', credentials=creds)


def search_messages(service, query):
    result = service.users().messages().list(userId='me', q=query).execute()
    messages = []
    if 'messages' in result:
        messages.extend(result['messages'])
    while 'nextPageToken' in result:
        page_token = result['nextPageToken']
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(2)):
            with attempt:
                result = service.users().messages().list(userId='me',q=query, pageToken=page_token).execute()
        if 'messages' in result:
            messages.extend(result['messages'])
    return messages


class Email:
    def __init__(
            self,
            email_id,
            datetime,
            plaintext
    ):
        self.email_id = email_id
        self.datetime = datetime
        self.plaintext = plaintext
        self._job_alerts = None

    @property
    def job_alerts(self) -> List["RawJobAlert"]:
        if self._job_alerts is not None:
            return self._job_alerts
        blocks = self.plaintext.strip().split("\n\n")
        job_count = int(blocks[0].split("\n")[1].split()[0])
        print(f"{job_count} new jobs")
        job_blocks = blocks[2:-6]
        if len(job_blocks) != job_count:
            raise Exception(f"Missing job block. Should be {job_count} jobs. But found {len(job_blocks)} blocks.")
        alerts = []
        for job_block in job_blocks:
            alert = RawJobAlert.parse_text_block(job_block)
            alerts.append(alert)
        self._job_alerts = alerts
        return alerts

    def to_json(self):
        return {
            "email_id": self.email_id,
            "date_str": self.datetime,
            "job_ids": [alert.job_id for alert in self.job_alerts]
        }


def parse_email(service, email_id) -> Email:
    msg = service.users().messages().get(userId='me', id=email_id, format='full').execute()
    payload = msg['payload']
    date_str = None
    headers = payload.get("headers", [])
    for header in headers:
        if header.get("name", "").lower() == "date":
            date_str = header.get("value")
    plaintext = None
    parts = payload.get("parts", [])
    for part in parts:
        if part.get("mimeType") == "text/plain":
            data = part.get("body", {}).get("data")
            if data is not None:
                plaintext = urlsafe_b64decode(data).decode()
    if date_str is None or plaintext is None:
        raise Exception("Email is missing date or plaintext")
    return Email(
        email_id,
        date_str,
        plaintext
    )


class RawJobAlert:
    def __init__(
            self, 
            title: str,
            subtitle: str,
            link: str,
            other_lines: List[str]
    ):
        self.title = title
        self.subtitle = subtitle
        self.link = link
        self.other_lines = other_lines
        self._job_id = None
        self._corrected_link = None
        self._selenium_link = None

    @classmethod
    def parse_text_block(cls, text_block: str) -> "RawJobAlert":
        lines = text_block.strip().split("\n")
        title = lines[0]
        subtitle = lines[1]
        link = None
        other_lines = []
        for line in lines[2:]:
            if line.startswith("https"):
                if link is not None:
                    raise Exception(f"Second link found for job block: {text_block}")
                link = line
            else:
                other_lines.append(line)
        if link is None:
            raise Exception(f"Could not find link for job block: {text_block}")
        return RawJobAlert(title, subtitle, link, other_lines)

    @property
    def correct_link(self):
        if self._corrected_link is None:
            resp = requests.get(self.link)
            self._corrected_link = resp.url
        return self._corrected_link

    @property
    def selenium_link(self) -> str:
        if self._selenium_link is None:
            selenium_link = SELENIUM_HANDLER.url_after_redirect(self.link)
            self._selenium_link = selenium_link
        return self._selenium_link

    @property
    def job_id(self):
        if self._job_id is None:
            id_regex = re.compile(r"jk=([a-z0-9A-Z]+)")
            match = id_regex.search(self.link)
            if not match:
                match = id_regex.search(self.correct_link)
            if not match:
                match = id_regex.search(self.selenium_link)
            self._job_id = match.group(1)
        return self._job_id

    @property
    def short_link(self):
        return f"https://uk.indeed.com/viewjob?jk={self.job_id}"

    def to_json(self):
        return {
            "title": self.title,
            "subtitle": self.subtitle,
            "link": self.link,
            "correct_link": self._corrected_link,
            "selenium_link": self._selenium_link,
            "job_id": self._job_id,
            "other_lines": self.other_lines
        }


def get_store():
    try:
        with open("job_store.json", "r") as f:
            store = json.load(f)
    except Exception:
        store = {}
    if "job_ids" not in store:
        store["job_ids"] = {}
    if "email_ids" not in store:
        store["email_ids"] = {}
    EMAILS_IN_STORE.set(len(store["email_ids"]))
    JOBS_IN_STORE.set(len(store["job_ids"]))
    return store


def save_store(store):
    with open("job_store.json", "w") as f:
        json.dump(store, f, indent=2)
    EMAILS_IN_STORE.set(len(store["email_ids"]))
    JOBS_IN_STORE.set(len(store["job_ids"]))


def check_and_post_email(email: Email):
    store = get_store()
    if email.email_id in store["email_ids"]:
        return
    print("Storing new email")
    store["email_ids"][email.email_id] = email.to_json()
    save_store(store)


def post_alert_to_telegram(job_alert):
    time.sleep(1)
    resp = requests.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        json={
            "chat_id": CHAT_ID,
            "text": f"New job alert.\nTitle: {job_alert.title}\n{job_alert.subtitle}\n{job_alert.short_link}"
        }
    ).json()
    print(resp)
    if not resp['ok']:
        if resp['error_code'] == 429:
            print("Too fast, waiting a minute")
            time.sleep(60)
            return post_alert_to_telegram(job_alert)
        raise Exception(f"Telegram is unhappy. Resp: {resp}")


def check_and_alert(job_alert: RawJobAlert):
    store = get_store()
    job_id = job_alert.job_id
    if job_id in store['job_ids']:
        return
    print("POSTING ALERT")
    LATEST_ALERT.set_to_current_time()
    post_alert_to_telegram(job_alert)
    store['job_ids'][job_id] = job_alert.to_json()
    save_store(store)


def mark_as_read(service, email_id):
    return service.users().messages().batchModify(
        userId='me',
        body={
            'ids': [email_id],
            'removeLabelIds': ['UNREAD']
        }
    ).execute()


def scan_and_process(service) -> None:
    LATEST_SCAN.set_to_current_time()
    unread_emails = search_messages(service, "label:professional-job-alert label:unread")
    print("Unread alert emails:")
    print(len(unread_emails))
    for unread_email in unread_emails:
        LATEST_EMAIL.set_to_current_time()
        email = parse_email(service, unread_email['id'])
        alerts = email.job_alerts
        check_and_post_email(email)
        print(f"Email has {len(alerts)} job alerts")
        for alert in alerts:
            check_and_alert(alert)
            print(alert.job_id)
        mark_as_read(service, email.email_id)


if __name__ == "__main__":
    LATEST_STARTUP.set_to_current_time()
    get_store()  # Get store, to initialise metrics
    start_http_server(PROM_PORT)
    # get the Gmail API service
    service = gmail_authenticate()

    scan_and_process(service)

    if "loop" in sys.argv:
        while True:
            time.sleep(WAIT_BETWEEN_CHECKS)
            scan_and_process(service)
