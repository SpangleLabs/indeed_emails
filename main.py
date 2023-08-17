import datetime
import json
import os
import pickle
import re
import sys

import requests
import time
from typing import List, Optional, Any
# Gmail API utils
from googleapiclient.discovery import build
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
# for encoding/decoding messages in base64
from base64 import urlsafe_b64decode
# Metrics
from prometheus_client import Counter, Gauge, start_http_server
# For retrying
from tenacity import Retrying, stop_after_attempt, wait_fixed
# For bypassing forwarding pages
from selenium import webdriver
from selenium.webdriver import DesiredCapabilities
# For selenium docker container
import docker
from docker import errors as docker_errors

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
PARSED_JOB_BLOCKS = Counter(
    "indeed_emails_job_block_parse_count",
    "Count of how many times we tried to parse a job block in an email",
    labelnames=["result"],
)
PARSED_JOB_BLOCKS.labels(result="worked")
PARSED_JOB_BLOCKS.labels(result="failed")
JOB_ID_FROM_REGEX = Counter(
    "indeed_emails_job_id_regex_match_count",
    "Count of how many times we have tried to extract the job ID from the link in the email",
    labelnames=["result"],
)
JOB_ID_FROM_REGEX.labels(result="worked")
JOB_ID_FROM_REGEX.labels(result="failed")
JOB_ID_FROM_REQUEST = Counter(
    "indeed_emails_job_id_from_request_count",
    "Count of how many times we had to make a http request to try and get the job ID of a link",
    labelnames=["result"],
)
JOB_ID_FROM_REQUEST.labels(result="worked")
JOB_ID_FROM_REQUEST.labels(result="failed")
JOB_ID_FROM_SELENIUM = Counter(
    "indeed_emails_selenium_attempts_count",
    "Count of how many times we had to use selenium to try and get the job ID of a link",
    labelnames=["result"],
)
JOB_ID_FROM_SELENIUM.labels(result="worked")
JOB_ID_FROM_SELENIUM.labels(result="failed")
FAILED_JOB_ID = Counter(
    "indeed_emails_failed_to_fetch_job_id_count",
    "Count of how many times we've attempted and failed to get a job ID"
)


UNKNOWN_JOB_ID = "unknown_job_id"


class SeleniumHandler:
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:66.0) Gecko/20100101 Firefox/66.0",
        "Accept-Encoding": "gzip, deflate",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "DNT": "1",
        "Connection": "close",
        "Upgrade-Insecure-Requests": "1"
    }
    CONTAINER_NAME = "indeed_selenium"

    def __init__(self):
        self._start_docker()
        self.driver = webdriver.Remote("http://127.0.0.1:4444/wd/hub", DesiredCapabilities.FIREFOX)
        self.last_request = datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(seconds=10)

    def url_after_redirect(self, original_url: str) -> str:
        while datetime.datetime.now(datetime.timezone.utc) < self.last_request + datetime.timedelta(seconds=30):
            time.sleep(0.1)
        self.last_request = datetime.datetime.now(datetime.timezone.utc)
        self.driver.get(original_url)
        time.sleep(5)
        self.last_request = datetime.datetime.now(datetime.timezone.utc)
        return self.driver.current_url

    def _start_docker(self) -> None:
        self.shutdown()
        client = docker.from_env()
        print("Starting selenium container")
        client.containers.run(
            "selenium/standalone-firefox",
            ports={"4444/tcp": 4444},
            name=self.CONTAINER_NAME,
            detach=True,
        )
        print("Selenium container started")
        time.sleep(60)
        print("Waited for it to come up")

    def shutdown(self) -> None:
        client = docker.from_env()
        try:
            container = client.containers.get(self.CONTAINER_NAME)
            print("Found running selenium container, killing it")
            container.kill()
            container.remove(force=True)
        except docker_errors.NotFound:
            print("Selenium container is not running")


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


def search_messages(service, query: str) -> List[Any]:
    for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(2)):
        with attempt:
            result = service.users().messages().list(userId='me', q=query).execute()
    messages = []
    if 'messages' in result:
        messages.extend(result['messages'])
    while 'nextPageToken' in result:
        page_token = result['nextPageToken']
        for attempt in Retrying(stop=stop_after_attempt(5), wait=wait_fixed(2)):
            with attempt:
                result = service.users().messages().list(userId='me', q=query, pageToken=page_token).execute()
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
        alerts = []
        for job_block in job_blocks:
            alert = RawJobAlert.parse_text_block(job_block)
            PARSED_JOB_BLOCKS.labels(result="worked" if alert else "failed").inc()
            if alert:
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
    def parse_text_block(cls, text_block: str) -> Optional["RawJobAlert"]:
        if text_block.strip().startswith("Do not share this email"):
            return None
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
    def job_id(self) -> str:
        if self._job_id is None:
            id_regex = re.compile(r"jk=([a-z0-9A-Z]+)")
            match = id_regex.search(self.link)
            label_val = "worked" if match else "failed"
            JOB_ID_FROM_REGEX.labels(result=label_val).inc()
            if not match:
                match = id_regex.search(self.correct_link)
                label_val = "worked" if match else "failed"
                JOB_ID_FROM_REQUEST.labels(result=label_val).inc()
            if not match:
                match = id_regex.search(self.selenium_link)
                label_val = "worked" if match else "failed"
                JOB_ID_FROM_SELENIUM.labels(result=label_val).inc()
            if not match:
                print(f"ERROR: Can't find Job ID for link: {self.link}")
                FAILED_JOB_ID.inc()
                return UNKNOWN_JOB_ID
            self._job_id = match.group(1)
        return self._job_id

    @property
    def short_link(self):
        job_id = self.job_id
        if job_id == UNKNOWN_JOB_ID:
            return self.link
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
    suffix = ""
    if job_alert.job_id == UNKNOWN_JOB_ID:
        suffix = "\nJob ID unknown, may be repeat"
    resp = requests.post(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        json={
            "chat_id": CHAT_ID,
            "text": f"New job alert.\nTitle: {job_alert.title}\n{job_alert.subtitle}\n{job_alert.short_link}{suffix}"
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
    if job_id != UNKNOWN_JOB_ID and job_id in store['job_ids']:
        return
    print("POSTING ALERT")
    LATEST_ALERT.set_to_current_time()
    post_alert_to_telegram(job_alert)
    if job_id != UNKNOWN_JOB_ID:
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
    try:
        # get the Gmail API service
        service = gmail_authenticate()

        scan_and_process(service)

        if "loop" in sys.argv:
            while True:
                time.sleep(WAIT_BETWEEN_CHECKS)
                scan_and_process(service)
    finally:
        SELENIUM_HANDLER.shutdown()
