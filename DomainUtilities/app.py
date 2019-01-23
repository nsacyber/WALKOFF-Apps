import re
import time
import socket

import tldextract

from apps import action


@action
def extract_urls_from_text(text):
    return re.findall('http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\(\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+', text)

@action
def hostname_from_url(url):
    extracted = tldextract.extract(url)
    return '.'.join(extracted)

@action
def tld_from_domain(domain):
    return tldextract.extract(domain).suffix

@action
def resolve_ip_for_host(hostname):
    return socket.gethostbyname(hostname)
    