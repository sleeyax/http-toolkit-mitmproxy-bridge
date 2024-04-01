import base64
import hashlib
import logging
import os
import re
import subprocess

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives._serialization import PublicFormat
from mitmproxy import ctx
from mitmproxy.http import HTTPFlow

import json

logger = logging.getLogger(__name__)

PREFIX = "http-toolkit-mitmproxy-bridge: "


class HttpToolkitBridge:
    def __init__(self):
        self.certificate = ""

    def load(self, loader):
        # read mitmproxy configuration options
        options = ctx.options._options
        listenPort = options.get("listen_port").current()
        localIps = get_local_ip_addresses()
        configDir = os.path.expanduser(options.get("confdir").current())
        config = {}

        # read the local CA certificate
        self.certificate = read_certificate(configDir)

        # create the configuration object that HTTP Toolkit expects
        config["addresses"] = localIps
        config["port"] = listenPort
        config["certFingerprint"] = get_certificate_fingerprint(self.certificate)

        # generate QR code
        logger.info(PREFIX + "config: " + json.dumps(config))
        logger.info(PREFIX + "QR code link: " + get_qr_code_link(config))

    def response(self, flow: HTTPFlow):
        if flow.request.method == "GET":
            if flow.request.url == "http://android.httptoolkit.tech/config":
                logger.info(PREFIX +
                            "overriding HTTP Toolkit config endpoint"
                            )
                flow.response.status_code = 200
                flow.response.text = json.dumps({
                    'certificate': self.certificate
                })
            elif flow.request.url == "https://amiusing.httptoolkit.tech/":
                logger.info(
                    PREFIX +
                    "overriding HTTP Toolkit amiusing endpoint"
                )
                flow.response.status_code = 200
                flow.response.text = re.sub(r"<\/h1>", "<br><br>But it was me, mitmproxy >_<</h1>",
                                            flow.response.text)


def get_local_ip_addresses():
    # mitmproxy doesn't support external modules (unless you compile it from source), so we'll use the subprocess
    # module to do extract the local IPs ourselves.
    # This probably only supports Linux for now though (Windows users may test their luck with WSL).
    ip_addresses = []

    try:
        # Run the "ip addr show" command to get interface information
        result = subprocess.run(['ip', '-f', 'inet', 'addr', 'show'], capture_output=True, text=True)
        output = result.stdout

        # Parse the output to extract IP addresses
        lines = output.split('\n')
        for line in lines:
            if 'inet' in line and '127.0.0.1' not in line:  # Exclude loopback addresses
                parts = line.split()
                if len(parts) >= 2:
                    ip_address = parts[1]
                    ip_addresses.append(ip_address.split('/')[0])

    except Exception as e:
        logger.error(f"{PREFIX} failed to get local IP addresses: {e}")

    return ip_addresses


def read_certificate(configDir: str):
    try:
        with open(f"{configDir}/mitmproxy-ca-cert.pem", 'r') as file:
            cert = file.read()
            return cert
    except Exception as e:
        logger.error(f"{PREFIX} failed to read certificate file: {e}")
        return None


def get_certificate_fingerprint(certificate: str):
    pem = x509.load_pem_x509_certificate(certificate.encode(), default_backend())
    public_key = pem.public_key().public_bytes(
        encoding=serialization.Encoding.DER,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    sha256 = hashlib.sha256()
    sha256.update(public_key)
    fingerprint = sha256.digest()
    return base64.b64encode(fingerprint).decode()


def encode_to_base64(input_string):
    encoded_bytes = base64.b64encode(input_string.encode('utf-8'))
    return encoded_bytes.decode('utf-8')


def get_qr_code_link(config: dict):
    url = f"https://android.httptoolkit.tech/connect/?data={encode_to_base64(json.dumps(config))}"
    return f"https://api.qrserver.com/v1/create-qr-code/?size=150x150&data={url}"


addons = [HttpToolkitBridge()]
