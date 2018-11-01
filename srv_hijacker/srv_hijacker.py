import os
import re

from socket import error as SocketError, timeout as SocketTimeout

from urllib3.connection import HTTPConnection
from urllib3.exceptions import (NewConnectionError, ConnectTimeoutError)
from urllib3.util import connection

from dns import resolver


def resolve_srv_record(host, resolver):
    ans = resolver.query(host, 'SRV')

    return ans.response.additional[0].items[0].address, ans[0].port


original_new_conn = HTTPConnection._new_conn


def patched_new_conn(url_regex, srv_resolver):
    """
    Returns a function that does pretty much what
    `urllib3.connection.HTTPConnection._new_conn` does.

    url_regex:

    The regex to match a host against. If this regex matches the host, we
    hit the srv_resolver to fetch the new host + port
    """

    def patched_f(self):
        if re.search(url_regex, self.host):
            self.host, self.port = resolve_srv_record(self.host, srv_resolver)

        return original_new_conn(self)

    return patched_f


def hijack(host_regex, srv_dns_host, srv_dns_port):
    srv_resolver = resolver.Resolver()

    srv_resolver.port = int(srv_dns_port)
    srv_resolver.nameservers = [srv_dns_host]

    HTTPConnection._new_conn = patched_new_conn(host_regex, srv_resolver)
