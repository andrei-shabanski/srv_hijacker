import re

import itertools
import random
import socket
from socket import gaierror as SocketError
from functools import wraps

import dns
from dns import resolver

import logging

logger = logging.getLogger("srv_hijacker")


def resolve_ip(rrsets, old_host):
    for rrset in rrsets:
        if rrset.rdtype == dns.rdatatype.A:
            # TODO: Is it safe to assume that **any** A record in the
            # response is valid? Should we be matching against name?
            return list(rrset.items.keys())[0].address

    raise SocketError(f"Couldn't find A record for {old_host}")


def resolve_srv_record(old_host, srv_resolver):
    try:
        answers = srv_resolver.resolve(old_host, "SRV")
    except resolver.NoAnswer:
        # No SRV record. Client must try to resolve A \ CNAME record instead
        return None

    # TODO: Should we go through each answer to search alive "server"?
    by_priority_func = lambda ans: ans.priority
    answers_by_priority = itertools.groupby(sorted(answers, key=by_priority_func), key=by_priority_func)
    answer = random.choice(tuple(next(answers_by_priority)[1]))

    new_port = answer.port
    new_host = str(answer.target)  # TODO: AWS Private VPC returns CNAME-like record that a client must resolve

    logger.debug(
        "Resolved SRV record for host %s: (%s:%s)", old_host, new_host, new_port
    )

    return new_host, new_port


original_socket_getaddrinfo = socket.getaddrinfo


def patched_socket_getaddrinfo(host_regex, srv_resolver):
    """
    Returns a function that behaves like `socket.getaddrinfo`.

    host_regex:

    The regex to match a host against. If this regex matches the host
    we hit srv_resolver to fetch the new host + port
    """

    def patched_f(host, port, family=0, type=0, proto=0, flags=0):
        if re.search(host_regex, host):
            logger.debug("TCP host %s matched SRV regex, resolving", host)
            host_and_port = resolve_srv_record(host, srv_resolver)
            if host_and_port:
                host, port = host_and_port
        else:
            logger.debug("TCP host %s did not match SRV regex, ignoring", host)

        return original_socket_getaddrinfo(host, port, family, type, proto, flags)

    return patched_f


class PatchError(Exception):
    pass


def _patch_psycopg2(host_regex, srv_resolver):
    try:
        import psycopg2
        from psycopg2.extensions import parse_dsn, make_dsn
    except ImportError as e:
        raise PatchError(f"failed to import psycopg2. {e}")

    def patch_psycopg2_connect(fn):
        @wraps(fn)
        def wrapper(dsn, connection_factory=None, *args, **kwargs):
            config = parse_dsn(dsn)
            host = config.get("host")
            if host is None:
                host = kwargs.get("host")

            if host is None:
                # Host may be left out to use localhost or
                # possibly set using environment variables, nothing
                # we can do in either case.
                logger.error(
                    "'host' parameter is not present in call to psycopg2.connect, "
                    "DNS resolution might not work properly"
                )

                return fn(dsn, connection_factory, *args, **kwargs)

            if re.search(host_regex, host):
                logger.debug("Host %s matched SRV regex, resolving", host)
                host_and_port = resolve_srv_record(host,  srv_resolver)
                if host_and_port:
                    config["host"] = host_and_port[0]
                    config["port"] = host_and_port[1]

            dsn = make_dsn(**config)

            return fn(dsn, connection_factory, *args, **kwargs)

        return wrapper

    psycopg2._connect = patch_psycopg2_connect(psycopg2._connect)


def _patch_asyncpg(host_regex, srv_resolver):
    try:
        import asyncpg
        from asyncpg.connect_utils import _parse_connect_dsn_and_args
    except ImportError as e:
        raise PatchError(f"failed to import asyncpg. {e}")

    def patch_asyncpg_connect(fn):
        @wraps(fn)
        async def wrapper(dsn=None, **kwargs):
            addrs, _ = _parse_connect_dsn_and_args(
                dsn=dsn,
                host=kwargs.get('host'),
                port=kwargs.get('port'),
                user=kwargs.get('user'),
                password=kwargs.get('password'),
                passfile=kwargs.get('passfile'),
                database=kwargs.get('database'),
                ssl=kwargs.get('ssl'),
                connect_timeout=kwargs.get('connect_timeout'),
                server_settings=kwargs.get('server_settings'),
            )

            if not addrs:
                logger.error("Could not resolve %s SRV record")
                return fn(dsn=dns, **kwargs)

            host, port = addrs[0]
            if re.search(host_regex, host):
                logger.debug("Host %s matched SRV regex, resolving", host)
                host_and_port = resolve_srv_record(host,  srv_resolver)
                if host_and_port:
                    kwargs["host"] = host_and_port[0]
                    kwargs["port"] = host_and_port[1]

            return await fn(dsn=None, **kwargs)

        return wrapper

    asyncpg.connect = patch_asyncpg_connect(asyncpg.connect)


PATCHABLE_LIBS = {
    "psycopg2": _patch_psycopg2,
    "asyncpg": _patch_asyncpg,
}


def hijack(host_regex, srv_dns_host=None, srv_dns_port=None, libraries_to_patch=None):
    """
    Usage:

    ```
    srv_hijacker.hijack(
        host_regex=r'service.consul$',
        srv_dns_host='127.0.0.1',
        srv_dns_port=8600,
        libraries_to_patch=['psycopg2']
    )
    ```
    """
    srv_resolver = resolver.Resolver()
    if srv_dns_host:
        srv_resolver.nameservers = [srv_dns_host]
    if srv_dns_port:
        srv_resolver.port = int(srv_dns_port)

    socket.getaddrinfo = patched_socket_getaddrinfo(host_regex, srv_resolver)

    if not libraries_to_patch:
        return

    for each in libraries_to_patch:
        if each not in PATCHABLE_LIBS:
            raise PatchError(f"library {each} is not supported")

        PATCHABLE_LIBS.get(each)(host_regex, srv_resolver)
