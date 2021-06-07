"""DNS Authenticator using DNS API Dynamic Updates."""
import logging
from typing import Optional

import dns.flags
import dns.message
import dns.name
import dns.query
import dns.rdataclass
import dns.rdatatype
import dns.resolver
import zope.interface

import requests
import requests.auth

from certbot import errors
from certbot import interfaces
from certbot.plugins import dns_common
from certbot.plugins.dns_common import CredentialsConfiguration

logger = logging.getLogger(__name__)

DEFAULT_NETWORK_TIMEOUT = 45

@zope.interface.implementer(interfaces.IAuthenticator)
@zope.interface.provider(interfaces.IPluginFactory)
class Authenticator(dns_common.DNSAuthenticator):
    """DNS Authenticator using DNS API Dynamic Updates
    This Authenticator uses DNS API Dynamic Updates to fulfull a dns-01 challenge.
    """

    description = 'Obtain certificates using a DNS TXT record (if you are using DNS API for DNS).'
    ttl = 120

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.credentials: Optional[CredentialsConfiguration] = None

    @classmethod
    def add_parser_arguments(cls, add):  # pylint: disable=arguments-differ
        super().add_parser_arguments(add, default_propagation_seconds=60)
        add('credentials', help='DNS API credentials INI file.')

    def more_info(self):  # pylint: disable=missing-function-docstring
        return 'This plugin configures a DNS TXT record to respond to a dns-01 challenge using ' + \
               'DNS API Dynamic Updates.'

    def _validate_algorithm(self, credentials):
        algorithm = credentials.conf('algorithm')
        if algorithm:
            if not self.ALGORITHMS.get(algorithm.upper()):
                raise errors.PluginError("Unknown algorithm: {0}.".format(algorithm))

    def _setup_credentials(self):
        self.credentials = self._configure_credentials(
            'credentials',
            'DNS API credentials INI file',
            {
                'name': 'username',
                'secret': 'password',
                'server': 'The target DNS server'
            }
        )

    def _perform(self, _domain, validation_name, validation):
        self._get_dnsapi_client().add_txt_record(validation_name, validation, self.ttl)

    def _cleanup(self, _domain, validation_name, validation):
        self._get_dnsapi_client().del_txt_record(validation_name, validation)

    def _get_dnsapi_client(self):
        if not self.credentials:  # pragma: no cover
            raise errors.Error("Plugin has not been prepared.")
        return _DNSAPIClient(self.credentials.conf('server'),
                              self.credentials.conf('name'),
                              self.credentials.conf('secret'))


class _DNSAPIClient:
    """
    Encapsulates all communication with the target DNS server.
    """
    def __init__(self, server, username, password, timeout=DEFAULT_NETWORK_TIMEOUT):
        self.server = server
        self.auth = requests.auth.HTTPBasicAuth(username, password)
        self._default_timeout = timeout

    def add_txt_record(self, record_name, record_content, record_ttl):
        """
        Add a TXT record using the supplied information.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        domain = dns.resolver.zone_for_name(record_name)

        n = dns.name.from_text(record_name)
        rel = n.relativize(domain)

        response = requests.put('{server}/update/{zone_name}/add?name={name}&rtype={rtype}&value={value}&ttl={ttl}'
                                .format(server=self.server, zone_name=domain, name=rel, rtype='txt',
                                        value=record_content, ttl=record_ttl),
                                auth=self.auth)

        if not response.ok:
            raise errors.PluginError('Encountered error adding TXT record: {0}'
                                     .format(response.text))

    def del_txt_record(self, record_name, record_content):
        """
        Delete a TXT record using the supplied information.
        :param str record_name: The record name (typically beginning with '_acme-challenge.').
        :param str record_content: The record content (typically the challenge validation).
        :param int record_ttl: The record TTL (number of seconds that the record may be cached).
        :raises certbot.errors.PluginError: if an error occurs communicating with the DNS server
        """

        domain = dns.resolver.zone_for_name(record_name)

        n = dns.name.from_text(record_name)
        rel = n.relativize(domain)

        response = requests.put('{server}/update/{zone_name}/delete?name={name}&rtype={rtype}&value={value}'
                                .format(server=self.server, zone_name=domain, name=rel, rtype='txt',
                                        value=record_content),
                                auth=self.auth)

        if not response.ok:
            raise errors.PluginError('Encountered error adding TXT record: {0}'
                                     .format(response.text))
