#!/usr/bin/env python3
# cython: language_level=3
import re

try:
    from gevent import monkey
    monkey.patch_all(ssl=True)
except Exception as _:
    pass
import argparse
import json
import sys
import time
import requests

__AUTH_TYPE_API_KEY__ = 1
__AUTH_TYPE_ACCESS_TOKEN__ = 2


def str2bool(v):
    if isinstance(v, bool):
        return v
    if v.lower() in ('yes', 'true', 't', 'y', '1'):
        return True
    elif v.lower() in ('no', 'false', 'f', 'n', '0'):
        return False
    else:
        raise argparse.ArgumentTypeError('Boolean value expected.')


class Dynu(object):
    def __init__(self, client_id=None, secret=None, api_key=None, proxies=None):
        if (client_id and secret) and api_key:
            print("请指定两种方式中的一种：API Key或者OAuth2的client id 和secret")
            exit(1)
        if not (client_id and secret) and not api_key:
            print("请指定API Key或者OAuth2的client id 和secret")
            exit(1)
        self.__got_token__ = False
        self.__auth_type__ = 0
        self.__auth_at__ = -1.0
        self.__expire_time__ = -1.0
        self.__access_token__ = ''
        self.__header_accept_json__ = {'accept': 'application/json'}
        self.__header_content_json__ = {'Content-Type': 'application/json'}
        self.__api_url__ = 'https://api.dynu.com/v2/'
        self.__header_get__ = dict()
        self.__header_get__.update(self.__header_accept_json__)
        self.__proxies__ = proxies
        if client_id:
            self.__client_id__ = client_id
            self.__secret__ = secret
            self.__auth_type__ = __AUTH_TYPE_ACCESS_TOKEN__
            self.__token_url__ = 'https://api.dynu.com/v2/oauth2/token'
            self.__get_token__()
            if not self.__is_authed__():
                print("failed to get access token, please check your client_id and secret")
                exit(1)
        else:
            self.__api_key__ = api_key
            self.__auth_type__ = __AUTH_TYPE_API_KEY__
            self.__header_auth__ = {'API-Key': self.__api_key__}
            self.__header_get__.update(self.__header_auth__)
            if not self.req_get_data(suburi='dns'):
                print("Failed to access resources, please check your API Key!")
                exit(1)
        self.__header_post__ = dict()
        self.__header_post__.update(self.__header_get__)
        self.__header_post__.update(self.__header_content_json__)

    def __get_token__(self):
        try:
            result = requests.request("GET", self.__token_url__, auth=(self.__client_id__, self.__secret__),
                                      headers=self.__header_accept_json__, proxies=self.__proxies__)
            if not result or result.status_code != 200 or not result.text:
                print("Error occurred while get access token.")
                exit(1)
            j_msg = json.loads(result.text)
            if not j_msg:
                print("Error occurred while get access token.")
                exit(1)
            if not isinstance(j_msg, dict) or \
                    not j_msg['access_token'] or \
                    not j_msg['token_type'] or \
                    not j_msg['expires_in'] or \
                    j_msg['token_type'] != 'bearer':
                print("Error occored while get access token.")
                print(j_msg)
                exit(1)
            self.__got_token__ = True
            self.__auth_at__ = time.time()
            self.__expire_time__ = float(j_msg['expires_in'])
            self.__access_token__ = j_msg['access_token']
            self.__header_auth__ = {'Authorization': 'Bearer {0}'.format(self.__access_token__)}
            self.__header_get__.update(self.__header_auth__)
        except Exception as e:
            print("Error occored while get access token.")
            print(e)
            exit(1)

    def __refresh_token__(self):
        if self.__auth_type__ == __AUTH_TYPE_ACCESS_TOKEN__ and not self.__is_authed__():
            # init before refresh token
            self.__got_token__ = False
            self.__auth_at__ = -1
            self.__expire_time__ = -1
            self.__access_token__ = ''
            self.__header_get__ = dict()
            self.__header_get__.update(self.__header_accept_json__)
            self.__get_token__()

    def __is_authed__(self):
        if self.__auth_type__ == __AUTH_TYPE_API_KEY__ and self.__api_key__:
            return True
        time_now = time.time()
        if self.__auth_type__ == __AUTH_TYPE_ACCESS_TOKEN__ \
                and self.__got_token__ \
                and time_now < self.__auth_at__ + self.__expire_time__ \
                and self.__access_token__:
            return True
        return False

    @staticmethod
    def __handle_resp__(resp):
        if not resp or resp.status_code != 200 or not resp.text:
            print("Error occurred while post.")
            print(json.loads(resp.text))
            return False
        result = json.loads(resp.text)
        if 'statusCode' in result and int(result['statusCode']) == 200:
            print(result)
            return True
        elif 'exception' in result:
            e = result['exception']
            print(e)
            return False
        print(result)
        return False

    def req_get_data(self, suburi=None):
        if not self.__is_authed__():
            self.__refresh_token__()
        try:
            result = requests.request('GET', self.__api_url__ + suburi, headers=self.__header_get__,
                                      proxies=self.__proxies__)
            if not result or result.status_code != 200 or not result.text:
                print(result.text)
                return
            j_msg = json.loads(result.text)
            if int(j_msg['statusCode']) != 200:
                print(result.text)
                print(j_msg)
                exit(1)
            return j_msg
        except Exception as e:
            print("Failed to perform DYNU-api, Error: ")
            print(e)

    def req_post_data(self, suburi=None, data=None):
        if not self.__is_authed__():
            self.__refresh_token__()
        try:
            headers = self.__header_post__
            j_data = json.dumps(data)
            resp = requests.request('POST', self.__api_url__ + suburi, headers=headers, data=j_data,
                                    proxies=self.__proxies__)
            return self.__handle_resp__(resp)
        except Exception as e:
            print("Failed to perform POST, please check the auth")
            print(e)
            return False

    def req_delete_data(self, suburi=None):
        try:
            headers = self.__header_post__
            resp = requests.request('DELETE', self.__api_url__ + suburi, headers=headers, proxies=self.__proxies__)
            return self.__handle_resp__(resp)
        except Exception as e:
            print("Failed to perform POST, please check the auth")
            print(e)
            return False

    def __get_id_by_hostname__(self, hostname=None):
        if not hostname:
            return
        t_data = self.req_get_data("dns/getroot/{0}".format(hostname))
        if t_data:
            return t_data['id']

    @staticmethod
    def __fix_dns_values__(data=None):
        if data and isinstance(data, dict):
            data['ipv4'] = False
            data['ipv6'] = False
            if "ipv4Address" in data:
                data['ipv4'] = True
            if "ipv6Address" in data:
                data['ipv6'] = True
        return data

    def get_all_domains(self):
        '''
        Get all domain with details for DNS service.
        '''
        data = self.req_get_data('dns')
        if data['statusCode'] == 200:
            return data['domains']

    def get_all_domains_id(self):
        '''
        Get all domain name and id for DNS service. return dictionary
        '''
        current_domain_id_dict = {}
        current_domain_obj = [(item['name'], item['id']) for item in self.get_all_domains()]
        current_domain_id_dict.update(dict(current_domain_obj))
        return current_domain_id_dict

    def get_all_domains_name(self):
        """
        Get all domain name list for DNS service.
        """
        current_domain_obj = self.get_all_domains()
        current_domain_list = [item['name'] for item in current_domain_obj]
        return current_domain_list

    def get_domain_details(self, t_id):
        """
        Get details of a domain for DNS service.
        """
        self.req_get_data(f"dns/{t_id}")

    def add_dns_service_single(self, hostname, group="", ipv4Address="", ipv6Address="", ttl=120, ipv4=True,
                               ipv6=True, ipv4WildcardAlias=True, ipv6WildcardAlias=True, allowZoneTransfer=False,
                               dnssec=False, direct=True):
        data = {
            "name": hostname,
            "group": group,
            "ipv4Address": ipv4Address,
            "ipv6Address": ipv6Address,
            "ttl": ttl,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "ipv4WildcardAlias": ipv4WildcardAlias,
            "ipv6WildcardAlias": ipv6WildcardAlias,
            "allowZoneTransfer": allowZoneTransfer,
            "dnssec": dnssec
        }
        data = self.__fix_dns_values__(data)
        if not direct:
            current_domain_list = [item['name'] for item in self.get_all_domains()]
            if hostname in current_domain_list:
                print(f"{hostname} is already added")
                return True
        return self.req_post_data("dns", data=data)

    def add_dns_service_multi(self, domain_list, group="", ipv4Address="", ipv6Address="", ttl=60, ipv4=True,
                              ipv6=True, ipv4WildcardAlias=True, ipv6WildcardAlias=True, allowZoneTransfer=False,
                              dnssec=False):
        if not domain_list or not isinstance(domain_list, (list, tuple, set)):
            print("Incorrect domain list")
            return False
        current_domain_list = self.get_all_domains_name()
        result = {}
        for domain_name in domain_list:
            if domain_name in current_domain_list:
                print(f"{domain_name} is already added")
                result[domain_name] = False
                continue
            t_value = self.add_dns_service_single(hostname=domain_name, group=group,
                                                  ipv4Address=ipv4Address,
                                                  ipv6Address=ipv6Address,
                                                  ttl=ttl, ipv4=ipv4, ipv6=ipv6,
                                                  ipv4WildcardAlias=ipv4WildcardAlias,
                                                  ipv6WildcardAlias=ipv6WildcardAlias,
                                                  allowZoneTransfer=allowZoneTransfer,
                                                  dnssec=dnssec)
            if t_value:
                print(f"add {domain_name} successfully")
            else:
                print(f"fail to add {domain_name}")
            result[domain_name] = t_value
        return result

    def update_dns_by_hostname(self, hostname="", group="", ipv4Address="", ipv6Address="", ttl=30, ipv4=False,
                               ipv6=False, ipv4WildcardAlias=False, ipv6WildcardAlias=False, allowZoneTransfer=False,
                               dnssec=False):
        if not hostname:
            return
        t_id = self.__get_id_by_hostname__(hostname)
        if not t_id:
            print(f"{hostname} is not available")
            return False
        return self.update_dns_service_by_id(t_id, domain_name=hostname, group=group, ipv4Address=ipv4Address,
                                             ipv6Address=ipv6Address, ttl=ttl, ipv4=ipv4, ipv6=ipv6,
                                             ipv4WildcardAlias=ipv4WildcardAlias, ipv6WildcardAlias=ipv6WildcardAlias,
                                             allowZoneTransfer=allowZoneTransfer, dnssec=dnssec)

    def update_dns_service_by_id(self, id, domain_name, group, ipv4Address, ipv6Address, ttl=120, ipv4=True, ipv6=True,
                                 ipv4WildcardAlias=True, ipv6WildcardAlias=True, allowZoneTransfer=False, dnssec=False):
        """
        Update an existing DNS service.
        """
        data = {
            "name": domain_name,
            "group": group,
            "ipv4Address": ipv4Address,
            "ipv6Address": ipv6Address,
            "ttl": ttl,
            "ipv4": ipv4,
            "ipv6": ipv6,
            "ipv4WildcardAlias": ipv4WildcardAlias,
            "ipv6WildcardAlias": ipv6WildcardAlias,
            "allowZoneTransfer": allowZoneTransfer,
            "dnssec": dnssec
        }
        data = self.__fix_dns_values__(data)
        return self.req_post_data(f"dns/{id}", data=data)

    def update_dns_by_multi(self, domain_list, group="", ipv4Address="", ipv6Address="", ttl=30, ipv4=False,
                            ipv6=False, ipv4WildcardAlias=False, ipv6WildcardAlias=False, allowZoneTransfer=False,
                            dnssec=False):
        if domain_list and isinstance(domain_list, (list, tuple, set)):
            domain_list = set(domain_list)
            current_domain_id_dict = self.get_all_domains_id()
            result = {}
            for t_d in domain_list:
                if t_d not in current_domain_id_dict:
                    print(f"{t_d} is not available")
                    result[t_d] = False
                    continue
                t_value = self.update_dns_service_by_id(current_domain_id_dict[t_d], domain_name=t_d, group=group,
                                                        ipv4Address=ipv4Address, ipv6Address=ipv6Address,
                                                        ttl=ttl, ipv4=ipv4, ipv6=ipv6,
                                                        ipv4WildcardAlias=ipv4WildcardAlias,
                                                        ipv6WildcardAlias=ipv6WildcardAlias,
                                                        allowZoneTransfer=allowZoneTransfer,
                                                        dnssec=dnssec)
                result[t_d] = t_value
            return result

    def remove_domain_by_id(self, id):
        """
        Remove domain from DNS service.
        """
        return self.req_delete_data(f"dns/{id}")

    def remove_domain_by_hostname(self, hostname):
        """
        Remove domain from DNS service.
        """
        if not hostname:
            return
        t_id = self.__get_id_by_hostname__(hostname)
        if not t_id:
            print(f"{hostname} is not available")
            return False
        return self.remove_domain_by_id(t_id)

    def remove_domain_multiply(self, hostname_list):
        """
        Remove domain from DNS service multiply.
        """
        if not hostname_list or not isinstance(hostname_list, (tuple, list, set)) or len(hostname_list) == 0:
            return False
        all_domain_dict = self.get_all_domains_id()
        result = {}
        for t_d in hostname_list:
            if not t_d in all_domain_dict:
                print(f"{t_d} is not available")
                result[t_d] = False
                continue
            t_result_t = self.remove_domain_by_id(all_domain_dict[t_d])
            result[t_d] = t_result_t
        return result

    def get_root_domain_name_by_hostname(self, hostname):
        """
        Get the root domain name based on a hostname.
        """
        return self.req_get_data(f"dns/getroot/{hostname}")

    def get_dnssec_record_by_id(self, node_id):
        """
        DS record of DNSSEC for DNS service.
        """
        return self.req_post_data(f"dns/{node_id}/dnssec")

    def enable_dnssec(self, node_id):
        """
        Enable DNSSEC for DNS service.
        """
        return self.req_get_data(f"dns/{node_id}/dnses/enable")

    def disable_dnssec(self, node_id):
        """
        Disable DNSSEC for DNS service.
        """
        return self.req_get_data(f"dns/{node_id}/dnses/disable")

    def list_dns_records(self, node_id):
        """
        Get a list of DNS records for DNS service.
        """
        return self.req_get_data(f"dns/{node_id}/record")

    def get_dns_records_by_hostname(self, hostname):
        """
        Get DNS records based on a hostname and resource record type.
        """
        node_id = self.__get_id_by_hostname__(hostname)
        if node_id:
            t_value = self.list_dns_records(node_id)
            if t_value and isinstance(t_value, dict) and "dnsRecords" in t_value:
                return t_value['dnsRecords']
        return

    def get_dns_records_by_hostname_and_type(self, hostname, record_type="A"):
        """
        Get DNS records based on a hostname and resource record type.
        """
        t_value = self.req_get_data(f"dns/record/{hostname}?recordType={record_type}")
        if t_value and isinstance(t_value, dict) and "dnsRecords" in t_value:
            return t_value['dnsRecords']
        return

    def get_dns_record_details_by_id(self, node_id, record_id):
        """
        :param node_id:
        :param record_id:
        :return:
        """
        return self.req_get_data(f"dns/{node_id}/record/{record_id}")

    @staticmethod
    def __generate_record_data__(domain_name, record_type, ttl, state, group, record_value, **kwargs):
        """
        generate record data.
        """
        record_type = str(record_type).upper()
        data = {
            "nodeName": domain_name,
            "recordType": record_type,
            "ttl": ttl,
            "state": state,
            "group": group
        }
        if record_type == "A":
            data['ipv4Address'] = record_value
        elif record_type == 'AAAA':
            data['ipv6Address'] = record_value
        elif record_type == 'CNAME':
            data['host'] = record_value
        elif record_type == 'MX':
            data['host'] = record_value
            data['priority'] = kwargs['priority'] or 100
        elif record_type == 'SRV':
            data['host'] = record_value
            data['priority'] = kwargs['priority'] or 100
            data['weight'] = kwargs['weight'] or 100
            data['port'] = kwargs['port'] or 443
        elif record_type == 'TXT':
            data['textData'] = record_value
        else:
            print(f"{record_type} is not supported!")
            return {}
        return data

    def add_dns_record_by_id(self, domain_id, domain_name, record_type, ttl, state, group, record_value, **kwargs):
        """
        Add a new DNS record for DNS service.
        """

        data = self.__generate_record_data__(domain_name, record_type, ttl, state, group, record_value, **kwargs)
        if len(data) == 0:
            print(f"{record_type} is not supported!")
            return False
        return self.req_post_data(f"dns/{domain_id}/record", data)

    def add_dns_record_by_domain_name(self, domain_name, node_name, record_type, ttl=30, state=True, group="",
                                      record_value="", **kwargs):
        domain_id = self.__get_id_by_hostname__(domain_name)
        if not domain_id:
            print(f"{domain_name} is not available")
            return False
        return self.add_dns_record_by_id(domain_id, node_name, record_type, ttl, state, group, record_value, **kwargs)

    def update_dns_record(self, domain_id, dns_record_id, node_name, record_type, record_value, ttl=30, state=True,
                          group="", **kwargs):
        """
        Update an existing DNS record for DNS service.
        """
        record_type = str(record_type).upper()
        data = self.__generate_record_data__(node_name, record_type, ttl, state, group, record_value, **kwargs)
        if len(data) == 0:
            print(f"{record_type} is not supported!")
            return False
        return self.req_post_data(f"dns/{domain_id}/record/{dns_record_id}", data=data)

    def remove_dns_record(self, domain_id, dns_record_id):
        """
        Remove a DNS record from DNS service.
        """
        return self.req_delete_data(f"dns/{domain_id}/record/{dns_record_id}")

    def list_ip_update_history(self):
        """
        Get a list of IP address updates.
        """
        return self.req_get_data(f"dns/ipUpdateHistory")

    def list_groups(self):
        """
        Get a list of groups to which hosts are assigned to.
        """
        return self.req_get_data(f"dns/group")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--client-id', action="store", dest="client_id", type=str, help="Dynu OAuth2验证方式的client id")
    parser.add_argument('--secret', action="store", dest="secret", type=str, help="Dynu OAuth2验证方式的secret")
    parser.add_argument('--api-key', action="store", dest="api_key", type=str,  help="Dynu API Key验证方式的API key")
    parser.add_argument('--http-proxy', action="store", dest="http_proxy", type=str, help="Http(s) Proxy")
    parser.add_argument('--list-dn', action="store", dest="list_dn", type=str2bool, default=False, nargs='?',
                        const=True, help="列出所有主域名")
    parser.add_argument('--add-dn', action="store", dest="add_dn", type=str2bool, default=False, nargs='?',
                        const=True, help="增加域名解析")
    parser.add_argument('--update-dn', action="store", dest="update_dn", type=str2bool, default=False, nargs='?',
                        const=True, help="更新域名解析")
    parser.add_argument('--delete-dn', action="store", dest="delete_dn", type=str2bool, default=False, nargs='?',
                        const=True, help="删除域名解析")
    parser.add_argument('--list-record', action="store", dest="list_record", type=str2bool, default=False, nargs='?',
                        const=True, help="列出DNS记录")
    parser.add_argument('--add-record', action="store", dest="add_record", type=str2bool, default=False, nargs='?',
                        const=True, help="增加DNS记录")
    parser.add_argument('--update-record', action="store", dest="update_record", type=str2bool, default=False, nargs='?',
                        const=True, help="更新DNS记录")
    parser.add_argument('--delete-record', action="store", dest="delete_record", type=str2bool, default=False, nargs='?',
                        const=True, help="删除DNS记录")
    parser.add_argument("-d", '--domain-name', action="append", dest="domain_name_list", type=str, help="域名")
    parser.add_argument("-4", '--ipv4-address', action="store", dest="ipv4_addr", type=str, help="IPv4地址")
    parser.add_argument("-6", '--ipv6-address', action="store", dest="ipv6_addr", type=str, help="IPv6地址")
    parser.add_argument('--ipv4-wildcard', action="store", dest="ipv4_wildcard", type=str2bool, default=True, nargs='?',
                        const=True, help="ipv4地址是否为该域名子记录的通配解析记录")
    parser.add_argument('--ipv6-wildcard', action="store", dest="ipv6_wildcard", type=str2bool, default=True, nargs='?',
                        const=True, help="ipv6地址是否为该域名子记录的通配解析记录")
    parser.add_argument('--ttl', action="store", dest="ttl", type=int,  default=30, help="TTL")
    parser.add_argument("-a", '--alias', action="append", dest="alias_list", type=str, help="node(alias)名称、别名")
    parser.add_argument("-t", '--record-type', action="store", dest="record_type", type=str, help="记录类型")
    parser.add_argument("-e", '--record-value', action="append", dest="record_value_list", type=str, help="记录类型")
    parser.add_argument("-p", '--priority', action="store", dest="priority", type=int, default=10, help="优先级(限MX记录)")
    
    parser.add_argument("-v", "--version", action="store", dest="version", type=str2bool, default=False, nargs='?',
                        const=True, help="show version")
    args = parser.parse_args()

    if args.version:
        from src import __version__
        print(f"dynu-utils Version: {__version__}")
        sys.exit(0)

    if not args.api_key and not (args.client_id and args.secret):
        print("请指定API Key或者OAuth2的client id 和secret")
        sys.exit(1)
    if args.api_key and args.client_id and args.secret:
        print("请指定两种方式中的一种：API Key或者OAuth2的client id 和secret")
        sys.exit(1)
    proxies = {}
    if args.http_proxy:
        proxies = {"http": args.http_proxy, "https": args.http_proxy}
    t_mark = 0
    if args.list_dn:
        t_mark += 1
    if args.add_dn:
        t_mark += 1
    if args.update_dn:
        t_mark += 1
    if args.delete_dn:
        t_mark += 1
    if args.list_record:
        t_mark += 1
    if args.add_record:
        t_mark += 1
    if args.update_record:
        t_mark += 1
    if args.delete_record:
        t_mark += 1
    if t_mark != 1:
        print("--list-dn, --add-dn, --update-dn, --delete-dn, --list-record, --add-record, --update-record"
              " 和 --delete-record这八种操作有且只有一个")
        sys.exit(1)
    a = Dynu(client_id=args.client_id, secret=args.secret, api_key=args.api_key, proxies=proxies)
    # check parameters
    if args.list_dn:
        all_domains = a.get_all_domains_name()
        for d in all_domains:
            print(d)
        sys.exit(0)
    domain_list = []
    if not args.domain_name_list or len(args.domain_name_list) == 0:
        print("--domain-name不能为空")
        sys.exit(1)
    reg_rules = re.compile(r"[\s;,|]+")
    for t_d in args.domain_name_list:
        domain_list.extend(reg_rules.split(t_d))
    domain_list = [item.strip() for item in domain_list if len(item.strip()) > 0]
    domain_list = list(set(domain_list))
    if len(domain_list) == 0:
        print("--domain-name不能为空")
        sys.exit(1)
    if args.list_record:
        for d in domain_list:
            t_records_list = a.get_dns_records_by_hostname(d)
            print(f"Root Domain {d}:")
            for t_r in t_records_list:
                print(f"\t{t_r}")
            sys.exit(0)
    if args.add_record or args.update_record or args.delete_record:
        if not args.alias_list or len(args.alias_list) == 0:
            print("--node-name不能为空")
            sys.exit(1)
        if not args.record_type or args.record_type not in ('A', 'AAAA', 'MX', 'CNAME', 'TXT'):
            print("--record-type不能为空或者不在支持的范围内(目前仅支持'A', 'AAAA', 'MX', 'CNAME', 'TXT')")
            sys.exit(1)
    if args.add_record or args.update_record:
        if not args.record_value_list or len(args.record_value_list) == 0:
            print("--record-value不能为空")
            sys.exit(1)
    if args.add_dn:
        ipv4_addr = args.ipv4_addr or ""
        ipv6_addr = args.ipv6_addr or ""
        ttl = args.ttl or 30
        t_result = a.add_dns_service_multi(domain_list, ipv4Address=ipv4_addr, ipv6Address=ipv6_addr,
                                           ipv4WildcardAlias=args.ipv4_wildcard, ipv6WildcardAlias=args.ipv6_wildcard)
    elif args.update_dn:
        ipv4_addr = args.ipv4_addr or ""
        ipv6_addr = args.ipv6_addr or ""
        ttl = args.ttl or 30
        t_result = a.update_dns_by_multi(domain_list, ipv4Address=ipv4_addr, ipv6Address=ipv6_addr,
                                         ipv4WildcardAlias=args.ipv4_wildcard, ipv6WildcardAlias=args.ipv6_wildcard)
    elif args.delete_dn:
        a.remove_domain_multiply(domain_list)
    elif args.add_record:
        current_dn_list = a.get_all_domains_id()
        for t_d in domain_list:
            if t_d not in current_dn_list:
                print(f"{t_d} is not available")
                continue
            for t_r in args.alias_list:
                for t_v in args.record_value_list:
                    a.add_dns_record_by_id(current_dn_list[t_d], t_r, record_type=args.record_type, record_value=t_v,
                                           ttl=args.ttl, group=None, state=True, priority=args.priority)
    elif args.update_record:
        current_dn_list = a.get_all_domains_id()
        for t_d in domain_list:
            if t_d not in current_dn_list:
                print(f"{t_d} is not available")
                continue
            for t_r in args.alias_list:
                current_record_list = a.get_dns_records_by_hostname_and_type(f"{t_r}.{t_d}", args.record_type)
                t_i = 0
                t_m = min(len(current_record_list), len(args.record_value_list))
                while t_i < t_m:
                    t_d_id = current_record_list[t_i]['domainId']
                    t_r_id = current_record_list[t_i]['id']
                    t_r_value = args.record_value_list[t_i]
                    a.update_dns_record(t_d_id, t_r_id, t_r, args.record_type, record_value=t_r_value, ttl=args.ttl)
                    t_i += 1
                # delete extra records from current lib,
                if t_i < len(current_record_list):
                    while t_i < len(current_record_list):
                        a.remove_dns_record(current_record_list['domainId'], current_record_list[t_i]['id'])
                        t_i += 1
                # add extra records if we have more records which need be updated than it's have in lib
                if t_i < len(args.record_value_list):
                    while t_i < len(args.record_value_list):
                        t_v = args.record_value_list[t_i]
                        a.add_dns_record_by_id(current_dn_list[t_d], t_r, record_type=args.record_type, record_value=t_v,
                                               ttl=args.ttl, group=None, state=True, priority=args.priority)
    elif args.delete_record:
        current_dn_list = a.get_all_domains_id()
        for t_d in domain_list:
            if t_d not in current_dn_list:
                print(f"{t_d} is not available")
                continue
            for t_r in args.alias_list:
                current_record_list = a.get_dns_records_by_hostname_and_type(f"{t_r}.{t_d}", args.record_type)
                if not current_record_list:
                    print(f"{t_r}.{t_d} is not available!")
                    continue
                for t_record in current_record_list:
                    t_d_id = t_record['domainId']
                    t_r_id = t_record['id']
                    a.remove_dns_record(t_d_id, t_r_id)
    else:
        parser.print_usage()


if __name__ == '__main__':
    main()
