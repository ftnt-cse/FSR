import json, re
import requests, ipaddress
import paramiko

from connectors.core.connector import get_logger, ConnectorError

SSL_VALIDATION_ERROR = 'SSL certificate validation failed'
CONNECTION_TIMEOUT = 'The request timed out while trying to connect to the remote server'
REQUEST_READ_TIMEOUT = 'The server did not send any data in the allotted amount of time'
INVALID_URL_OR_CREDENTIALS = 'Invalid endpoint or credentials'
UNAUTHORIZED = 'Unauthorized'
LIST_OF_POLICIES_API = '/api/v2/cmdb/firewall/policy/'
LOGIN_API = '/logincheck'
GET_BLOCKED_IP = '/api/v2/cmdb/firewall/policy/{policy_id}/dstaddr/{ip}'
GET_ADDRESSES = '/api/v2/cmdb/firewall/address/{ip}?key=name&pattern={ip}'
ADD_ADDRESS = '/api/v2/cmdb/firewall/address/'
GET_POLICY = '/api/v2/cmdb/firewall/policy?vdom={vdom}&key=name&pattern={policy}'
LOGOUT_API = '/logout'
GET_LIST_OF_APPLICATIONS = '/api/v2/cmdb/application/name?with_meta=1'
BLOCK_APP = '/api/v2/cmdb/application/list/{app_block_policy}'
BLOCK_URL = '/api/v2/cmdb/webfilter/urlfilter/{url_profile_id}/entries'
GET_URL_PROFILE = '/api/v2/cmdb/webfilter/urlfilter?key=name&pattern={url_profile_name}'
GET_BLOCKED_URL = '/api/v2/cmdb/webfilter/urlfilter/{url_profile_id}/entries?key=url&pattern={url}'
UNBLOCK_URL = '/api/v2/cmdb/webfilter/urlfilter/{url_profile_id}/entries/{url_id}'
LIST_VDOM = '/api/v2/cmdb/system/vdom'
#VDOM = "config vdom\nedit {vdom_value}\n"
VDOM = "\n"
BAN_IP = 'diagnose user quarantine add {src} {ip_address} {duration} {cause}'
REMOVE_BAN = 'diagnose user quarantine delete {src} {ip_address}'
LIST_BANNED_IPS = 'diagnose user quarantine list'
UPDATE_POLICY_COMMAND = "config firewall policy\nedit {policy_id}\nset dstaddr {ips_list}"
src_value = {'IPv4': 'src4', 'IPv6': 'src6'}
ban_source_value = {'ADMIN': 'admin', 'DLP': 'dlp', 'IPS': 'ips', 'AV': 'av', 'DOS': 'dos'}
time_to_live_values = {'1 Hour': 3600, '6 Hour': 21600, '12 Hour': 43200, '1 Day': 86400, '6 Months': 1.577e+7,
                       '1 Year': 3.154e+7}
logger = get_logger('fortigate-firewall')


def _get_input(params, key, type=str):
    ret_val = params.get(key, None)
    if ret_val:
        if isinstance(ret_val, type):
            return ret_val
        else:
            logger.info("Parameter Input Type is Invalid: Parameter is: {0}, Required Parameter "
                        "Type is: {1}".format(str(key), str(type)))
            raise ConnectorError("Parameter Input Type is Invalid: Parameter is: {0}, Required "
                                 "Parameter Type is: {1}".format(str(key), str(type)))
    else:
        return None


def _get_config(config):
    verify_ssl = config.get("verify_ssl", None)
    address = _get_input(config, "address")
    port = _get_input(config, "port", type=int)
    server_url = '{0}:{1}'.format(address, port)
    username = _get_input(config, "username")
    password = _get_input(config, "password")
    if server_url[:7] != 'http://' and server_url[:8] != 'https://':
        server_url = 'https://{}'.format(str(server_url))
    return server_url, username, password, verify_ssl


def _api_request(config, url, body=None, method='get', decode_utf=True):
    try:
        server_url, username, password, verify_ssl = _get_config(config)
        url = server_url + url
        cookies = _get_cookies(server_url + LOGIN_API, username, password, verify_ssl,
                               method="post")
        csrftoken = ""
        for c in cookies:
            if c.name == 'ccsrftoken':
                csrftoken = c.value[1:-1]
                break
        if csrftoken == "" or csrftoken == "0%260":
            raise ConnectorError('Fail To Generate Token with Given Username And Password')
        header = {
            'content-Type': 'application/json;charset=UTF-8',
            'Accept': 'application/json',
            'X-CSRFTOKEN': csrftoken
        }
        api_response = requests.request(method, url=url, data=json.dumps(body), headers=header,
                                        verify=verify_ssl, cookies=cookies)
        logout = requests.post(url=server_url + LOGOUT_API, data=json.dumps(body), headers=header,
                               verify=verify_ssl, cookies=cookies)
        if api_response.ok:
            if decode_utf:
                return json.loads(api_response.content.decode('utf-8'))
            else:
                return api_response
        else:
            logger.info('Fail To request API {0} response is : {1}'.
                        format(str(url), str(api_response.content)))
            raise ConnectorError('Fail To request API {0} response is : {1}'.format(str(url),
                                                                                    str(api_response.content)))
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _get_cookies(server_url, username, password, verify_ssl, method="get"):
    try:
        payload = {
            'username': username,
            'secretkey': password
        }
        response = requests.request(method, server_url, verify=verify_ssl, data=payload)
        return response.cookies
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _get_url_profile_id(config):
    profile_name = _get_input(config, 'url_block_policy')
    if profile_name:
        response = _api_request(config, GET_URL_PROFILE.format(url_profile_name=profile_name))
        return response["results"][0]["id"]
    else:
        logger.info("URL Block Policy not Found")
        raise ConnectorError("URL Block Policy not Found")


def _get_app_block_profile(config):
    try:
        app_block_policy_name = _get_input(config, "app_block_policy")
        response = _api_request(config, BLOCK_APP.format(app_block_policy=app_block_policy_name))
        if response["status"] == "success":
            return response
        else:
            logger.info("Application Block Policy not Found")
            raise ConnectorError("Application Block Policy not Found")
    except Exception as Err:
        logger.info("Application Block Policy not Found : {}".format(str(Err)))
        raise ConnectorError("Application Block Policy not Found")


def _get_list_from_str_or_list(params, parameter, is_ip=False):
    try:
        parameter_list = params.get(parameter)
        if parameter_list:
            if isinstance(parameter_list, str):
                parameter_list = list(map(lambda x: x.strip(' '), parameter_list.split(",")))
                return parameter_list
            elif isinstance(parameter_list, list):
                return parameter_list
            if is_ip:
                for ip in parameter_list:
                    try:
                        ipaddress.ip_address(ip)
                    except Exception as Err:
                        logger.error(str(Err))
                        raise ConnectorError(str(Err))
        raise ConnectorError(
            "{0} Are Not in Format or Empty: {1}".format(parameter, parameter_list))
    except Exception as Err:
        raise ConnectorError(Err)


def _get_app_id(config, params, app_name_list):
    result = []
    # Get application details for getting application id
    all_apps_details = get_list_of_applications(config, params)
    app_id_list = []
    for app in app_name_list:
        temp_id = list(filter(lambda app_details: app == app_details["name"],
                              all_apps_details["results"]))
        if temp_id:
            app_id_list += temp_id
        else:
            result.append({"message": "Application not found in Fortigate database", "status":
                "Failed", "name": app})
    return result, app_id_list


def _is_address_available(config, ip):
    try:
        try:
            response = _api_request(config, GET_ADDRESSES.format(ip=ip))
            return response.get("results")[0].get("name")
        except:
            return False
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _get_policy(config, params, check_multiple_policy=False):
    block_ip_policy = _get_list_from_str_or_list(params, "ip_block_policy")
    try:
        vdom = _get_vdom(config, params, check_multiple_vdom=True)
        result = []
        for policy in block_ip_policy:
            response = _api_request(config, GET_POLICY.format(vdom=vdom[0], policy=policy))
            try:
                if response.get("results")[0].get("action") != 'deny':
                    logger.info('IP Block Policy {0} is action is not deny: {1}'.
                                format(block_ip_policy, response))
                    raise ConnectorError('IP Block Policy {0} is action is not deny: {1}'.
                                         format(block_ip_policy, response))
                result.append(response)
            except:
                logger.info("Policy not Found")
                raise ConnectorError("Policy not Found")
        return result if check_multiple_policy else result[0]
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _get_policy_id(config, params):
    try:
        response = _get_policy(config, params)
        return response.get("results")[0].get("policyid")
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _is_ip_blocked(config, ip, policy_id):
    try:
        try:
            response = _api_request(config, GET_BLOCKED_IP.format(policy_id=policy_id, ip=ip))
            if response["status"] == "success":
                return True
            else:
                return False
        except:
            return False
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _get_url_id(url, url_profile_id, config):
    try:
        response = _api_request(config, GET_BLOCKED_URL.format(
            url=url, url_profile_id=url_profile_id), method="get")
        if response["results"]:
            blaoked_urls = list(filter(lambda url_obj: url_obj["action"] == "block",
                                       response["results"]))
            if blaoked_urls:
                return blaoked_urls[0]["id"]
            else:
                logger.info("URL Not in Block State")
                raise ConnectorError("URL Not in Block State")
        else:
            logger.info("URL Not Found")
            raise ConnectorError("URL not Found")
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def check_health(config):
    try:
        server_url, username, password, verify_ssl = _get_config(config)
        payload = {
            'username': username,
            'secretkey': password
        }
        header = {
            'content-Type': 'application/json;charset=UTF-8',
            'Accept': 'application/json'
        }
        response = requests.post(server_url + LOGIN_API, verify=verify_ssl, data=payload)
        csrftoken = ""
        for c in response.cookies:
            if c.name == 'ccsrftoken':
                csrftoken = c.value[1:-1]
                break
        if csrftoken == "" or csrftoken == "0%260":
            raise ConnectorError(INVALID_URL_OR_CREDENTIALS)
        else:
            logout = requests.post(url=server_url + LOGOUT_API, data=json.dumps(payload),
                                   headers=header, verify=verify_ssl, cookies=response.cookies)
            return True
    except requests.exceptions.SSLError:
        raise ConnectorError(SSL_VALIDATION_ERROR)
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError(CONNECTION_TIMEOUT)
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(REQUEST_READ_TIMEOUT)
    except requests.exceptions.ConnectionError:
        raise ConnectorError(INVALID_URL_OR_CREDENTIALS)
    except Exception as e:
        raise ConnectorError(str(e))


def _prepare_ssh_client(config, **kwargs):
    try:
        # extract host info
        host = config.get('address').replace('https://', '')
        port = 22  # config.get('port')
        username = config.get('username')
        password = config.get('password')
        verify_ssl = config.get('verify_ssl')
        rsa_key = None
        client = paramiko.client.SSHClient()
        client.set_missing_host_key_policy(paramiko.client.AutoAddPolicy())
        client.load_system_host_keys()
        client.connect(host, port=port, username=username, password=password, pkey=rsa_key,
                       allow_agent=False, look_for_keys=False)
        return client
    except Exception as Err:
        raise ConnectorError(str(Err))


def run_remote_command(config, cmd_list, **kwargs):
    try:
        client = _prepare_ssh_client(config, **kwargs)
        if not cmd_list:
            return []
        cmd_output = []

        for cmd in cmd_list:
            logger.info('cmd: {}'.format(cmd))
            streams = client.exec_command(cmd, timeout=int(config.get('timeout')), get_pty=True)
            logger.info('streams: {}'.format(streams))
            stdin, stdout, stderr = streams
            error_str = stderr.read().decode('utf-8')
            if len(error_str) > 0:
                logger.error("Failed command execution with error [{0}]. "
                             "Commands executed successfully [{1}]".format(error_str, str(cmd_output)))
                raise ConnectorError("Failed command execution with error [{0}]. Refer log file"
                                     " for more details".format(error_str))
            result = stdout.read().decode('utf-8').strip()
            cmd_output.append({"command": cmd, "output": result.split("\r\n")})
            if "Command fail." in result:
                logger.error("Command Fail to Execute {}".format(str(cmd_output)))
                raise ConnectorError("Command Fail to Execute {}".format(str(cmd_output)))
        client.close()
        return cmd_output
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def add_bulk_address(config, params, ip_list):
    vdom = _get_vdom(config, params)
    status = False
    if vdom:
        for vdom_value in vdom:
            cmd = VDOM.format(vdom_value=vdom_value) + 'config firewall address'
            try:
                for ip in ip_list:
                    cmd += '{new_line}edit "{ip}"{new_line}set subnet {ip}/32{new_line}next'.format(new_line='\n',
                                                                                                    ip=ip)
                cmd += '\nend'
                return run_remote_command(config, [cmd])
            except Exception as err:
                logger.exception(err)
    return status


def _get_vdom(config, params, check_multiple_vdom=False):
    vdom = None
    try:
        vdom = _get_list_from_str_or_list(params, "vdom")
    except Exception as e:
        logger.debug('vdom not provided as param. Check config vdom otherwise set vdom to default value "root".')
    # Default VDOM is root if VDOM is not found in config or params
    if vdom is None:
        try:
            vdom = _get_list_from_str_or_list(config, "vdom")
        except Exception as e:
            logger.debug('vdom not provided as config. Set vdom to default value "root".')
    if vdom is None:
        vdom = ["root"]
    if check_multiple_vdom:
        if len(vdom) > 1:
            logger.error("Action is not supported for multiple vdom")
            raise ConnectorError("Action is not supported for multiple vdom")
    return vdom


def _block_ip(config, params):
    list_vdom = _api_request(config, LIST_VDOM).get('results')
    vdom_names = [i.get('name') for i in list_vdom]
    vdom_not_exists = []
    try:
        ip_address_list = _get_list_from_str_or_list(params, 'ip_addresses', is_ip=True)
        src = src_value.get(_get_input(params, 'src'))
        time_to_live = _get_input(params, 'time_to_live')
        if time_to_live == "Custom Time":
            duration = _get_input(params, 'duration', type=int)
        else:
            duration = time_to_live_values.get(time_to_live)
        cause = ban_source_value.get(_get_input(params, 'cause'))
        vdom = _get_vdom(config, params)
        if vdom:
            cmd_list = []
            for vdom_value in vdom:
                if vdom_value in vdom_names:
                    cmd = VDOM.format(vdom_value=vdom_value)
                    for ip in ip_address_list:
                        cmd = cmd + BAN_IP.format(ip_address=ip, duration=duration, cause=cause, src=src) + "\n"
                    if len(cmd) > 255381:
                        logger.info("IP Address limit exceeded")
                        raise ConnectorError("IP Address limit exceeded")
                    cmd_list.append(cmd + "end\n")
                else:
                    vdom_not_exists.append(vdom_value)
        else:
            logger.info("VDOM is not provided")
            cmd = BAN_IP.format(ip_address=ip, duration=duration, cause=cause, src=src) + "\n"
            cmd_list.append(cmd + "end\n")
            #raise ConnectorError("VDOM is not provided")
        result = run_remote_command(config, cmd_list)
        response = {'result': result}
        if not result:
            logger.error("VDOM: {} does not exist".format(','.join(vdom_not_exists)))
            raise ConnectorError('VDOM: {} does not exist'.format(','.join(vdom_not_exists)))
        else:
            response.update({'vdom_not_exist': vdom_not_exists})
        return response
    except Exception as Err:
        logger.exception(str(Err))
        raise ConnectorError(str(Err))


def block_ip(config, params):
    method = params.get("method")
    try:
        if "Diagnose Base Block" == method:
            return _block_ip(config, params)
        else:
            return policy_base_block_ip(config, params)
    except Exception as e:
        logger.exception('Failed to block IP address with error {}'.format(e))
        raise ConnectorError('Failed to block IP address with error {}'.format(e))


def policy_base_block_ip(config, params):
    result = {'already_blocked': [], 'newly_blocked': [], 'error_with_block': []}
    block_ip_policy = _get_input(params, 'ip_block_policy')

    cmd_list = []
    current_ip_list = []
    created_address_list = []
    ip_list = _get_list_from_str_or_list(params, 'ip', is_ip=True)
    vdom = _get_vdom(config, params, check_multiple_vdom=True)[0]
    list_vdom = _api_request(config, LIST_VDOM).get('results')
    vdom_names = [i.get('name') for i in list_vdom]
    if vdom not in vdom_names:
        logger.error("VDOM: {} does not exist".format(vdom))
        raise ConnectorError('VDOM: {} does not exist'.format(vdom))

    vdom_policy_data = get_list_of_policies(config, params)
    policy_names = [x for x in vdom_policy_data.get('result')[0].get('results') if x.get('name') == block_ip_policy]
    if not policy_names:
        logger.error('{policy} policy not exists in {vdom} VDOM'.format(policy=block_ip_policy, vdom=vdom))
        raise ConnectorError('{policy} policy not exists in {vdom} VDOM'.format(policy=block_ip_policy, vdom=vdom))
    block_ips_obj = policy_names[0].get("dstaddr")
    blocked_ips = list(map(lambda ip: ip.get("name"), block_ips_obj))
    ip_list = list(set(ip_list))  # Removed duplicate
    for ip in ip_list:
        if ip not in blocked_ips:
            current_ip_list.append(ip)
        else:
            result['already_blocked'].append(ip)

    end_index = batch_size = 3000
    start_index = 0

    while start_index < len(current_ip_list):
        new_ip_list = current_ip_list[start_index: end_index]
        if add_bulk_address(config, params, new_ip_list):
            created_address_list += new_ip_list
        else:
            result['not_block'] += new_ip_list
        start_index = end_index
        end_index += batch_size
    result['newly_blocked'] = created_address_list

    if len(current_ip_list) == 0:
        return result
    policy_id = policy_names[0].get("policyid")
    if vdom:
        cmd = VDOM.format(vdom_value=vdom) + UPDATE_POLICY_COMMAND.format(policy_id=policy_id,
                                                                          ips_list=' '.join(
                                                                              blocked_ips + created_address_list))
        cmd_list.append(cmd + "\nend\n")
    run_remote_command(config, cmd_list)
    return result


def _unblock_ip(config, params):
    list_vdom = _api_request(config, LIST_VDOM).get('results')
    vdom_names = [i.get('name') for i in list_vdom]
    vdom_not_exists = []
    try:
        ip_address_list = _get_list_from_str_or_list(params, 'ip_addresses', is_ip=True)
        src = src_value.get(_get_input(params, 'src'))
        vdom = _get_vdom(config, params)
        if vdom:
            cmd_list = []
            for vdom_value in vdom:
                if vdom_value in vdom_names:
                    cmd = VDOM.format(vdom_value=vdom_value)
                    for ip in ip_address_list:
                        cmd = cmd + REMOVE_BAN.format(ip_address=ip, src=src) + "\n"
                    if len(cmd) > 255381:
                        logger.info("IP Address limit exceeded")
                        raise ConnectorError("IP Address limit exceeded")
                    cmd_list.append(cmd + "end\n")
                else:
                    vdom_not_exists.append(vdom_value)
        else:
            logger.info("VDOM is not provided")
            raise ConnectorError("VDOM is not provided")
        result = run_remote_command(config, cmd_list)
        response = {'result': result}
        if not result:
            logger.error("VDOM: {} does not exist".format(','.join(vdom_not_exists)))
            raise ConnectorError('VDOM: {} does not exist'.format(','.join(vdom_not_exists)))
        else:
            response.update({'vdom_not_exist': vdom_not_exists})
        return response
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def unblock_ip(config, params):
    method = params.get("method")
    if "Diagnose Base Unblock" == method:
        return _unblock_ip(config, params)
    else:
        return policy_base_unblock_ip(config, params)


def policy_base_unblock_ip(config, params):
    result = {'not_exist': [], 'newly_unblocked': [], 'error_with_unblock': []}
    vdom = _get_vdom(config, params, check_multiple_vdom=True)[0]
    list_vdom = _api_request(config, LIST_VDOM).get('results')
    vdom_names = [i.get('name') for i in list_vdom]
    current_unblock_ips = []
    if vdom not in vdom_names:
        logger.error("VDOM: {} does not exist".format(vdom))
        raise ConnectorError('VDOM: {} does not exist'.format(vdom))
    ip_list = _get_list_from_str_or_list(params, 'ip', is_ip=True)
    blocked_ips = policy_base_get_blocked_ips(config, params)
    for ip in ip_list:
        if ip in blocked_ips:
            current_unblock_ips.append(ip)
        else:
            result['not_exist'].append(ip)
    if len(current_unblock_ips) == 0:
        return result
    current_block_ips = list(set(blocked_ips) - set(current_unblock_ips))
    if not current_block_ips:
        raise ConnectorError('While configure policy at least one IP should be present.')
    cmd_list = []
    policy_id = _get_policy_id(config, params)
    if vdom:
        cmd = VDOM.format(vdom_value=vdom) + UPDATE_POLICY_COMMAND.format(policy_id=policy_id,
                                                                          ips_list=' '.join(current_block_ips))
        cmd_list.append(cmd + "\nend\n")

    run_remote_command(config, cmd_list)
    result['newly_unblocked'] = current_unblock_ips
    return result


def get_list_of_policies(config, params):
    try:
        vdom_not_exists = []
        list_vdom = _api_request(config, LIST_VDOM).get('results')
        vdom_names = [i.get('name') for i in list_vdom]
        vdom_list = _get_vdom(config, params)
        policy_list = []
        if vdom_list:
            for vdom in vdom_list:
                if vdom not in vdom_names:
                    vdom_not_exists.append(vdom)
                else:
                    endpoint = LIST_OF_POLICIES_API if (
                        vdom == 'root') else LIST_OF_POLICIES_API + '?vdom={vdom}'.format(vdom=vdom)
                    result = _api_request(config, endpoint)
                    policy_list.append(result)
        response = {'result': policy_list}
        if not policy_list:
            logger.error("VDOM: {} does not exist".format(','.join(vdom_not_exists)))
            raise ConnectorError('VDOM: {} does not exist'.format(','.join(vdom_not_exists)))
        else:
            response.update({'vdom_not_exist': vdom_not_exists})
        return response
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def _get_blocked_ip(config, params):
    try:
        vdom_not_exists = []
        list_vdom = _api_request(config, LIST_VDOM).get('results')
        vdom_names = [i.get('name') for i in list_vdom]
        vdom = _get_vdom(config, params)
        if vdom:
            cmd_list = []
            for v in vdom:
                if v not in vdom_names:
                    vdom_not_exists.append(v)
                else:
                    cmd = VDOM.format(vdom_value=v) + LIST_BANNED_IPS
                    cmd_list.append(cmd + "\nend\n")
        else:
            logger.info("VDOM is not provided")
            raise ConnectorError("VDOM is not provided")
        result = run_remote_command(config, cmd_list)
        response = {}
        if not result:
            logger.error("VDOM: {} does not exist".format(','.join(vdom_not_exists)))
            raise ConnectorError('VDOM: {} does not exist'.format(','.join(vdom_not_exists)))
        else:
            for data in result:
                ipv4_list = re.findall(r'[0-9]+(?:\.[0-9]+){3}', '\r\n'.join(data.get('output', "")))
                ipv6_list = re.findall(
                    r"(?:(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){6})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:::(?:(?:(?:[0-9a-fA-F]{1,4})):){5})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){4})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,1}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){3})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,2}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:(?:[0-9a-fA-F]{1,4})):){2})(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,3}(?:(?:[0-9a-fA-F]{1,4})))?::(?:(?:[0-9a-fA-F]{1,4})):)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,4}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9]))\.){3}(?:(?:25[0-5]|(?:[1-9]|1[0-9]|2[0-4])?[0-9])))))))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,5}(?:(?:[0-9a-fA-F]{1,4})))?::)(?:(?:[0-9a-fA-F]{1,4})))|(?:(?:(?:(?:(?:(?:[0-9a-fA-F]{1,4})):){0,6}(?:(?:[0-9a-fA-F]{1,4})))?::))))",
                    '\r\n'.join(data.get('output', "")))
                data['output'] = ipv4_list + ipv6_list
            response.update({'result': result})
            response.update({'vdom_not_exist': vdom_not_exists})
        return response
    except Exception as Err:
        logger.error(str(Err))
        raise ConnectorError(str(Err))


def get_blocked_ip(config, params):
    method = params.get("method")
    if "Diagnose Base Block" == method:
        return _get_blocked_ip(config, params)
    else:
        return policy_base_get_blocked_ips(config, params, check_multiple_policy=True)


def policy_base_get_blocked_ips(config, params, check_multiple_policy=False):
    result_data = []
    try:
        vdom = _get_vdom(config, params, check_multiple_vdom=True)[0]
        list_vdom = _api_request(config, LIST_VDOM).get('results')
        vdom_names = [i.get('name') for i in list_vdom]
        if vdom not in vdom_names:
            logger.error("VDOM: {} not exist".format(vdom))
            raise ConnectorError('VDOM: {} not exist'.format(vdom))
        policy_list = _get_policy(config, params, check_multiple_policy=check_multiple_policy)
        if not check_multiple_policy:
            block_ips_obj = policy_list.get("results")[0].get("dstaddr")
            return list(map(lambda ip: ip.get("name"), block_ips_obj))
        else:
            for policy in policy_list:
                block_ips_obj = policy.get("results")[0].get("dstaddr")
                result_data.append(
                    {policy.get("results")[0].get("name"): list(map(lambda ip: ip.get("name"), block_ips_obj))})
        return result_data if check_multiple_policy else result_data[0]
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_list_of_applications(config, params):
    try:
        return _api_request(config, GET_LIST_OF_APPLICATIONS)
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def block_applications(config, params):
    try:
        block_policy = {'rate-duration': 60, 'protocols': 'all', 'shaper': '', 'id': 1,
                        'session-ttl': 0, 'application': [], 'log-packet': 'disable',
                        'behavior': 'all', 'technology': 'all', 'sub-category': [],
                        'action': 'block', 'rate-count': 0, 'category': [], 'q_origin_key': 1,
                        'tags': [], 'risk': [], 'rate-track': 'none', 'shaper-reverse': '',
                        'log': 'enable', 'quarantine-expiry': '5m', 'vendor': 'all',
                        'quarantine-log': 'enable', 'rate-mode': 'continuous', 'per-ip-shaper': '',
                        'parameters': [], 'popularity': '1 2 3 4 5', 'quarantine': 'none'}
        app_block_policy_name = _get_input(config, "app_block_policy")
        app_name_list = _get_list_from_str_or_list(params, 'app_list')
        result, app_id_list = _get_app_id(config, params, app_name_list)
        # Get default application block policy
        block_policy_details = _get_app_block_profile(config)
        # Finding all block policy.
        # if block_policy_details["results"][0]["entries"]:
        temp_policy = list(filter(lambda app: app["action"] == "block",
                                  block_policy_details["results"][0]["entries"]))
        if not temp_policy:
            temp_policy = [block_policy]
            # Creating new block policy and put it into 1st position and change all policy sequence incrementing by 1.
            for policy in block_policy_details["results"][0]["entries"]:
                policy["q_origin_key"] = policy["q_origin_key"] + 1
                policy["id"] = policy["id"] + 1
            block_policy_details["results"][0]["entries"] = temp_policy + \
                                                            block_policy_details["results"][0]["entries"]
        for app in app_id_list:
            block_found = list(filter(lambda app_id: app_id["id"] == app["id"],
                                      temp_policy[0]["application"]))
            if block_found:
                result.append({"message": "Application Already Blocked", "name": app["name"],
                               "status": "Successful"})
            else:
                temp_policy[0]["application"] += [{"id": app["id"], "q_origin_key": app["id"]}]
                result.append({"name": app["name"], "message": "Application Block Successfully",
                               "status": "Successful"})
        response = _api_request(config, BLOCK_APP.format(app_block_policy=app_block_policy_name)
                                , method="put", body=block_policy_details["results"][0])
        if response["status"] == "success":
            return result
        else:
            result = []
            for app in app_name_list:
                result.append(
                    {"name": app, "message": "Application Block Fail", "status": "Failed"})
            return result
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def unblock_applications(config, params):
    try:
        app_block_policy_name = _get_input(config, "app_block_policy")
        app_name_list = _get_list_from_str_or_list(params, 'app_list')
        result, app_id_list = _get_app_id(config, params, app_name_list)
        # Get default application block policy
        block_policy_details = _get_app_block_profile(config)
        # Finding all block policy.
        block_policy_list = list(
            filter(lambda app: app["action"] == "block",
                   block_policy_details["results"][0]["entries"]))
        if block_policy_list:
            for policy in block_policy_list:
                for app_id in app_id_list:
                    block_found = list(filter(lambda app: app["id"] == app_id["id"],
                                              policy["application"]))
                    if block_found:
                        policy["application"].remove(block_found[0])
                        result.append({"name": str(app_id["name"]), "message":
                            "Application Unblock Successfully", "status": "Successful"})
                    else:
                        app_name = [i['name'] for i in result]
                        if app_id["name"] not in app_name:
                            result.append({"name": str(app_id["name"]), "message":
                                "Application Not Found in Block State", "status": "Successful"})
            response = _api_request(config, BLOCK_APP.format(app_block_policy=app_block_policy_name)
                                    , method="put", body=block_policy_details["results"][0])
            if response["status"] == "success":
                return result
        logger.exception("Application block policy not found")
        result = []
        for app in app_name_list:
            result.append({"name": app, "message": "Application Unblock Fail", "status": "Failed"})
        return result
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_blocked_applications(config, params):
    try:
        app_block_policy_name = _get_input(config, "app_block_policy")
        all_apps_details = get_list_of_applications(config, params)
        # Get default application block policy
        block_policy_details = _api_request(config, BLOCK_APP.format(app_block_policy=
                                                                     app_block_policy_name))
        # Finding all block policy.
        block_policy_list = list(
            filter(lambda app: app["action"] == "block",
                   block_policy_details["results"][0]["entries"]))
        app_id_list = []
        for policy in block_policy_list:
            app_id_list += list(map(lambda app_id: app_id["id"], policy["application"]))
        block_app_details = []
        for app in app_id_list:
            block_app_details += list(filter(lambda app_details: app_details["id"] == app,
                                             all_apps_details["results"]))
        return block_app_details
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def block_url(config, params):
    try:
        list_urls = get_blocked_urls(config, params)
        url_names = [i.get('url') for i in list_urls]
        url = _get_input(params, 'url')
        if url in url_names:
            logger.error('URL {} already blocked.'.format(url))
            raise ConnectorError('URL {} already blocked.'.format(url))
        url_profile_id = _get_url_profile_id(config)
        payload = {
            "status": "enable",
            "exempt": "av web-content activex-java-cookie dlp fortiguard range-block all",
            "web-proxy-profile": "",
            "action": "block",
            "type": "simple",
            "url": url,
            "referrer-host": "",
        }
        response = _api_request(config, BLOCK_URL.format(url_profile_id=url_profile_id),
                                method="post", body=payload)
        if response["status"] == "success":
            return {"message": "URL block Successfully", "name": url, "status": "Successful"}
        return response
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def unblock_url(config, params):
    try:
        url = _get_input(params, 'url')
        url_profile_id = _get_url_profile_id(config)
        url_id = _get_url_id(url, url_profile_id, config)
        response = _api_request(config, UNBLOCK_URL.format(url_profile_id=url_profile_id,
                                                           url_id=url_id), method="delete")
        if response["status"] == "success":
            return {"message": "URL Unblock Successfully", "name": url, "status": "Successful"}
        return response
    except Exception as Err:
        logger.exception(Err)
        raise ConnectorError(Err)


def get_blocked_urls(config, params):
    profile_name = _get_input(config, 'url_block_policy')
    if profile_name:
        response = _api_request(config, GET_URL_PROFILE.format(url_profile_name=profile_name))
        return list(filter(lambda url_obj: url_obj["action"] == "block",
                           response["results"][0]["entries"]))
    else:
        logger.info("Policy not Found")
        raise ConnectorError("Policy not Found")


fortigate_operations = {
    'get_list_of_policies': get_list_of_policies,
    'block_ip': block_ip,
    'unblock_ip': unblock_ip,
    'get_blocked_ip': get_blocked_ip,
    'get_list_of_applications': get_list_of_applications,
    'block_applications': block_applications,
    'unblock_applications': unblock_applications,
    'get_blocked_applications': get_blocked_applications,
    'block_url': block_url,
    'unblock_url': unblock_url,
    'get_blocked_urls': get_blocked_urls
}
