""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import base64
from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError
from connectors.core.utils import update_connnector_config
from .constant import *
from datetime import datetime, timedelta


logger = get_logger("commvault")


class Commvault:
    def __init__(self, config, connector_info, *args, **kwargs):
        """
        For documentation refer
        1. https://documentation.commvault.com/v11/essential/45578_rest_api_authentication_post_login.html
        2. https://documentation.commvault.com/v11/essential/45551_rest_api_postman.html
        Note: The token by default is valid for 30 minutes
        """
        pwd = bytes(config.get("password"), encoding='utf8')
        pwd = str(base64.b64encode(pwd), encoding='utf-8')
        server_url = config.get("server_url")
        if not server_url.startswith('https://') and not server_url.startswith('http://'):
            server_url = "https://"+server_url
        self.url = server_url
        self.username = config.get("username")
        self.password = pwd
        self.verify_ssl = config.get("verify_ssl")
        self.token = self.get_token(config, connector_info, **kwargs)

    def get_token(self, config, connector_info, **kwargs):
        token = config.get("token")
        expiry_in = config.get("expiry_in")
        check_health = kwargs.get("check_health")
        if not check_health and token and expiry_in and datetime.fromtimestamp(int(expiry_in)) > datetime.now():
            return token
        else:
            data = {
              "username": self.username,
              "password": self.password
            }
            current_time = datetime.now() + timedelta(minutes=EXPIRY_TIME)
            headers = dict()
            headers["Accept"] = "application/json"
            headers["Content-Type"] = "application/json"
            response = self.api_request(Method.POST, Endpoint.LOGIN, self.url+Endpoint.LOGIN, data=data)
            token = response.get("token")
            config["token"] = token
            config["expiry_in"] = int(current_time.timestamp())
            update_connnector_config(connector_info["connector_name"],
                                     connector_info["connector_version"],
                                     config,
                                     config["config_id"])
            return token

    def api_request(self, method, endpoint, params={}, data={}):
        try:
            endpoint = self.url + endpoint
            headers = dict()
            headers["Accept"] = "application/json"
            if Endpoint.LOGIN not in endpoint:
                headers["Authtoken"] = self.token
            if data:
                headers["Content-Type"] = "application/json"
            response = request(method, endpoint, headers=headers, params=params,
                               data=data, verify=self.verify_ssl)

            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.json()
                    failure_msg = err_resp['error']['message']
                    error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                         failure_msg if failure_msg else '')
                else:
                    error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
                logger.error(error_msg)
                raise ConnectorError(error_msg)
        except req_exceptions.SSLError:
            logger.error('An SSL error occurred')
            raise ConnectorError('An SSL error occurred')
        except req_exceptions.ConnectionError:
            logger.error('A connection error occurred')
            raise ConnectorError('A connection error occurred')
        except req_exceptions.Timeout:
            logger.error('The request timed out')
            raise ConnectorError('The request timed out')
        except req_exceptions.RequestException:
            logger.error('There was an error while handling the request')
            raise ConnectorError('There was an error while handling the request')
        except Exception as err:
            raise ConnectorError(str(err))


def check_health_ex(config, connector_info):
    try:
        Commvault(config, connector_info, check_health=True)
        return True
    except Exception as err:
        raise ConnectorError(str(err))


def get_payload_data(input_params):
    data = dict()
    for param_key in QUERY_PARAMS:
        param_value = input_params.get(param_key)
        if param_value:
            if param_key == "password":
                pwd = bytes(param_value, encoding='utf8')
                pwd = str(base64.b64encode(pwd), encoding='utf-8')
                data.update({"password": pwd, "validationParameters": {"password": pwd}})
            elif param_key == "userGroupNames":
                li = param_value.split(",")
                group_names = list()
                for group_name in li:
                    group_names.append({"userGroupName": group_name})
                data.update({"associatedUserGroups": group_names})
            elif param_key == "userName":
                data.update({"userEntity": {"userName": param_value}})
            else:
                data.update({param_key: param_value})
    payload_data = {"users": [data]}
    return payload_data


def list_of_alerts(config, params, connector_info):
    ob = Commvault(config, connector_info)
    return ob.api_request(Method.GET, Endpoint.ALERT_RULE)


def alert_details(config, params, connector_info):
    ob = Commvault(config, connector_info)
    return ob.api_request(Method.GET, Endpoint.ALERT_RULE + f"/{params.get('alert_id', '')}")


def list_of_users(config, params, connector_info):
    ob = Commvault(config, connector_info)
    filter_params = dict()
    level = params.get("level")
    level and filter_params.update({"level": level})
    return ob.api_request(Method.GET, Endpoint.USER, params=filter_params)


def update_user(config, params, connector_info):
    ob = Commvault(config, connector_info)
    return ob.api_request(Method.POST, Endpoint.USER + f"/{params.pop('user_id', '')}", data=get_payload_data(params))


operations = {
    "list_of_alerts": list_of_alerts,
    "alert_details": alert_details,
    "list_of_users": list_of_users,
    "update_user": update_user
}
