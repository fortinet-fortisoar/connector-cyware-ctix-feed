""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import time, base64, hashlib, hmac
from requests import request, exceptions as req_exceptions
from connectors.core.connector import get_logger, ConnectorError
from datetime import datetime
logger = get_logger('cyware-feed')


class CywareFeed:
    def __init__(self, config):
        self.base_url = config.get('server').strip('/')
        if not self.base_url.startswith('https://'):
            self.base_url = 'https://{0}'.format(self.base_url)
        self.access_id = config['access_id']
        self.secret_key = config['secret_key']
        self.verify_ssl = config['verify_ssl']
        self.headers = {'content-type': 'application/json'}

    def get_signature(self, expires):
        to_sign = '%s\n%i' % (self.access_id, expires)
        return base64.b64encode(hmac.new(self.secret_key.encode('utf-8'), to_sign.encode('utf-8'),
                                         hashlib.sha1).digest()).decode('utf-8')

    def make_rest_call(self, endpoint, params={}, method='GET'):
        service_endpoint = '{0}{1}'.format(self.base_url, endpoint)
        expires = int(time.time() + 30)
        params['AccessID'] = self.access_id
        params['Expires'] = expires
        params['Signature'] = self.get_signature(expires)
        try:
            response = request(method, service_endpoint, verify=self.verify_ssl, params=params)
            if response.status_code in [200, 201, 204]:
                if response.text != "":
                    return response.json()
                else:
                    return True
            else:
                if response.text != "":
                    err_resp = response.json()
                    if isinstance(err_resp['error'], list):
                        failure_msg = err_resp['error'][0]['message']
                    else:
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


def build_params(config, params):
    new_params = {"version": config.get("version")}
    for k, v in params.items():
        if v is not None and v != '':
            if k in ("from_timestamp", "to_timestamp") and isinstance(v, str):
                new_params[k] = int(datetime.fromisoformat(v[:-1]).timestamp())
            else:
                new_params[k] = v
    return new_params


def get_save_result_set_data(config, params):
    ob = CywareFeed(config)
    params = build_params(config, params)
    return ob.make_rest_call("/ingestion/rules/save_result_set/", params=params)


def get_indicators(config, params):
    ob = CywareFeed(config)
    params = build_params(config, params)
    response = ob.make_rest_call("/ingestion/rules/save_result_set/", params=params)
    results = response.get("results", [])
    data, indicator_data = [], []
    for _result in results:
        data.extend(_result.get("data", []))
    for obj in data:
        if obj.get("sdo_type") == "indicator":
            indicator_data.append(obj)
    response.update({"results": indicator_data})
    return response


def get_save_result_set_indicators(config, params):
    fetch_all_records = False
    if not params.get("page") and not params.get("page_size"):
        fetch_all_records = True
    if fetch_all_records:
        page, indicators, resp_indicators = 1, list(), True
        while resp_indicators:
            params.update({"page": page, "page_size": 100})
            response = get_indicators(config, params)
            resp_indicators = response.get("results", [])
            indicators += resp_indicators
            page += 1
        response.update({"results": indicators})
        response.pop("page", None)
    else:
        response = get_indicators(config, params)
    return response


def _check_health(config):
    ob = CywareFeed(config)
    params = {
        "version": config.get("version"),
        "from_timestamp": int(datetime.now().timestamp())
    }
    resp = ob.make_rest_call("/ingestion/rules/save_result_set/", params=params)
    return True


operations = {
    "get_save_result_set_data": get_save_result_set_data,
    "get_save_result_set_indicators": get_save_result_set_indicators
}
