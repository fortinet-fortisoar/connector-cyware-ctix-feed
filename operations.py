""" Copyright start
  Copyright (C) 2008 - 2020 Fortinet Inc.
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
            return mock_output(method, service_endpoint, verify=self.verify_ssl, params=params)
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


def mock_output(method, endpoint, verify=False, params={}):
    logger.error(f"------------------\nmethod: {method} \n endpoint: {endpoint} \n params: {params} \n")
    null, true, false = None, True, False
    return {
      "next": null,
      "previous": null,
      "page_size": 10,
      "total": 1,
      "results": [
        {
          "id": "92c6c68a-ceda-42c2-bbc5-1fd6c8fac72e",
          "ctix_created": 1649406695,
          "ctix_modified": 1649406695,
          "version": "v3",
          "ctix_tags": [
            {
              "id": "acb6cafe-c688-4d10-884e-f00123dd1d42",
              "name": "two",
              "type": "manual",
              "created": 1649406622,
              "modified": 1649406622,
              "created_by": {
                "id": "59f01fa7-3628-4218-b123-c00243881adc",
                "email": "John@gmail.com",
                "last_name": "John",
                "first_name": "John"
              },
              "colour_code": "#0068FA",
              "modified_by": {
                "id": "59f01fa7-3628-4218-b123-c00243881adc",
                "email": "John@gmail.com",
                "last_name": "John",
                "first_name": "John"
              }
            }
          ],
          "data": [
            {
              "id": "b66e8954-fb19-4a02-afad-8dc5ae5666a6",
              "created": 1649406693.362959,
              "sources": [
                {
                  "tlp": "WHITE",
                  "name": "Import",
                  "score": 70,
                  "last_seen": null,
                  "first_seen": 1649406693
                }
              ],
              "ctix_tlp": null,
              "modified": 1649406693.362999,
              "sdo_name": "3.2.1.1",
              "sdo_type": "indicator",
              "ctix_score": null,
              "analyst_tlp": null,
              "ctix_created": 1649406693.489487,
              "is_whitelist": false,
              "ctix_modified": 1649406693.489505,
              "is_deprecated": false,
              "indicator_type": {
                "type": "ipv4-addr",
                "attribute_field": "value"
              },
              "is_false_positive": false
            },
            {
              "id": "835652d2-0f25-4917-bbc1-c2f7e9972edd",
              "created": 1649402138.175512,
              "sources": [
                {
                  "tlp": "GREEN",
                  "name": "Import",
                  "score": 83,
                  "last_seen": null,
                  "first_seen": 1649402138
                }
              ],
              "ctix_tlp": null,
              "modified": 1649402138.175567,
              "sdo_name": "1.1.1.1",
              "sdo_type": "indicator",
              "ctix_score": 44,
              "analyst_tlp": null,
              "ctix_created": 1649402138.617737,
              "is_whitelist": false,
              "ctix_modified": 1649402138.617759,
              "is_deprecated": false,
              "indicator_type": {
                "type": "ipv4-addr",
                "attribute_field": "value"
              },
              "is_false_positive": false
            },
            {
              "id": "b2f53079-d203-44c5-8806-9de5be1e9974",
              "created": 1649402609.678553,
              "sources": [
                {
                  "tlp": "AMBER",
                  "name": "Import",
                  "score": 88,
                  "last_seen": null,
                  "first_seen": 1649402609
                }
              ],
              "ctix_tlp": null,
              "modified": 1649405255.346014,
              "sdo_name": "8.8.8.8",
              "sdo_type": "indicator",
              "ctix_score": 46,
              "analyst_tlp": null,
              "ctix_created": 1649402609.990111,
              "is_whitelist": false,
              "ctix_modified": 1649402609.990129,
              "is_deprecated": false,
              "indicator_type": {
                "type": "ipv4-addr",
                "attribute_field": "value"
              },
              "is_false_positive": false
            },
            {
              "id": "b2f53079-d203-44c5-8806-9de5be1e9974",
              "created": 1649402609.678553,
              "sources": [
                {
                  "tlp": "AMBER",
                  "name": "Import",
                  "score": 88,
                  "last_seen": null,
                  "first_seen": 1649402609
                }
              ],
              "ctix_tlp": null,
              "modified": 1649405255.346014,
              "sdo_name": "8.8.8.8",
              "sdo_type": "indicator",
              "ctix_score": 46,
              "analyst_tlp": null,
              "ctix_created": 1649402609.990111,
              "is_whitelist": false,
              "ctix_modified": 1649402609.990129,
              "is_deprecated": false,
              "indicator_type": {
                "type": "ipv4-addr",
                "attribute_field": "value"
              },
              "is_false_positive": false
            },
            {
              "id": "5d086b20-e3fb-44bc-8319-c6bda6fbe3d0",
              "created": 1649402138.38093,
              "sources": [
                {
                  "tlp": "GREEN",
                  "name": "Import",
                  "score": 83,
                  "last_seen": null,
                  "first_seen": null
                }
              ],
              "ctix_tlp": null,
              "modified": 1649402138.380951,
              "sdo_name": "CVE-1234",
              "sdo_type": "vulnerability",
              "ctix_score": null,
              "analyst_tlp": null,
              "ctix_created": 1649402138.622643,
              "is_whitelist": null,
              "ctix_modified": 1649402138.622655,
              "is_deprecated": false,
              "indicator_type": null,
              "is_false_positive": null
            },
            {
              "id": "028ce8f1-e3fb-41f4-a008-8713924fe215",
              "created": 1649402609.879376,
              "sources": [
                {
                  "tlp": "AMBER",
                  "name": "Import",
                  "score": 88,
                  "last_seen": null,
                  "first_seen": null
                }
              ],
              "ctix_tlp": null,
              "modified": 1649402609.879396,
              "sdo_name": "CVE-321",
              "sdo_type": "vulnerability",
              "ctix_score": null,
              "analyst_tlp": null,
              "ctix_created": 1649402609.994466,
              "is_whitelist": null,
              "ctix_modified": 1649402609.994478,
              "is_deprecated": false,
              "indicator_type": null,
              "is_false_positive": null
            }
          ],
          "timestamp": 1649406695,
          "title": "Package From CTIX"
        }
      ]
    }


def build_params(params):
    new_params = dict()
    for k, v in params.items():
        if v is not None and v != '':
            if k in ("from_timestamp", "to_timestamp"):
                new_params[k] = int(datetime.fromisoformat(v[:-1]).timestamp())
            else:
                new_params[k] = v
    return new_params


def get_save_result_set_data(config, params):
    ob = CywareFeed(config)
    params = build_params(params)
    return ob.make_rest_call("/ingestion/rules/save_result_set/", params=params)


def get_indicators(config, params):
    ob = CywareFeed(config)
    params = build_params(params)
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
            if page == 3:
                resp_indicators = []
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
        "version": "v3",
        "from_timestamp": int(datetime.now().timestamp())
    }
    resp = ob.make_rest_call("/ingestion/rules/save_result_set/", params=params)
    return True


operations = {
    "get_save_result_set_data": get_save_result_set_data,
    "get_save_result_set_indicators": get_save_result_set_indicators
}
