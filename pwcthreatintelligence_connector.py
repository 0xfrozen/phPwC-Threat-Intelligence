from __future__ import print_function, unicode_literals
import phantom.app as phantom
from phantom.base_connector import BaseConnector
from phantom.action_result import ActionResult
import requests
import json

class RetVal(tuple):
    def __new__(cls, val1, val2=None):
        return tuple.__new__(RetVal, (val1, val2))

class PwcThreatIntelligenceConnector(BaseConnector):

    def _make_rest_call(self, endpoint, action_result):
        config = self.get_config()
        url = config['Base_URL'] + endpoint
        params = {'apikey': config['API_KEY']}
        resp_json=None
        try:
            r = requests.get(url=url, params=params)
        except Exception as e:
            return action_result.set_status(phantom.APP_ERROR, 'PwC TI API Unavailable', e), resp_json
        try:
            resp_json=r.json()
        except Exception as e:
            msg_string = r.text.replace('{', '').replace('}', '')
            return action_result.set_status(phantom.APP_ERROR, msg_string, e), resp_json
        
        errors = resp_json.get('error')
        if errors:
            details = json.dumps(resp_json).replace('{', '').replace('}', '')
            return (action_result.set_status(phantom.APP_ERROR,"Response code: {status}, Response from the server: {details}".format(status=r.status_code, details=details)),resp_json)
        
        if r.status_code == 200:
            return phantom.APP_SUCCESS, resp_json

        action_result.add_data(resp_json)
        details = json.dumps(resp_json).replace('{', '').replace('}', '')
        return (action_result.set_status(phantom.APP_ERROR, "Response code: {}, Response from the server: {}".format(r.status_code, details)), resp_json)
    
    def _handle_lookup_ip(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        ret_val, response = self._make_rest_call("/synapse/v2/ipv4s/{ip}/tie".format(ip=param['ip']), action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            data = response['data']
        except:
            return action_result.set_status(phantom.APP_ERROR, "Response not in the expected format")
        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS)
    
    def _handle_lookup_domain(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        ret_val, response = self._make_rest_call("/synapse/v2/domains/{domain}/tie".format(domain=param['domain']), action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            data = response['data']
        except:
            return action_result.set_status(phantom.APP_ERROR, "Response not in the expected format")
        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS)
    
    def _handle_lookup_hash(self, param):
        action_result = self.add_action_result(ActionResult(dict(param)))
        self.save_progress("In action handler for: {0}".format(self.get_action_identifier()))
        ret_val, response = self._make_rest_call("/synapse/v2/hashes/{hash}/tie".format(hash=param['hash']), action_result)
        if phantom.is_fail(ret_val):
            return action_result.get_status()
        try:
            data = response['data']
        except:
            return action_result.set_status(phantom.APP_ERROR, "Response not in the expected format")
        action_result.add_data(data)
        return action_result.set_status(phantom.APP_SUCCESS)

    def _handle_test_connectivity(self, param):
        config = self.get_config()
        ip = config['IP_to_Lookup']
        if not ip:
            self.save_progress("Please specify an IP to lookup")
            return self.set_status(phantom.APP_ERROR)
        
        action_result = ActionResult()
        self.save_progress("Looking up the IP to check connectivity")
        ret_val, response = self._make_rest_call("/synapse/v2/ipv4s/{ip}/tie".format(ip=ip), action_result)
        if phantom.is_fail(ret_val):
            self.debug_print(action_result.get_message())
            self.set_status(phantom.APP_ERROR, action_result.get_message())
            return phantom.APP_ERROR
        return self.set_status_save_progress(phantom.APP_SUCCESS, "Test connectivity passed")
    
    def handle_action(self, param):
        action_id = self.get_action_identifier()
        ret_val = phantom.APP_SUCCESS
        if action_id == 'lookup_ip':
            ret_val = self._handle_lookup_ip(param)
        if action_id == 'lookup_domain':
            ret_val = self._handle_lookup_domain(param)
        if action_id == 'lookup_hash':
            ret_val = self._handle_lookup_hash(param)
        if action_id == 'test_connectivity':
            ret_val = self._handle_test_connectivity(param)
        return ret_val

def main():
    import argparse

    argparser = argparse.ArgumentParser()

    argparser.add_argument('input_test_json', help='Input Test JSON file')
    argparser.add_argument('-u', '--username', help='username', required=False)
    argparser.add_argument('-p', '--password', help='password', required=False)

    args = argparser.parse_args()
    session_id = None

    username = args.username
    password = args.password

    if username is not None and password is None:

        # User specified a username but not a password, so ask
        import getpass
        password = getpass.getpass("Password: ")

    if username and password:
        try:
            login_url = PwcThreatIntelligenceConnector._get_phantom_base_url() + '/login'

            print("Accessing the Login page")
            r = requests.get(login_url, verify=False)
            csrftoken = r.cookies['csrftoken']

            data = dict()
            data['username'] = username
            data['password'] = password
            data['csrfmiddlewaretoken'] = csrftoken

            headers = dict()
            headers['Cookie'] = 'csrftoken=' + csrftoken
            headers['Referer'] = login_url

            print("Logging into Platform to get the session id")
            r2 = requests.post(login_url, verify=False, data=data, headers=headers)
            session_id = r2.cookies['sessionid']
        except Exception as e:
            print("Unable to get session id from the platform. Error: " + str(e))
            exit(1)

    with open(args.input_test_json) as f:
        in_json = f.read()
        in_json = json.loads(in_json)
        print(json.dumps(in_json, indent=4))

        connector = PwcThreatIntelligenceConnector()
        connector.print_progress_message = True

        if session_id is not None:
            in_json['user_session_token'] = session_id
            connector._set_csrf_info(csrftoken, headers['Referer'])

        ret_val = connector._handle_action(json.dumps(in_json), None)
        print(json.dumps(json.loads(ret_val), indent=4))

    exit(0)
if __name__ == '__main__':
    main()

# this is a comment added to test git