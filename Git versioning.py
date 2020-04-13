import requests, base64, json, sys
import configparser

# work on a branch.

class httpRequest:
    def __init__(self):
        """ intitialize required variables. """
        self.verbose = False
        self._token_CP = None
        self.cp_scriptid = None
        self.git_scriptname = None
        self.consumer_key = None
        self.consumer_secret = None
        """ Dict to link Catchpoint and Git scripts. """
        self.script_links = []
        """ Dict with basic properties for creating requests. """
        self.creds_basic_CP = {
            'content_type': 'application/json',
            'uri': {
                'domain': None,
                'path': None
            },
            'git_repo_url': None,
            'git_repo_secret': None,
            'request_type': 'GET',
            'data_retrieval_type': 'Git',
            'test_data': None
        }

    def _debug(self, msg):
        """ Debug output. Set self.verbose to True to enable. """
        if self.verbose:
            print(str(msg))

    def _terminate_execution(self, msg):
        """ exit script execution """
        print('\n {}\n'.format(msg))
        input('press enter key to exit...')
        sys.exit(msg)

    def _loadGitConfig(self, configFilename):
        parser = configparser.ConfigParser()
        parser.read(configFilename)
        if parser.has_option('git_repo_details', 'repo_url'):
            self.creds_basic_CP['git_repo_url'] = parser.get('git_repo_details', 'repo_url')
        if parser.has_option('git_repo_details', 'git_secret'):
            self.creds_basic_CP['git_repo_secret'] = parser.get('git_repo_details', 'git_secret')

    def _loadCP_Cred(self, configFilename):
        parser = configparser.ConfigParser()
        parser.read(configFilename)

        if parser.has_option('cp_cred', 'key'):
            self.consumer_key = parser.get('cp_cred', 'key')
        if parser.has_option('cp_cred', 'secret'):
            self.consumer_secret = parser.get('cp_cred', 'secret')


    def _loadCP_GitConfig(self, configFilename):
        parser = configparser.ConfigParser()
        parser.read(configFilename)
        count = 0
        if parser.has_section('script_links'):
            for key, value in parser.items('script_links'):
                each_script_details = {count:{
                        'cp_script_id': key,
                        'git_script_name': value
                        }}
                count=count+1
                self.script_links.append(each_script_details)

    def _match_test_id(self, current_test_id):
        for key in self.script_links:
            obj = self.script_links[key]
            for prop in obj:
                if current_test_id == obj[prop]:
                    return obj

    def _build_request_dictionary(self, request_dictionary_obj):
        """ Endpoint for reference to build the object. can be deleted once code is complete. https://io.catchpoint.com/ui/api/v1/tests/12345 """
        if request_dictionary_obj['data_retrieval_type'] == 'Token':
            request_dictionary_obj['client_id'] = self.consumer_key
            request_dictionary_obj['client_secret'] = self.consumer_secret
            return request_dictionary_obj
        elif request_dictionary_obj['data_retrieval_type'] == 'Test Management':
            request_dictionary_obj['uri']['path'] = request_dictionary_obj['uri']['path']+''+self.cp_scriptid
            return request_dictionary_obj
        else:
            self._terminate_execution('Only scripted to work with few endpoints for now. Please modify the script to handle other scenarios.')

    def _make_request(self, request_obj):
        """ Make a HTTP/HTTPS request """
        """ Prepare request data. """
        headers = {}
        if request_obj['data_retrieval_type'] == 'Git':
            if self.git_scriptname != None and request_obj['uri']['filename'] != 'combined':
                uri = request_obj['git_repo_url']+''+request_obj['uri']['filename']
            else:
                uri = request_obj['git_repo_url']
        else:
            uri = request_obj['uri']['domain']+''+request_obj['uri']['path']
            if request_obj['data_retrieval_type'] == 'Token':
                payload = {
                    'grant_type': 'client_credentials',
                    'client_id': request_obj['client_id'],
                    'client_secret': request_obj['client_secret']
                }
            elif request_obj['data_retrieval_type'] == 'Test Management':
                payload = request_obj['test_data']
                headers['Accept'] = request_obj['content_type']
                headers['Content_Type'] = request_obj['content_type']
                headers['Authorization'] = 'Bearer ' + base64.b64encode(self._token_CP.encode('ascii')).decode("utf-8")

        """ Trigger the request. """
        try:
            if request_obj['request_type'] == 'POST':
                r = requests.post(uri, headers=headers, data=payload,verify=False)
            elif request_obj['request_type'] == 'GET':
                r = requests.get(uri, headers=headers, verify=False)
            if r.status_code != 200:
                self._debug("The response is "+str(r.content))
                self._debug("there was some error"+str(r))
        except requests.exceptions.ConnectionError as e:
            self._debug(e)
            self._terminate_execution(e)

        if request_obj['data_retrieval_type'] == 'Git':
            data = r.content.decode("utf-8").replace('"', "'")
            self._debug(data)
        else:
            data = r.json()
            self._debug(data)

        """ Return request data. """
        if request_obj['data_retrieval_type'] == 'Token':
            if 'access_token' not in data:
                self._terminate_execution('Access token not present in response')
            self._token_CP = data['access_token']
        else:
            return data



httpRequest_obj = httpRequest()
# read cp API credentials
httpRequest_obj._loadCP_Cred('config.ini')
# read git repo details from config file
httpRequest_obj._loadGitConfig('config.ini')
# read cp and git link details
httpRequest_obj._loadCP_GitConfig('config.ini')



print('\t\tGIT Versioning Script For Catchpoint')
print('.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+.')
# Check if git info is present in config file
if httpRequest_obj.creds_basic_CP['git_repo_url'] != None:
    print('+ This script is configured to get versioning scripts from:             +')
    print('  {} '.format(httpRequest_obj.creds_basic_CP['git_repo_url']))
else:
    print('| This script is not configured to get details from a config.ini file   |')
print('.+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+.')

# Check if CP API credentials are set in config file.
if httpRequest_obj.consumer_key == None or httpRequest_obj.consumer_secret == None:
    httpRequest_obj.consumer_key = input('\tEnter Catchpoint API Key:')
    httpRequest_obj.consumer_secret = input('\tEnter Catchpoint API Secret:')

# Check if Git URL is set in config file.
if httpRequest_obj.creds_basic_CP['git_repo_url'] == None:
    httpRequest_obj.creds_basic_CP['git_repo_url'] = input('\tEnter Git repository URL\n\t[eg: https://raw.githubusercontent.com/user/repo/master/cpscript]\n\t:')

# Check if links are set in config file
if httpRequest_obj.script_links != []:
    print('|  Enter one of the below Catchpoint script ID to perform an update:    |')
    print('\t-------------------\n\tCP Id  : Git Script\n\t-------------------')

    # Display all test details form config file
    for item in httpRequest_obj.script_links:
        for key, value in item.items():
            print('\t{}: {}'.format(value['cp_script_id'], value['git_script_name']))

print('|+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+|')

# accept script Id from user
CP_script_id = input('\tEnter Catchpoint Script Id to update:')

# Check if the script ID matches
if httpRequest_obj.script_links != []:
    flag = False
    script_name = None
    for item in httpRequest_obj.script_links:
        for key, value in item.items():
            if value['cp_script_id'] == CP_script_id:
                script_name = value['git_script_name']
                httpRequest_obj.cp_scriptid = value['cp_script_id']
                httpRequest_obj.git_scriptname = value['git_script_name']
                flag = True
                break
    if flag == False:
        httpRequest_obj._terminate_execution('Please enter one of the above configured script Id.')
else:
    script_name = 'combined'
    httpRequest_obj.cp_scriptid = CP_script_id

#print(script_name)
httpRequest_obj.creds_basic_CP['uri']['filename'] = script_name

""" Get data from Git repo. """
current_git_script_obj = httpRequest_obj._make_request(httpRequest_obj.creds_basic_CP)

# Check if script made connection with git repo
if current_git_script_obj != None:
    print('Connection with repository was successful.')
else:
    httpRequest_obj._terminate_execution('Connection with repository was not successful.')

""" Generate token for Catchpoint access. """
httpRequest_obj.creds_basic_CP['uri']['domain'] = 'https://io.catchpoint.com/'
httpRequest_obj.creds_basic_CP['uri']['path'] = 'ui/api/token'
httpRequest_obj.creds_basic_CP['data_retrieval_type'] = 'Token'
httpRequest_obj.creds_basic_CP['request_type'] = 'POST'
httpRequest_obj_creds_token = httpRequest_obj._build_request_dictionary(httpRequest_obj.creds_basic_CP)
httpRequest_obj._make_request(httpRequest_obj_creds_token)

# Check if CP token generation was successful
if httpRequest_obj._token_CP != None:
    print('Catchpoint token generation was successful.')
else:
    httpRequest_obj._terminate_execution('Catchpoint token generation failed.')

""" Get cusrrent setting for the script from Catchpoint. """
httpRequest_obj.creds_basic_CP['data_retrieval_type'] = 'Test Management'
httpRequest_obj.creds_basic_CP['request_type'] = 'GET'
httpRequest_obj.creds_basic_CP['uri']['path'] = 'ui/api/v1/tests/'
httpRequest_obj_creds_req1 = httpRequest_obj._build_request_dictionary(httpRequest_obj.creds_basic_CP)
current_test_details_obj = httpRequest_obj._make_request(httpRequest_obj_creds_req1)
current_test_details_obj['script'] = current_git_script_obj

""" Confirm the updation of script in Catchpoint. """
print('\nCatchpoint Script Details: \nID: {}\nName: {}\n'.format(current_test_details_obj['id'], current_test_details_obj['name']))
cp_scriptName = current_test_details_obj['name']
confirmMsg = input('Please confirm if you wish update "{}" in Catchpoint [yes/no]:'.format(cp_scriptName))
if confirmMsg == 'no' or confirmMsg == 'NO' or confirmMsg == 'No' or confirmMsg == 'n' or confirmMsg == 'N':
    httpRequest_obj._terminate_execution('You have selected the option "No".')
elif confirmMsg == 'yes' or confirmMsg == 'YES' or confirmMsg == 'Yes' or confirmMsg == 'y' or confirmMsg == 'Y':
    current_test_details_obj = json.dumps(current_test_details_obj)

    """ Update script in Catchpoint with new script from Git. """
    httpRequest_obj.creds_basic_CP['request_type'] = 'POST'
    httpRequest_obj.creds_basic_CP['uri']['path'] = 'ui/api/v1/tests/'
    httpRequest_obj.creds_basic_CP['test_data'] = current_test_details_obj
    httpRequest_obj_creds_req2 = httpRequest_obj._build_request_dictionary(httpRequest_obj.creds_basic_CP)
    current_test_Update_obj = httpRequest_obj._make_request(httpRequest_obj_creds_req2)
    if current_test_Update_obj['status'] == 'Success' or current_test_Update_obj['status'] == 'success':
        print('\n"{}" updation was successful!'.format(cp_scriptName))
        exit_key = input('press enter key to exit...')
else:
    httpRequest_obj._terminate_execution('Confirmation msg is invalid, this will cause the script to exit.')
