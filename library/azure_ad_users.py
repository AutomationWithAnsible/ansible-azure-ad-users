#!/usr/bin/python
# -*- coding: utf-8 -*-
__version__ = "1.0.0"
DOCUMENTATION = '''
---
module: azure_ad_users
short_description: Create and delete users in azure AD
description:
     - Allows for the management of Azure AD users.
version_added: "1.0"
options:
  user_name:
    description:
      - The user name of the Azure user to create or identify for deletion.
        This has to be unique as it will be the person's username (e.g. test.user)
    required: true
    default: null

  state:
    description:
      - Whether to create or delete an Azure user account.
    required: false
    default: present
    choices: [ "present", "absent" ]

  password:
    description:
      - When type is user and state is present, define the users login password. Also works with update. Note that always returns changed.
    required: false
    default: null

  client_id:
    description:
      - Azure clientID. If not set then the value of the AZURE_CLIENT_ID environment variable is used.
    required: false
    default: null
    aliases: [ 'azure_client_id', 'client_id' ]

  client_secret:
    description:
      - Azure Client secret key. If not set then the value of the AZURE_CLIENT_SECRET environment variable is used.
    required: false
    default: null
    aliases: [ 'azure_client_secret', 'client_secret' ]

  tenant_domain:
    description:
      - This is your tenant domain name, usually something.onmicrosoft.com (e.g. AnsibleDomain.onmicrosoft.com)
    required: True
    default: null

  change_password_onlogin:
    description:
      - If you are creating a user, here you can mention is he should be asked to change his password on the next login.
    required: false
    default: True

  enabled:
    description:
      - If the user should be create in the enabled or disabled state
    required: false
    default: enabled

  display_name:
    description:
      - This is the user account displayname.
    required: false
    default: If no argument is passed, it will be set to the UPN without the @Domain part.

  mail_nick_name:
    description:
      - This is the Mail Nick Name for the user account.
    required: false
    default: If no argument is passed, it will be set to the UPN without the @Domain part.

  given_name:
    description:
      - User account first name
    required: false
    default: null

  surname:
    description:
      - User account last name.
    required: false
    default: null
'''.format(__version__)

EXAMPLES = '''
# Basic user creation example
tasks:
- name: Create a new Azure user account
  azure_ad_users:
    user_name            : "ansible.test"
    state           : present
    password        : "Test1234"
    tenant_domain    : "AnsibleDomain.onmicrosoft.com"
    client_id       : "6359f1g62-6543-6789-124f-398763x98112"
    client_secret   : "HhCDbhsjkuHGiNhe+RE4aQsdjjrdof8cSd/q8F/iEDhx="

# Basic user deletion example
tasks:
- name: Delete one Azure user account
  azure_ad_users:
    user_name            : "ansible.test"
    state           : absent
    tenant_domain    : "AnsibleDomain.onmicrosoft.com"
    client_id       : "6359f1g62-6543-6789-124f-398763x98112"
    client_secret   : "HhCDbhsjkuHGiNhe+RE4aQsdjjrdof8cSd/q8F/iEDhx="

'''

class AzureAdUsers():
    def __init__(self, module):
        self.module = module
        self.user_name = self.module.params["user_name"] + "@" + self.module.params["tenant_domain"]
        self.state = self.module.params["state"]
        self.password = self.module.params["password"]
        self.change_password_onlogin = self.module.params["change_password_onlogin"]
        self.enabled = self.module.params["enabled"]
        self.display_name = self.module.params["display_name"]
        if not self.display_name:
            #i = self.user_name.split('@', 1)
            self.display_name = self.module.params["user_name"]
        self.mail_nick_name = self.module.params["mail_nick_name"]
        if not self.mail_nick_name:
            #i = self.user_name.split('@', 1)
            self.mail_nick_name = self.module.params["user_name"]
	self.immutable_id = self.module.params["immutable_id"]
        self.given_name = self.module.params["given_name"]
        self.surname = self.module.params["surname"]
        self.tenant_domain = self.module.params["tenant_domain"]
        self.client_id = self.module.params["client_id"]
        self.client_secret = self.module.params["client_secret"]
        self.graph_url = self.module.params["graph_url"]
        self.login_url  = self.module.params["login_url"]
        if not self.graph_url:
            self.graph_url = "https://graph.windows.net/{}".format(self.tenant_domain)
        if not self.login_url:
            self.login_url = "https://login.windows.net/{}/oauth2/token?api-version=1.0".format(self.tenant_domain)

        # Geting azure cred from ENV if not defined
        if not self.client_id:
            if 'azure_client_id' in os.environ:
                self.client_id = os.environ['azure_client_id']
            elif 'AZURE_CLIENT_ID' in os.environ:
                self.client_id = os.environ['AZURE_CLIENT_ID']
            elif 'client_id' in os.environ:
                self.client_id = os.environ['client_id']
            elif 'CLIENT_ID' in os.environ:
                self.client_id = os.environ['CLIENT_ID']
            else:
                # in case client_id came in as empty string
                self.module.fail_json(msg="Client ID is not defined in module arguments or environment.")

        if not self.client_secret:
            if 'azure_client_secret' in os.environ:
                self.client_secret = os.environ['azure_client_secret']
            elif 'AZURE_CLIENT_SECRET' in os.environ:
                self.client_secret = os.environ['AZURE_CLIENT_SECRET']
            elif 'client_secret' in os.environ:
                self.client_secret = os.environ['client_secret']
            elif 'CLIENT_SECRET' in os.environ:
                self.client_secret = os.environ['CLIENT_SECRET']
            else:
                # in case secret_key came in as empty string
                self.module.fail_json(msg="Client Secret is not defined in module arguments or environment.")
        self.headers = None
        self.data = None
        self.azure_version = "api-version=1.6"

    # TODO: might not be needed
    def convert(self, data):
        if isinstance(data, basestring):
            return str(data)
        elif isinstance(data, collections.Mapping):
            return dict(map(self.convert, data.iteritems()))
        elif isinstance(data, collections.Iterable):
            return type(data)(map(self.convert, data))
        else:
            return data

    def login(self):
        headers = { 'User-Agent': 'ansible-azure-0.0.1', 'Connection': 'keep-alive', 'Content-Type': 'application/x-www-form-urlencoded' }
        payload = { 'grant_type': 'client_credentials', 'client_id': self.client_id, 'client_secret': self.client_secret }
        payload = urllib.urlencode(payload)

        try:
            r = open_url(self.login_url, method="post", headers=headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            self.module.fail_json(msg="Failed to login error code = '{}' and message = {}".format(response_code, response_msg))

        response_msg = r.read()
        # TODO: Should try and catch if failed to seriolize to json
        token_response = json.loads(response_msg)
        token = token_response.get("access_token", False)
        if not token:
            self.module.fail_json(msg="Failed to extract token type from reply")
        token_type = token_response.get("token_type", 'Bearer')
        self.headers = { 'Authorization' : '{} {}'.format(token_type, token),
                         'Accept' : 'application/json', "content-type": "application/json" }

    def create_user(self):
        # https://msdn.microsoft.com/en-us/Library/Azure/Ad/Graph/api/users-operations#BasicoperationsonusersCreateauser
        password_profile = { "password": self.password, "forceChangePasswordNextLogin": self.change_password_onlogin }
        payload = { 'accountEnabled': self.enabled, 'displayName': self.display_name, 'immutableId': self.immutable_id, \
                    'mailNickname': self.mail_nick_name, 'userPrincipalName': self.user_name, 'passwordProfile': password_profile  }

        if self.given_name:
            payload.update({ 'givenName': self.given_name})
        if self.surname:
            payload.update({ 'surname': self.surname})
        # convert payload to json
        payload = json.dumps(payload)
        url = self.graph_url + "/users?" + self.azure_version
        try:
            r = open_url(url, method="post", headers=self.headers ,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("odata.error", False) and "already exists" in response_json.get("odata.error").get("message",{}).get("value"):
                self.module.exit_json(msg="User already exists", changed=False)
            else:
                error_msg = response_json.get("odata.error").get("message")
                self.module.fail_json(msg="Error happend while trying to create user. Error code='{}' msg='{}'".format(response_code, error_msg))

        self.module.exit_json(msg="User created.", changed=True)

    def delete_user(self):
        # https://msdn.microsoft.com/en-us/Library/Azure/Ad/Graph/api/users-operations#BasicoperationsonusersDeleteauser
        #payload = { 'userPrincipalName': self.user_name }
        #payload = json.dumps(payload)
        url = self.graph_url + "/users/" + self.user_name + "?" + self.azure_version
        #print (url)
        #exit(1)
        try:
            r = open_url(url, method="delete", headers=self.headers) #,data=payload)
        except urllib2.HTTPError, err:
            response_code = err.getcode()
            response_msg = err.read()
            response_json = json.loads(response_msg)
            if response_json.get("odata.error", False) and "Insufficient privileges" in response_json.get("odata.error").get("message",{}).get("value"):
                self.module.exit_json(msg="You have to add this Service Principal to the \"User Account Administrator Role\" this can be done using Powershell.", changed=False)
            else:
                error_msg = response_json.get("odata.error").get("message")
                self.module.fail_json(msg="Error happend while trying to delete the user. Error code='{}' msg='{}'".format(response_code, error_msg))

        self.module.exit_json(msg="User deleted.", changed=True)

    def main(self):
        if self.state == "present":
            if self.user_name.find('@')==1:
                self.module.fail_json(msg="Please make sure to enter the username without the @tenant_domain.onmicrosoft.com")
            if self.password == None:
                self.module.fail_json(msg="You can't create a user without specifing a password!")
            if self.display_name == None:
                #i = self.user_name.split('@', 1)
                self.display_name = self.user_name
            self.login()
            self.create_user()

        elif self.state == "absent":
            if self.user_name.find('@')==1:
                self.module.fail_json(msg="Please make sure to enter the username without the @tenant_domain.onmicrosoft.com")
            if self.password != None:
                self.module.fail_json(msg="I am confiused, you specified a password for a user to be deleted! Are you sure its a delete operation?")
            self.user_name = self.user_name.replace("@", "%40", 1)

            self.login()
            self.delete_user()

def main():
    module = AnsibleModule(
        argument_spec=dict(
            user_name=dict(default=None, alias="user_principal_name", type="str", required=True),
            state=dict(default="present", choices=["absent", "present"]),
            tenant_domain = dict(default=None, type="str", required=True),
            password=dict(default=None, type="str", required=False, no_log=True),
            change_password_onlogin=dict(default=True, choices=BOOLEANS, type="bool"),
            enabled=dict(default=True, choices=BOOLEANS, type="bool"),
            display_name=dict(default=None, type="str", required=False),
            mail_nick_name=dict(default=None, type="str", required=False),
            immutable_id=dict(default=None, type="str"),
            given_name=dict(default=None, type="str"),
            surname=dict(default=None, type="str"),
            client_id = dict(default=None, alias="azure_client_id", type="str", no_log=True),
            client_secret = dict(default=None, alias="azure_client_secret", type="str", no_log=True),
            graph_url = dict(default=None, type="str"),
            login_url  = dict(default=None, type="str"),
        ),
        #mutually_exclusive=[['ip', 'mask']],
        #required_together=[['ip', 'mask']],
        #required_one_of=[['ip', 'mask']],
        supports_check_mode=False
    )

    AzureAdUsers(module).main()

import collections # might not be needed
import json
import urllib

# import module snippets
from ansible.module_utils.basic import *
from ansible.module_utils.urls import *
main()
