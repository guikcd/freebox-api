#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import requests
import simplejson as json
import logging

# challenge password
from hashlib import sha1
import hmac

BASEURL = 'https://mafreebox.freebox.fr'
API_BOOTSTRAP = '/api_version'
API_VERSION = 4
CA_FILE = 'freebox_ca.pem'

APP_ID = 'org.iroqwa.freebox_stats'
TOKEN_FILE = 'token'

AUTH_HEADER = 'X-Fbx-App-Auth'
USER_AGENT = APP_ID

class Session(object):

	def __init__(self, debug=False):
                self.debug = debug
                self.logger = logging.getLogger()
                self.logger.setLevel(logging.INFO)

                if self.debug is True:
                    self.logger.setLevel(logging.DEBUG)
                self.base_url = BASEURL
                self.api_version = API_VERSION
                self.ca_file = CA_FILE
		self.api_base_url = self.__get_api_base_url()
		self.app_token = self.__get_token()
		self.challenge = self.__get_challenge()
		self.password = self.__calculate_password()
		self.session_token = self.__get_session_token()
                self.headers = {
                        AUTH_HEADER: self.session_token,
                        'User-Agent': USER_AGENT}

	def __get_token(self):
                try:
                    with open(TOKEN_FILE, 'r') as token_file:
		        read_data = token_file.readlines()[0].rstrip('\n')
                        logging.debug("Token: %s" % read_data)
		        return read_data
	        except Exception, e:
	        	logging.error("Unexcepted error __get_token(): %s" % (e))
	        	sys.exit(e)

        def __get_user_agent(self):
                return {'User-Agent': USER_AGENT}

	def __get_api_base_url(self):
	        try:
	            result = requests.get(BASEURL + API_BOOTSTRAP, self.__get_user_agent(), verify=self.ca_file)
                    if result.status_code == requests.codes.ok:
                            logging.debug("__get_api_base_url(): %s" % result.text)
	        	    return json.loads(result.text)['api_base_url']
	        except Exception, e:
	        	logging.error("Unexcepted error __get_api_base_url(): %s" % (e))
	        	sys.exit(e)

	def __get_challenge(self):
		try:
		        result = requests.get(BASEURL + self.api_base_url + 'v%d/login/' % \
		        		API_VERSION, self.__get_user_agent(), verify=self.ca_file)
                        logging.debug("__get_challenge(): %s" % result.text)
			return json.loads(result.text)['result']['challenge']
		except Exception, e:
			logging.error("Problem in get_challenge(): %s" % e)
			sys.exit(e)

	def __calculate_password(self):
		# http://dev.freebox.fr/sdk/os/login/: password = hmac-sha1(app_token, challenge)
		myhmac = hmac.new(self.app_token, self.challenge, sha1)
                logging.debug("__calculate_password(): %s" % myhmac.hexdigest())
		return myhmac.hexdigest()

	# login
	def __get_session_token(self):
		session_token = '''
				{
					"app_id": "%s",
					"password": "%s"
				}
				''' \
				% (APP_ID, self.password)
		try:
		        result = requests.post(BASEURL + self.api_base_url + 'v%d/login/session/' % \
		        		API_VERSION, headers=self.__get_user_agent(), data=session_token, verify=self.ca_file)
			j = json.loads(result.text)
                        logging.debug("__get_session_token: %s" % result.text)
			if j['success']:
				return j['result']['session_token']
			else:
				logging.error("Error in __get_session_token(): %s" % j['msg'])
				return None
		except Exception, e:
			logging.error("Unable to get session token: %s" % e)
			sys.exit(e)

	def logout(self):
		try:
		        result = requests.post(BASEURL + self.api_base_url + 'v%d/login/logout/' % \
				API_VERSION, headers=self.headers, verify=self.ca_file)
                        logging.debug("logout(): %s " % result.text)
			j = json.loads(result.text)
			if not j['success']:
				logging.error("Error when logout (%s)" % j['msg'])
		except Exception, e:
			logging.error("Unable logout: %s" % e)
			sys.exit(e)

if __name__ == "__main__":
	session = Session(debug=True)
	import pprint
	pp = pprint.PrettyPrinter()
	#infos = lan.get_lan_info()
	#pp.pprint(infos)
	session.logout()
