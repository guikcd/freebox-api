#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from session import Session
import requests
import simplejson as json

class Lan(object):

	def __init__(self, session):
		self.session = session

	def get_lan_info(self):
		try:
		        result = requests.get(self.session.base_url + self.session.api_base_url + 'v%d/lan/browser/pub/' %\
                                self.session.api_version, headers=self.session.headers, verify=self.session.ca_file)
			j = json.loads(result.text)
                        self.session.logger.debug("get_lan_info(): %s" % result.text)
			if j['success']:
				return j['result']
			else:
                                self.session.logger.error("Success not found: %s" % j)
		except Exception, e:
			self.session.logger.error("Unable to get lan info : %s" % e)
			sys.exit(e)
