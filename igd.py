#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
from session import Session
import requests
import simplejson as json

class Igd(object):

	def __init__(self, session):
		self.session = session

	def get_redirections(self):
		try:
		        result = requests.get(self.session.base_url + self.session.api_base_url + 'v%d/upnpigd/redir/' %\
                                self.session.api_version, headers=self.session.headers, verify=self.session.ca_file)
			j = json.loads(result.text)
                        self.session.logger.debug("get_redirections(): %s" % result.text)
			if j['success']:
                                if 'return' in j:
				    return j['result']
			else:
				self.session.logger.error("%s" % j['msg'])
		except Exception, e:
			self.session.logger.error("Unable to get igd redirections : %s" % e)
			sys.exit(e)
