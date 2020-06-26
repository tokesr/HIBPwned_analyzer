#!/usr/bin/env python3
# encoding: utf-8

import time
import requests

from cortexutils.analyzer import Analyzer


class HIBPAnalyzer(Analyzer):

	def __init__(self):
		Analyzer.__init__(self)
		self.service = self.get_param('config.service', None, 'Missing  Service')
		self.unverified = self.get_param('config.unverified', None, 'Missing Unverified option')
		self.truncate = self.get_param('config.truncate', None, 'Missing Truncate option')
		self.api_key = self.get_param('config.api_key', None, 'Missing Api Key')
		self.retries = self.get_param('config.retries', None, 'Missing Retries option')
		self.baseurl = self.get_param('config.url', None, 'Missing baseURL')
		self.data = self.get_param('data', None, 'Data is missing')
		self.user_agent = self.get_param('config.user_agent', None, 'User-Agent is missing')


	def createURL(self):
		url = self.baseurl + str(self.data) 
		if (self.service != "site_breach") :
			url = url + "?"
		else:
			url = url + "&"
		url = url + "truncateResponse="+str(self.truncate) + "&includeUnverified=" + str(self.unverified) 
		return url

	def hibp_analyze(self, data):
		results = dict()

		try:

			url = self.createURL()
			headers = {
				"hibp-api-key" : self.api_key ,
				"User-Agent" : str(self.user_agent)
			}
			while int(self.retries) > 0:
				r = requests.get(url, headers=headers)
				self.retries = int(self.retries) - 1
				if r.status_code == 200:
					#Ok - everything worked and there's a string array of pwned sites for the account
					if r.text == "[]":
						return results
					else:
						results['reports'] = []
						for match in r.json():
							results['reports'].append(match)
						return results
				elif r.status_code == 404:
					#404 - Not found — the account could not be found and therefore has not been pwned
					return results
				elif (r.status_code == 429 or r.status_code == 503):
					#429 - Too many requests - the rate limit has been exceeded
					#503 - service is not available, probably cloudflare issue, worth to retry
					retry_after = int(r.headers.get('retry-after'))
					if (retry_after == ''):
						if r.status_code == 503:
							retry_after = 30 #site is either down or temporarily unavailable, can be a quickly-solved issue
						else:
							retry_after = 4 #site is up
					#waiting for the recommended time + 1sec
					time.sleep(retry_after + 1)
				else:
					#400 - non-acceptable format
					#401 - no Api or non-valid API
					#403 - no user agent in the request
					self.error('Unsuccessful GET request due to: ' + str(r.text))

		except Exception as e:
			self.error('Error in hibp_analyze: '  + str(e))

		return results




	def summary(self, raw):
		taxonomies = []
		level = "info"
		namespace = "HIBPwned"
		if self.service == "account_breach":
			predicate = "AccountBreach"
		elif self.service == "account_paste":
			predicate = "AccountPaste"
		else:
			predicate = "SiteBreach"

		breach_count = len(raw)
		if breach_count <= 0:
			level = "safe"
			value = "False"
		else:
			level = "malicious"
			value = "True"

		taxonomies.append(self.build_taxonomy(level, namespace, predicate, value))

		return {"taxonomies": taxonomies}



	def run(self):

		if self.service == "account_breach" or self.service == "account_paste":
			if self.data_type == "mail":
				self.report(self.hibp_analyze(self.data))			
			else:
				self.error("Invalid data_type: "+ str(self.data_type) +". Valid type is: mail.")

		elif self.service == "site_breach":
			if self.data_type == "domain" or self.data_type == "url":
				self.report(self.hibp_analyze(self.data))
			else:
				self.error("Invalid data type: "+ str(self.data_type) +". Valid types: domain, url.")
		else:
			self.error("Invalid service: " +str(self.service) +".")


if __name__ == '__main__':
	HIBPAnalyzer().run()