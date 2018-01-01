#!/usr/bin/env python
# -*- coding: utf-8 -*-

import builtwith
import argparse

from data import cms_dict
from config import *
import urlparse
import requests
import hashlib
import re



class BuiltCms(object):
	"""docstring for BuiltCms"""
	def __init__(self, url):
		super(BuiltCms, self).__init__()
		self.url = url
		
	def run(self):
		#调用builtwith，识别web开发信息
		result = self.built()

		#调用识别方法，识别web的cms信息
		cms = self.cms()
		if cms:
			result[u'cms'] = [u'{}'.format(cms)]
		#打印结果
		return result

	def built(self):
		result = builtwith.parse(self.url)
		if result:
			return result
		else:
			return {}

	def cms(self):

		for cmss in cms_dict:
			for i in cms_dict[cmss]:
				link = i[0]
				url = urlparse.urljoin(self.url, link)
				for (method,content) in i[1].items():
					if method == 'MD5':
						res = requests.get(url=url, headers=headers, allow_redirects=allow_redirects, verify=allow_ssl_verify, timeout=timeout)
						if res.status_code == 200:
							md5 = self.md5(res.content)
							if md5 == content:
								return cmss
					if method == 'regex':
						res = requests.get(url=url, headers=headers, allow_redirects=allow_redirects, verify=allow_ssl_verify, timeout=timeout)
						if res.status_code == 200:
							res_content = self.cont(content, res.content)
							if res_content:
								return cmss


	def md5(self,content):
		return hashlib.md5(content).hexdigest()

	def cont(self,regex,content):

		if re.search(regex,content):
			return True
		return False


# cms = BuiltCms('http://otcms.com/')
# cms.run()
if __name__ == '__main__':
	parser = argparse.ArgumentParser(description="CMS  BuiltScan Ver:1.0")
	parser.add_argument("-u", "--url", metavar="", help="url address")
	args = parser.parse_args()

	try:
		url = args.url
		if not url:
			print 'Usage : cms.py -u http://test.com/'
			sys.exit(1)
		cms = BuiltCms(url)
		print '[*]Fecting CMS ...'
		result = cms.run()
		print '\n\tOut:{}'.format(result)
		print '\tCMS:{}\n'.format(result['cms'][0])
		print '[-]Complete .'
	except KeyboardInterrupt:
		sys.exit(1)




