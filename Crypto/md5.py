import urllib

def crack(md5):
	url = 'http://www.md5online.org/md5-decrypt.html'

	#md5 = "4124bc0a9335c27f086f24ba207a4912"

	params = urllib.urlencode({
		'md5' : md5
	})

	data = urllib.urlopen(url, params).read()

	fIndex = data.find("Found : ")
	
	if fIndex == -1:
		return -1
	
	data = data[(fIndex+11):]
	fIndex = data.find("</b>")
	data = data[:fIndex]
	#	print("Found : ")
	return data

