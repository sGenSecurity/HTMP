import base64
import string




def b64encode(text):
	
	return base64.b64encode(text)

def b64decode(text):
	
	return base64.b64decode(text)

def b64encode_edit(text, edit_base64chars):
	
	if type(edit_base64chars) is not str:
		print "[-] The type of arguments must be str"
	if len(edit_base64chars) != 64:
		print "[-] table length must be 64"
	std_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

	return (base64.b64encode(text)).translate(string.maketrans(edit_base64chars,std_base64chars))

def b64decode_edit(text, edit_base64chars):
	
	if type(edit_base64chars) is not str:
		print "[-] The type of arguments must be str"
	if len(edit_base64chars) != 64:
		print "[-] table length must be 64"

	std_base64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	
	return base64.b64decode(text.translate(string.maketrans(std_base64chars, edit_base64chars)))




