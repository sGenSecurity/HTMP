import base64

class Base64():

	def encode(text):
		return base64.b64encode(text)

	def decode(text):
		return base64.b64decode(text)

	def et_encode(text, table):
		
