import subprocess
import re
import unittest

class GVM_CliTest(unittest.TestCase):
	version_answer = '<get_version_response status="200" status_text="OK"><version>7.0</version></get_version_response>'
	connection_closed = 'Connection closed by server'
	
	def testWrongHostname(self):
		try:
			result = subprocess.check_output(['python3', 'gvm-cli.py', '--hostname=127.0.0.0', '--xml=<get_version/>'])
			
		except subprocess.CalledProcessError as e:
			result = e.output.decode().strip()
			self.assertEqual('SSH Connection failed: [Errno 101] Network is unreachable', result)

	def testWrongPort(self):
		try:
			result = subprocess.check_output(['python3', 'gvm-cli.py', '--port=127', '--xml=<get_version/>'])
			
		except subprocess.CalledProcessError as e:
			result = e.output.decode().strip()
			self.assertEqual('SSH Connection failed: [Errno None] Unable to connect to port 127 on 127.0.0.1', result)

	def testWrongUnixSocketPath(self):
		try:
			result = subprocess.check_output(['python3', 'gvm-cli.py', '--socket=/this/is/wrong.sock', '--xml=<get_version/>'], stderr=subprocess.STDOUT)			
		except subprocess.CalledProcessError as e:
			result = e.output.decode().strip()						
			self.assertEqual('Error with unix socket connection: [Errno 2] No such file or directory', result)

	def testInvalidXMLSyntax(self):
		try:
			result = subprocess.check_output(['python3', 'gvm-cli.py', '--xml=<get_vversion/>', '--gmp-password=admin'], stderr=subprocess.STDOUT)
		except subprocess.CalledProcessError as e:
			result = e.output.decode().strip()
			self.assertEqual('GMP Response status not ok', result)

	def testWrongSSHUsername(self):
		try:
			result = subprocess.check_output(['python3', 'gvm-cli.py', '--xml=<get_version/>', '--ssh-user=bla'], stderr=subprocess.STDOUT)
		except subprocess.CalledProcessError as e:
			result = e.output.decode().strip()
			self.assertEqual('SSH Connection failed: Authentication failed.', result)

	def testWrongGMPCredentials(self):
		try:
			result = subprocess.check_output(['python3', 'gvm-cli.py', '--xml=<get_version/>', '--gmp-username=bla', '--gmp-password=admin'], stderr=subprocess.STDOUT)
		except subprocess.CalledProcessError as e:
			result = e.output.decode().strip()
			self.assertEqual('Connection closed by server', result)

	def testWithoutParameter(self):
		print('Validation with <get_version/> and Pass: admin')
		result = subprocess.check_output(['python3', 'gvm-cli.py'])
		result = result.decode().strip()
		self.assertEqual(self.version_answer, result)

	def testParametersOwnXMLInput(self):
		print('You have to type an simple "<get_version/>"')
		result = subprocess.check_output(['python3', 'gvm-cli.py', '--gmp-password=admin'])
		result = result.decode().strip()
		self.assertEqual(self.version_answer, result)

	def testParameterVersionwithSocket(self):
		result = subprocess.check_output(['python3', 'gvm-cli.py', '--gmp-password=admin', '--socket', '--xml=<get_version/>'])
		result = result.decode().strip()
		self.assertEqual(self.version_answer, result)


	def testParameterVersionWithTLS(self):
		result = subprocess.check_output(['python3', 'gvm-cli.py', '--gmp-password=admin', '--tls', '--xml=<get_version/>'])
		result = result.decode().strip()
		self.assertEqual(self.version_answer, result)

	def testParamterWithWrongGMPPassword(self):
		try:
			result = subprocess.check_output(['python3', 'gvm-cli.py', '--gmp-password=aaadmin', '--xml=<get_version/>'])
			result = result.decode().strip()
		except subprocess.CalledProcessError as e:
			self.assertEqual(1, e.returncode)
	


if __name__ == '__main__':
	unittest.main()