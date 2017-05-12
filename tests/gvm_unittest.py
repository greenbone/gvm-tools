import unittest
from libs.gvm_connection import (SSHConnection,
                                 TLSConnection,
                                 UnixSocketConnection,
                                 GMPError)
import warnings
import lxml


class GVMConnectionTest(unittest.TestCase):

    answer_ok = '<get_version_response status="200" status_text="OK"><version>\
8.0</version></get_version_response>'
    username = 'admin'
    password = 'admin'
    hostname = 'localhost'
    sockpath = '/usr/local/var/run/openvasmd.sock'

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)

    def testSSHConnection(self):
        gmp = SSHConnection(hostname=self.hostname, port=22,
                            timeout=5, ssh_user='gmp',
                            ssh_password='', shell_mode=False)

        version = gmp.get_version()
        gmp.close()
        self.assertEqual(version, self.answer_ok)

    def testSSHConnectionWithWrongHostname(self):

        try:
            SSHConnection(hostname='42.42.42.42', port=22,
                          timeout=5, ssh_user='gmp',
                          ssh_password='', shell_mode=False)
        except Exception as e:
            self.assertEqual(str(e), 'timed out')

    def testSSHConnectionWithWrongPort(self):

        try:
            SSHConnection(hostname='localhost', port=23,
                          timeout=5, ssh_user='gmp',
                          ssh_password='', shell_mode=False)
        except Exception as e:
            self.assertEqual(str(e), '[Errno None] Unable to connect to port \
23 on 127.0.0.1 or ::1')

    def testSSHConnectionWithWrongSSHUsername(self):

        try:
            SSHConnection(hostname='localhost', port=22,
                          timeout=5, ssh_user='gmppp',
                          ssh_password='', shell_mode=False)
        except Exception as e:
            self.assertEqual(str(e), 'Authentication failed.')

    def testSSHConnectionWithWrongSSHPassword(self):

        try:
            SSHConnection(hostname='localhost', port=22,
                          timeout=5, ssh_user='gmp',
                          ssh_password='test', shell_mode=False)
        except Exception as e:
            self.assertEqual(str(e), 'Authentication failed.')

    def testUnixSocketConnection(self):
        gmp = UnixSocketConnection(sockpath=self.sockpath, shell_mode=False)

        version = gmp.get_version()
        gmp.close()
        self.assertEqual(version, self.answer_ok)

    def testUnixSocketConnectionWrongPath(self):
        try:
            UnixSocketConnection(sockpath='/foo/bar', shell_mode=False)
        except Exception as e:
            self.assertEqual(str(e), '[Errno 2] No such file or directory')

    def testTLSConnection(self):
        gmp = TLSConnection(hostname=self.hostname, port=9390,
                            shell_mode=False)
        version = gmp.get_version()
        gmp.close()
        self.assertEqual(version, self.answer_ok)

    def testTLSConnectionWithWrongHostname(self):

        try:
            TLSConnection(hostname='42.42.42.42', port=9390,
                          timeout=5, shell_mode=False)
        except Exception as e:
            self.assertEqual(str(e), 'timed out')

    def testTLSConnectionWithWrongPort(self):

        try:
            TLSConnection(hostname='localhost', port=9999,
                          shell_mode=False)
        except Exception as e:
            self.assertEqual(str(e), '[Errno 111] Connection refused')

    def testCheckInvalidCommandStatus(self):
        gmp = SSHConnection(hostname=self.hostname, port=22,
                            timeout=5, ssh_user='gmp',
                            ssh_password='', shell_mode=False)

        xml_invalid = '<get_version_response status="400" status_text="ERROR">\
<version>8.0</version></get_version_response>'

        try:
            gmp.checkCommandStatus(xml_invalid)
        except GMPError as e:
            self.assertEqual(str(e), 'ERROR')

        try:
            gmp.checkCommandStatus(0)
        except GMPError as e:
            self.assertEqual(str(e), 'XML Command is empty')

        try:
            gmp.checkCommandStatus(None)
        except GMPError as e:
            self.assertEqual(str(e), 'XML Command is empty')

        try:
            gmp.checkCommandStatus('')
        except Exception as e:
            self.assertIsInstance(e, lxml.etree.XMLSyntaxError)
        gmp.close()

if __name__ == '__main__':
    unittest.main()
