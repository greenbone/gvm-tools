import unittest
from libs.gvm_connection import (SSHConnection,
                                 GMPError)
import warnings
import lxml

# UnitOfWork_StateUnderTest_ExpectedBehavior
# Sum_NegativeNumberAs2ndParam_ExceptionThrown ()


class GMPTest(unittest.TestCase):
    hostname = 'localhost'
    CURRENT_VERSION = '8.0'
    AUTHENTICATION_ERR_MSG = 'Authentication failed'
    STATUS_TEXT_OK = 'OK'

    def setUp(self):
        warnings.simplefilter("ignore", ResourceWarning)
        self.gmp = SSHConnection(hostname=self.hostname, port=22,
                                 timeout=5, ssh_user='gmp',
                                 ssh_password='', shell_mode=True)

    def tearDown(self):
        self.gmp.close()

    def test_Authenticate_WrongUsernameAs1stParam_ExceptionThrown(self):
        with self.assertRaises(GMPError) as context:
            self.gmp.authenticate('amin', 'admin')

        self.assertEqual(self.AUTHENTICATION_ERR_MSG, str(context.exception))

    def test_Authenticate_WrongPasswordAs2stParam_ExceptionThrown(self):
        with self.assertRaises(GMPError) as context:
            self.gmp.authenticate('admin', 'admn')

        self.assertEqual(self.AUTHENTICATION_ERR_MSG, str(context.exception))

    def test_Authenticate_RightCredentialsWithCorrectCommand_CorrectVersionNumber(self):
        result = self.gmp.authenticate('admin', 'admin', '<get_version/>')
        version = result.xpath('get_version_response/version/text()')[0]

        self.assertEqual(self.CURRENT_VERSION, version)

    def test_Authenticate_RightCredentials_OKAsStatustext(self):

        result = self.gmp.authenticate('admin', 'admin')
        status_text = result.xpath('@status_text')[0]
        self.assertEqual(self.STATUS_TEXT_OK, status_text)
