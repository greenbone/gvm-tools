import unittest
import argparse
import sys
from gvm_connection import GVMConnection


class GVMConnectionTest(unittest.TestCase):

    def setUp(self):
        parser = argparse.ArgumentParser(
            prog='gvm-cli',
            add_help=False,
            usage='gvm-cli [--help] [--hostname HOSTNAME] [--port PORT] [--xml XML]')
        parser.add_argument('-h', '--help', action='help',
                            help='Show this help message and exit.')
        parser.add_argument('-c', '--config', nargs='?', const='~/.config/gvm-tools.conf',
                            help='Path to the configuration file. Default: ~/.config/gvm-tools.conf')
        parser.add_argument('--hostname', default='127.0.0.1',
                            help='SSH hostname or IP-Address. Default: 127.0.0.1.')
        parser.add_argument('--tls', action='store_true',
                            help='Use TLS secured connection for omp service.')
        parser.add_argument('--port', default=22,
                            help='SSH port. Default: 22.')
        parser.add_argument('--ssh-user', default='gmp',
                            help='SSH username. Default: gmp.')
        parser.add_argument('--gmp-username', default='admin',
                            help='GMP username. Default: admin')
        parser.add_argument('--gmp-password', default='admin',
                            help='GMP password. Default: admin.')
        parser.add_argument('--socket', default='/usr/local/var/run/openvasmd.sock',
                            help='Path to UNIX-Socket. Default: /usr/local/var/run/openvasmd.sock.')
        parser.add_argument('-X', '--xml', help='The XML request to send.')
        parser.add_argument('infile', nargs='?', type=open, default=sys.stdin)

        self.argv = parser.parse_args()

    def testSSHConnection(self):
        gmp = GVMConnection(GVMConnection.SSH, self.argv)
        gmp.authenticate()

        self.assertEqual(gmp.get_version(
        ), '<get_version_response status="200" status_text="OK"><version>7.0</version></get_version_response>')
        gmp.close()

    def testUnixSocketConnection(self):
        gmp = GVMConnection(GVMConnection.UNIX_SOCKET, self.argv)
        gmp.authenticate()

        self.assertEqual(gmp.get_version(
        ), '<get_version_response status="200" status_text="OK"><version>7.0</version></get_version_response>')
        gmp.close()

    def testTLSConnection(self):
        gmp = GVMConnection(GVMConnection.TLS, self.argv)
        gmp.authenticate()

        self.assertEqual(gmp.get_version(
        ), '<get_version_response status="200" status_text="OK"><version>7.0</version></get_version_response>')
        gmp.close()


if __name__ == '__main__':
    unittest.main()
