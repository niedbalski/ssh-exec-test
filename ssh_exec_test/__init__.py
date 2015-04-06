from paramiko.transport import Transport
from paramiko.rsakey import RSAKey

from paramiko import (AUTH_SUCCESSFUL, OPEN_SUCCEEDED,
                      OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED)

try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

import socket
import threading
import select

import paramiko


class TransportChannel(Transport):

    DEFAULT_KEY = RSAKey(file_obj=StringIO(
        """-----BEGIN RSA PRIVATE KEY-----
MIIEogIBAAKCAQEAnahBtR7uxtHmk5UwlFfpC/zxdxjUKPD8UpNOOtIJwpei7gaZ
+Jgub5GFJtTG6CK+DIZiR4tE9JxMjTEFDCGA3U4C36shHB15Pl3bLx+UxdyFylpc
c7XYp4fpQjhFUoHOAIl5ZaA223kIxi7sFXtM1Gjy6g49u+G5teVfMbeZnks2xjjy
F84qVADFBXCsfjrY5m4R+Wnfups/jP1agOpnOvqHlX/bpvzEZRcwJ0A8CylBZzQP
D1Y4EXy1B4QLyLJKFIMRkWnr0f8rK5Q/obCLTjl+IMmZrkItbfC/hYCy6TDi+Efn
cgGw02L93Mf6QGDNc21BsRELPYMME22MmpLphQIBIwKCAQEAmScbQjtOWr1GY3r7
/dG90SGaG+w70AALDmM2DUEQy6k/MF4vLAGMMd3RzfNE4YDV4EgHszbVRWSiIsHn
pWJf7OyyVZ7s9r2LuO111gFr82iB98V+YcaX8zOSIxIXdLicOwk0GZRSjA8tGErW
tcg8AYqFkulDSMylxqRN2IZ3+NnTROxh4uUFH57roSYoCvzjM2v1Xa+S42BLpBD1
3mLAJD36JhOhMTgYUgHAROx9+YUUUzYk3jpkTGWnAYSumnJXQYphLE9zadXxh94N
HZJdvXajuP5N2M3Q2b4Gbyt2wNFlNcHGA+Zwk8wHIBnY9Sb9Gz0QALsOAwUoRY8T
rCysSwKBgQDPVjFdSgM3jScmFV9fVnx3iNIlM6Ea7+UCrOOCvcGtzDo5vuTPktw7
8abHEFHw7VrtxI3lRQ41rlmK3B//Q7b+ZJ0HdZaRdyCqW1u91tq1tQe7yiJBm0c5
hZ3F0Vr6HAXoBVOux5wUq55jvUJ8dCVYNYfctZducVmOos3toDkSzQKBgQDCqRQ/
GO5AU3nKfuJ+SZvv8/gV1ki8pGmyxkSebUqZSXFx+rQEQ1e6tZvIz/rYftRkXAyL
XfzXX8mU1wEci6O1oSLiUBgnT82PtUxlO3Peg1W/cpKAaIFvvOIvUMRGFbzWhuj7
4p4KJjZWjYkAV2YlZZ8Br23DFFjjCuawX7NhmQKBgHCN4EiV5H09/08wLHWVWYK3
/Qzhg1fEDpsNZZAd3isluTVKXvRXCddl7NJ2kuHf74hjYvjNt0G2ax9+z4qSeUhF
P00xNHraRO7D4VhtUiggcemZnZFUSzx7vAxNFCFfq29TWVBAeU0MtRGSoG9yQCiS
Fo3BqfogRo9Cb8ojxzYXAoGBAIV7QRVS7IPheBXTWXsrKRmRWaiS8AxTe63JyKcm
XwoGea0+MkwQ67M6s/dqCxgcdGITO81Hw1HbSGYPxj91shYlWb/B5K0+CUyZk3id
y8vHxcUbXSTZ8ls/sQqAhpZ1Tkn2HBpvglAaM+OUQK/G5vUSe6liWeTawJuvtCEr
rjRLAoGAUNNY4/7vyYFX6HkX4O2yL/LZiEeR6reI9lrK/rSA0OCg9wvbIpq+0xPG
jCrc8nTlA0K0LtEnE+4g0an76nSWUNiP4kALROfZpXajRRaWdwFRAO17c9T7Uxc0
Eez9wYRqHiuvU0rryYvGyokr62w1MtJO0tttnxe1Of6wzb1WeCU=
-----END RSA PRIVATE KEY-----"""))

    def __init__(self, server, client, rules):
        Transport.__init__(self, client)

        self.server = server
        self.encoding = "ascii"
        self.rules = rules
        self.add_server_key(self.DEFAULT_KEY)
        self.start_server(server=self)
        
    def has_rule(self, command):
        for rule in self.rules:
            if rule.command == command:
                return rule
        return False

    def check_channel_fordward_channel_request(self, channel):
        return True
    
    def check_channel_request(self, kind, channel_id):
        if kind in ('session', ):
            return OPEN_SUCCEEDED
        return OPEN_FAILED_ADMINISTRATIVELY_PROHIBITED
        
    def check_channel_exec_request(self, channel, command):
        rule = self.has_rule(command)
        if rule:
            if rule.output:
                channel.sendall(rule.output)
        else:
            self.server.exceptions.append(Exception(
                "Not found rule for input command: \"%s\"" % command))
                
        return True
    
    def check_auth_none(self, username):
        return AUTH_SUCCESSFUL

    def check_auth_password(self, username, password):
        return AUTH_SUCCESSFUL

    def check_auth_publickey(self, username, key):
        return AUTH_SUCCESSFUL

    def get_allowed_auths(self, username):
        return ('password', 'publickey', 'none')

    def check_channel_shell_request(self, channel):
        return False

    def enable_auth_gssapi(self):
        return AUTH_SUCCESSFUL

    def check_channel_pty_request(self, channel, term, width, height,
                                  pixelwidth,
                                  pixelheight, modes):
        return True

    
class Server(threading.Thread):

    DEFAULT_PORT = 2022
    DEFAULT_ADDR = "127.0.0.1"

    def __init__(self, addr, port, rules):
        threading.Thread.__init__(self)

        self.exceptions = []
        self.daemon = True
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.DEFAULT_ADDR, self.DEFAULT_PORT))

        if not isinstance(rules, list):
            self.rules = [rules]
        else:
            self.rules = rules
        
    def __enter__(self):
        self.start()
        return self

    def __exit__(self, *exc_info):
        self.stop()

    def stop(self):
        """
            Stop the server, waiting for the runloop to exit.
        """
        self.socket.close()
        if self.is_alive():
            self.join()

    def join(self):
        threading.Thread.join(self)

    def run(self):
        try:
            self.socket.listen(5)
            while True:
                r, w, x = select.select([self.socket], [], [], 1)
                if r:
                    sock = self.socket.accept()
                    client, address, port = (sock[0], sock[1][0], sock[1][1])
                    TransportChannel(self, client, self.rules)
        except (select.error, socket.error):
            pass


class Rule(object):

    def __init__(self, command, output=None, timeout=None):
        (self.command, self.output) = command, output

        
def input(command, output=None, timeout=None):
    return Rule(command, output=output, timeout=timeout)


def assert_ssh_exec(addr="127.0.0.1", port=2022, rules=()):
    return Server(addr, port, rules)
