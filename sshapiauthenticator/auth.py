import os

from traitlets import Unicode, Integer
from tornado import gen
import requests

from jupyterhub.auth import Authenticator


class SSHAPIAuthenticator(Authenticator):
    """Authenticate local Linux/UNIX users with SSH API"""
    encoding = Unicode('utf8',
                       help="""The encoding to use for SSH API"""
                       ).tag(config=True)
    server = Unicode('https://localhost',
                     help="""The SSH Auth API server URL to use for authentication."""
                     ).tag(config=True)

    cert_path = Unicode('/tmp/',
                               help="""The path for the cert/key file"""
                               ).tag(config=True)

    @gen.coroutine
    def authenticate(self, handler, data):
        """Authenticate with SSH Auth API, and return the privatre key
        if login is successful.

        Return None otherwise.
        """
        username = data['username']
        pwd = data['password']
        try:
            headers={'Authorization':'Basic %s:%s' % (username,pwd)}
            r = requests.post( self.server, headers=headers)
            if r.status_code==200:
               file = '%s/%s.key' %(cert_path, user)
               with open(file, 'w') as f:
                  f.write(r.text)
               os.chmod(file, 0o600)

        except:
            if handler is not None:
                self.log.warning("SSH Auth API Authentication failed (%s@%s):",
                                 username, handler.request.remote_ip)
            else:
                self.log.warning("SSH Auth API Authentication failed: ")
            return None
        else:
            return username
