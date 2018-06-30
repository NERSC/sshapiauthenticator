import os

from traitlets import Unicode, Integer
from tornado import gen
import requests
import json
from subprocess import check_output


from jupyterhub.auth import Authenticator


class SSHAPIAuthenticator(Authenticator):
    """Authenticate local Linux/UNIX users with SSH API"""
    encoding = Unicode('utf8',
                       help="""The encoding to use for SSH API"""
                       ).tag(config=True)

    server = Unicode('https://localhost',
                     help="""The SSH Auth API server URL to use for authentication."""
                     ).tag(config=True)

    skey = Unicode('',
                   help="""Shared key to use for a scope."""
                   ).tag(config=True)

    cert_path = Unicode('/tmp/',
                        help="""The path for the cert/key file"""
                        ).tag(config=True)

    def _write_key(self, file, data):
        with open(file, 'w') as f:
            f.write(data)
        os.chmod(file, 0o600)
        out = check_output(["ssh-keygen","-f",file,'-y'])
        with open(file+'.pub','w') as f:
            f.write(str(out, 'utf-8'))
        for line in data.split('\n'):
          if line.startswith('ssh-rsa-cert'):
            with open(file+'-cert.pub', 'w') as f:
                f.write(line)

    @gen.coroutine
    def authenticate(self, handler, data):
        """Authenticate with SSH Auth API, and return the privatre key
        if login is successful.

        Return None otherwise.
        """
        username = data['username']
        pwd = data['password']
        try:
            headers = {'Authorization': 'Basic %s:%s' % (username, pwd)}
            if self.skey!='':
                data = json.dumps({'skey':self.skey})
                r = requests.post(self.server, headers=headers, data=data)
            else:
                r = requests.post(self.server, headers=headers)
            if r.status_code == 200:
                file = '%s/%s.key' % (self.cert_path, username)
                self._write_key(file, r.text)
            else:
                self.log.warning("SSH Auth API Authentication failed (%s@%s):",
                                 username, handler.request.remote_ip)
                return None
        except:
            if handler is not None:
                self.log.warning("SSH Auth API Authentication failed (%s@%s):",
                                 username, handler.request.remote_ip)
            else:
                self.log.warning("SSH Auth API Authentication failed: ")
            return None
        else:
            return username
