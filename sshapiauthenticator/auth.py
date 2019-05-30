import os
import json
from pathlib import Path
from subprocess import check_output

from traitlets import Unicode, Integer
from tornado import httpclient, httputil
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
        out = check_output(['ssh-keygen', '-f', str(file), '-y'])
        with open(f'{file}.pub', 'w') as f:
            f.write(str(out, self.encoding))
        for line in data.split('\n'):
            if line.startswith('ssh-rsa-cert'):
                with open(f'{file}-cert.pub', 'w') as f:
                    f.write(f'{line}\n')

    async def authenticate(self, handler, data):
        """Authenticate with SSH Auth API, and return the private key
        if login is successful.

        Return None otherwise.
        """
        username = data['username'].lower()
        pwd = data['password']
        try:
            request = httpclient.AsyncHTTPClient()
            if self.skey != '':
                headers = httputil.HTTPHeaders({'content-type': 'application/json'})
                body = json.dumps({'skey': self.skey})
                resp = await request.fetch(self.server,
                                           raise_error=False,
                                           method='POST',
                                           headers=headers,
                                           auth_username=username,
                                           auth_password=pwd,
                                           body=body)
            else:
                resp = await request.fetch(self.server,
                                           raise_error=False,
                                           method='POST',
                                           headers=None,
                                           auth_username=username,
                                           auth_password=pwd)
            if resp.code == 200:
                file = Path(self.cert_path)/f'{username}.key'
                self._write_key(file, resp.body.decode(self.encoding))
            else:
                message = (
                    f'SSH Auth API Authentication failed for'
                    f' {username}@{handler.request.remote_ip}'
                    f' with error {resp.code}: "{resp.reason}"'
                )
                self.log.warning(message)
                return None
        except:
            message = f'SSH Auth API Authentication failed for user "{username}"'
            if handler is not None:
                message = (
                    f'SSH Auth API Authentication failed for'
                    f' {username}@{handler.request.remote_ip}'
                )
            self.log.warning(message)
            return None
        else:
            return username
