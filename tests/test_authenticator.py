import pytest
from asynctest import patch, Mock, CoroutineMock
import sys, os, pathlib, subprocess
# Enable importing of the module to be tested
test_dir = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
root_dir = test_dir.parent
sys.path.append(str(root_dir))
from sshapiauthenticator.auth import SSHAPIAuthenticator

@pytest.fixture(scope='module')
def ssh_key():
    # These calls will generate local files
    subprocess.call(['ssh-keygen', '-t', 'rsa', '-N', '', '-C', 'ca@localhost', '-f', 'ca'])
    subprocess.call(['ssh-keygen', '-s', 'ca', '-h', '-I', 'localhost', 'ca.pub'])
    skey = ''
    with open('ca', 'r') as f:
        skey += f.read()
    with open('ca-cert.pub', 'r') as f:
        skey += f.read()
    # Clean up generated files
    subprocess.call(['rm', 'ca', 'ca.pub', 'ca-cert.pub'])
    return skey

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_nonempty_skey_valid_credentials(mock_httpclient, ssh_key):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    async_client.fetch = CoroutineMock(
        return_value=Mock(**{'code': 200, 'body': ssh_key.encode('utf-8')})
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = 'non-empty'
    data = {'username': 'tester', 'password': 'valid'}
    resp = await authenticator.authenticate(None, data)
    assert resp == 'tester'

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_no_skey_valid_credentials(mock_httpclient, ssh_key):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    async_client.fetch = CoroutineMock(
        return_value=Mock(**{'code': 200, 'body': ssh_key.encode('utf-8')})
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = ''
    data = {'username': 'tester', 'password': 'valid'}
    resp = await authenticator.authenticate(None, data)
    assert resp == 'tester'

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_no_skey_invalid_username_password(mock_httpclient):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    # Server sends 401: Unauthorized error code
    async_client.fetch = CoroutineMock(
        return_value=Mock(**{'code': 401})
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = ''
    handler = Mock(**{'request': Mock(**{'remote_ip': 'http://localhost:9998'})})
    data = {'username': 'tester', 'password': 'invalid'}
    resp = await authenticator.authenticate(handler, data)
    assert resp is None

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_exception_with_handler(mock_httpclient):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    # No body, so _write_key will raise exception
    async_client.fetch = CoroutineMock(
        return_value=Mock(**{'code': 200})
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = ''
    handler = Mock(**{'request': Mock(**{'remote_ip': 'http://localhost:9998'})})
    data = {'username': 'tester', 'password': 'valid'}
    resp = await authenticator.authenticate(handler, data)
    assert resp is None

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_exception_no_handler(mock_httpclient):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    # No body, so _write_key will raise exception
    async_client.fetch = CoroutineMock(
        return_value=Mock(**{'code': 200})
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = ''
    data = {'username': 'tester', 'password': 'valid'}
    resp = await authenticator.authenticate(None, data)
    assert resp is None