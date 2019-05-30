import pytest
from asynctest import patch, Mock, CoroutineMock
import sys, os, subprocess
from pathlib import Path
# Enable importing of the module to be tested
test_dir = Path(os.path.dirname(os.path.realpath(__file__)))
root_dir = test_dir.parent
sys.path.append(str(root_dir))
from sshapiauthenticator.auth import SSHAPIAuthenticator

def get_file(filepath):
    if os.path.exists(filepath):
        with open(filepath, 'r') as f:
            return f.read()
    return None

def keypath(username, cert_path):
    return str(Path(cert_path)/f'{username}.key')

def assert_valid_keys_exist(ssh_key, username='tester', cert_path='/tmp/', encoding='utf8'):
    key = keypath(username, cert_path)
    assert get_file(key) == ssh_key
    public_key = subprocess.check_output(['ssh-keygen', '-f', key, '-y'])
    assert get_file(f'{key}.pub') == public_key.decode(encoding)
    assert get_file(f'{key}-cert.pub') == ssh_key[ssh_key.find('ssh-rsa-cert'):]

def assert_keys_do_not_exist(username='tester', cert_path='/tmp/'):
    key = keypath(username, cert_path)
    assert get_file(key) is None
    assert get_file(f'{key}.pub') is None
    assert get_file(f'{key}-cert.pub') is None

@pytest.fixture(autouse=True)
def cleaner():
    """If a test uses a different username and cert_path, it should call
    cleaner.config(username, cert_path) before exiting"""
    class Cleaner():
        def __init__(self):
            self.username = 'tester'
            self.cert_path = '/tmp/'

        def config(self, username, cert_path):
            self.username = username
            self.cert_path = cert_path

        def remove_files(self):
            key = keypath(self.username, self.cert_path)
            public_key = f'{key}.pub'
            cert = f'{key}-cert.pub'
            for file in [key, public_key, cert]:
                try:
                    os.remove(file)
                except FileNotFoundError as e:
                    pass
    cleaner = Cleaner()
    yield cleaner
    cleaner.remove_files()

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
        return_value=Mock(
            spec=['code', 'body'],
            **{'code': 200, 'body': ssh_key.encode('utf8')},
        )
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = 'non-empty'
    username = 'tester'
    data = {'username': username, 'password': 'valid'}
    assert_keys_do_not_exist()
    resp = await authenticator.authenticate(None, data)
    assert_valid_keys_exist(ssh_key)
    assert resp == username

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_no_skey_valid_credentials(mock_httpclient, ssh_key):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    async_client.fetch = CoroutineMock(
        return_value=Mock(
            spec=['code', 'body'],
            **{'code': 200, 'body': ssh_key.encode('utf8')},
        )
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = ''
    username = 'tester'
    data = {'username': username, 'password': 'valid'}
    assert_keys_do_not_exist()
    resp = await authenticator.authenticate(None, data)
    assert_valid_keys_exist(ssh_key)
    assert resp == username

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_no_skey_invalid_username_password(mock_httpclient, caplog):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    # Server sends 401: Unauthorized error code
    async_client.fetch = CoroutineMock(
        return_value=Mock(
            spec=['code', 'reason'],
            **{'code': 401, 'reason': 'Unauthorized'},
        )
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = ''
    handler = Mock(**{'request': Mock(**{'remote_ip': 'localhost'})})
    data = {'username': 'tester', 'password': 'invalid'}
    assert_keys_do_not_exist()
    resp = await authenticator.authenticate(handler, data)
    assert_keys_do_not_exist()
    assert resp is None
    logs = caplog.record_tuples
    assert len(logs) == 1
    _, _, message = logs[0]
    expected_message = (
        'SSH Auth API Authentication failed for tester@localhost'
        ' with error 401: "Unauthorized"'
    )
    assert message == expected_message

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_exception_with_handler(mock_httpclient, caplog):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    # No body, so _write_key will raise exception
    async_client.fetch = CoroutineMock(
        return_value=Mock(
            spec=['code'],
            **{'code': 200},
        )
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = ''
    handler = Mock(**{'request': Mock(**{'remote_ip': 'localhost'})})
    data = {'username': 'tester', 'password': 'valid'}
    assert_keys_do_not_exist()
    resp = await authenticator.authenticate(handler, data)
    assert_keys_do_not_exist()
    assert resp is None
    logs = caplog.record_tuples
    assert len(logs) == 1
    _, _, message = logs[0]
    expected_message = 'SSH Auth API Authentication failed for tester@localhost'
    assert message == expected_message

@pytest.mark.asyncio
@patch('sshapiauthenticator.auth.httpclient', autospec=True)
async def test_auth_exception_no_handler(mock_httpclient, caplog):
    async_client = mock_httpclient.AsyncHTTPClient.return_value
    # No body, so _write_key will raise exception
    async_client.fetch = CoroutineMock(
        return_value=Mock(
            spec=['code'],
            **{'code': 200},
        )
    )
    authenticator = SSHAPIAuthenticator()
    authenticator.server = 'http://localhost:9999'
    authenticator.skey = ''
    data = {'username': 'tester', 'password': 'valid'}
    assert_keys_do_not_exist()
    resp = await authenticator.authenticate(None, data)
    assert_keys_do_not_exist()
    assert resp is None
    logs = caplog.record_tuples
    assert len(logs) == 1
    _, _, message = logs[0]
    expected_message = 'SSH Auth API Authentication failed for user "tester"'
    assert message == expected_message