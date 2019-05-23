# SSHAuth Authenticator

Enables SSHAuth Authentication for Jupyterhub. Acquires a private SSH key from a SSH Auth API service.

Use with [SSH Spawner](https://github.com/NERSC/SSHSpawner) to authenticate to remote host with SSHAuthSSH

## Installation

Requires Python 3

```
python setup.py install
```

## Configuration

See [jupyterhub_config.py](jupyterhub_config.py) for a sample configuration

## Testing

In whatever environment you wish to run the tests, run `pip install -r test_requirements.txt`.

If you have [pipenv](https://github.com/pypa/pipenv) installed, you can run `pipenv install -r test_requirements.txt` to create an environment and do the installations in one step.

Then in that environment run `pytest --cov-report html --cov=sshapiauthenticator` from the project root directory to run the tests and generate a coverage report.