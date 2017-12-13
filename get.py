import requests

import getpass



r = requests.get('https://sshauthapi.nersc.gov/get_keys/canon')
print(r.text)
