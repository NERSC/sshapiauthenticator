import requests

import getpass

user='canon'
pwd=getpass.getpass('password: ')

headers={'Authorization':'Basic %s:%s' % (user,pwd)}

r = requests.post('https://sshauthapi.nersc.gov/create_pair', headers=headers)
if r.status_code==200:
   with open('%s.key' %(user), 'w') as f:
      f.write(r.text)
print( r.text)
