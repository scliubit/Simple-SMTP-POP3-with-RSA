from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as Cipher_pkcs1_v1_5
import base64

with open('1', 'r') as f:
    content = f.read()
    # print(content)
    # string = content.split('\n\n')
    # print(string)
    boundary = '------=_BIT2019CommonBoundary'
    string = content.split(boundary)
    print(len(string))
    content = string[1]
    content = content.split('\n')
    print(content)
    while True:
        if content[-1] == '':
            content = content[0:-1]
        elif content[0] == '':
            content = content[1:]
        elif ('Content' in content[0]) or ('charset' in content[0]):
            content = content[1:]
        else:
            break
    string = ''
    for i in content:
        string += i
    print(string)
    with open('content', 'w') as f2:
        f2.write(string)

    # print(base64.b64decode(string))
