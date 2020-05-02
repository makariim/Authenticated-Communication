from utils import default_backend, rsa, serialization, num, sha, random
import CertificateAuthority as ca
import string

def randomString(stringLength=5):
    letters = string.ascii_lowercase
    return ''.join(random.choice(letters) for i in range(stringLength))

N = 16

safe_prime = 0
while(True):
    p = num.getPrime(N)
    safe_prime = 2*p+1
    if(num.isPrime(safe_prime)):
        break
while(True):
    a = random.randint(2, safe_prime-1) 
    if((safe_prime-1)%a != 1):
        break

f = open("Parameters.txt", "w")
f.write(str(p)+'\n'+str(a))
f.close()

CA = ca.Certificate_Authority()

for i in range(10):

    x = random.randint(1, p-2)
    y = pow(a,x,p)  

    name = randomString(random.randint(3, 10))
    method = "ELGamal"

    CA.store_key(str(y), name, method)


for i in range(10):

    private_key = rsa.generate_private_key( 
        public_exponent=65537,              
        key_size=2048,
        backend=default_backend()
    )

    pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            )

    name = randomString(random.randint(4, 6))
    method = "RSA"

    CA.store_key(pem, name, method)
