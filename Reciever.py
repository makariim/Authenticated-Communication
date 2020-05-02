from utils import default_backend, serialization, hashes, rsa, padding, os
import CertificateAuthority as ca
import ELGamal as camel

CA = ca.Certificate_Authority()

private_key = rsa.generate_private_key( 
    public_exponent=65537,              
    key_size=2048,
    backend=default_backend()
)

pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

name = "Bob"
method = "RSA"

CA.store_key(pem, name, method)

open('tunnel', 'w').close()

while(1):
        
    f = open("tunnel", "rb")

    if(os.stat("tunnel").st_size == 0):
        continue

    print("\nJust recieved a message!\n")

    ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    plaintext = str(plaintext, 'utf-8')

    message, r, s = plaintext.split(",,SIGN,,")
    r, s = int(r), int(s)

    a, p = camel.get_parameters()

    Alice_pk = CA.get_key("Alice-ELGamal")

    if(camel.verify_sign(p, a, Alice_pk, r, s, bytes(message, 'utf-8'))):
        print("Message is authorized successfully! It is recieved from Alice.\n")
        print("Alice: ",message)
    else:
        print("Message is not sent from Alice!")
    
    print("\n-------------------------------------------------------------------")
    
    open('tunnel', 'w').close()

    


