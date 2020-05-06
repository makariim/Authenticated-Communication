from utils import hashes, rsa, padding, os
import CertificateAuthority as ca
import ELGamal as camel

x, y, a, p = camel.generate_key()

CA = ca.Certificate_Authority()

name = "Alice"
method = "ELGamal"

CA.store_key(str(y), name, method)

inputfile = False

while(1):

    pk, pk_bytes, sign = CA.get_key("Bob-RSA")

    if(pk == 0):
        continue

    authority_public_key = CA.get_key("CertificateAuthority-RSA")

    verified = authority_public_key.verify(
                    sign,
                    pk_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

    if(verified == False):
        print("\nPublic key is not verified!\n")
        continue

    print("\nPublic key is verified successfully! It is recieved from the Certificate Authority.")

    if(os.path.exists("test.txt")):
        if(os.stat("test.txt").st_size != 0):
            f = open("test.txt", "r")
            message = f.read()
            f.close()
            inputfile = True
        else:
            message = input("\nEnter Message: \n\n")

    r,s = camel.generate_sign(p, a, x, bytes(message, 'utf-8'))

    to_encrypt = message+",,SIGN,,"+str(r)+",,SIGN,,"+str(s)

    ciphertext = pk.encrypt(
        bytes(to_encrypt, 'utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )   

    print("\n-----------------------------------------------------------------------------------")

    f = open("tunnel","wb")
    f.write(ciphertext)
    f.close()

    if(inputfile):
        break
