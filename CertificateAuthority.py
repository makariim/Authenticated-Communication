from utils import default_backend, serialization, hashes, rsa, padding, os
import ELGamal as camel

CA_private_key = rsa.generate_private_key( 
    public_exponent=65537,              
    key_size=2048,
    backend=default_backend()
)

class Certificate_Authority:

    def __init__(self):

        pem = CA_private_key.public_key().public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

        name = "CertificateAuthority"
        method = "RSA"

        self.store_key(pem, name, method)


    def store_key(self, pkey, name, method):

        write_method = "wb" if method == "RSA" else "w"
        ext = method+".pem" if method == "RSA" else method
        f = open("Keys/"+name+'-'+ext, write_method)
        f.write(pkey)
        f.close()

    def get_key(self, id):

        if(id.endswith("ELGamal")):
            if(os.path.exists("Keys/"+id) == False):
                return 0
            f = open("Keys/"+id,"r")
            pk = f.read()
            return int(pk)

        else:
            if(os.path.exists("Keys/"+id+".pem") == False):
                return 0
            with open("Keys/"+id+".pem", "rb") as key_file:

                public_key = serialization.load_pem_public_key(
                    key_file.read(),
                    backend=default_backend()
                )


                if(id=="CertificateAuthority-RSA"):
                    return public_key


                public_key_bytes = public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )

                signature = CA_private_key.sign(
                    public_key_bytes,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                return public_key, public_key_bytes, signature

