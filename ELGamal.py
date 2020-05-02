from utils import hashes, random, num, sha

def get_parameters():

    f = open("Parameters.txt", "r")
    lines = f.readlines()
    p = int(lines[0])
    a = int(lines[1])
    f.close()
    return a, p

def generate_key():
    
    a, p = get_parameters()

    # Private Key is x, public key is y
    x = random.randint(1, p-2)
    y = pow(a,x,p)
    
    return x, y, a, p 

def generate_sign(p, a, x, m):
	
	h = sha.new()
	h.update(m)
	m = int(h.hexdigest(), 35)

	while 1:
		k = random.randint(1,p-2)
		if num.GCD(k,p-1)==1: break
	r = pow(a,k,p)
	l = num.inverse(k, p-1)
	s = l*(m-x*r)%(p-1)
	return r,s

def verify_sign(p, a, y, r, s, m):

	h = sha.new()
	h.update(m)
	m = int(h.hexdigest(), 35)

	if r < 1 or r > p-1 : return False
	v1 = pow(y,r,p)%p * pow(r,s,p)%p
	v2 = pow(a,m,p)
	return v1 == v2
