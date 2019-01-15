#!/usr/bin/env python
# coding: utf-8

# In[15]:


import hashlib
import os
import random
import secrets


# In[16]:


def PRG(seed):
    # Wrapper for a PRG
    # TODO? Implement one from a hash functoin
    random.seed(seed)        
    return format(random.getrandbits(len(seed)*3), f'0{len(seed)*3}b')

def gen_seed(length):
    return format(secrets.randbits(length), f'0{length}b')

#@click.command()
#@click.argument('N')
#@click.argument('pk')
#@click.argument('l')
def GenTestRing(N, pkl, l):
    """
    Generate a sample Ring.
    args:
        N: The number of people in the ring
        pkl: the public key that we know
        l: the position of the public key
        
    returns:
        A ring of N people, each person has a public key of type [128]
    """
    
    R = []
    
    for j in range(N):
        if j == l:
            R.append(pkl)
        else:
            pkj=[]
            for i in range(128):                
                pk = gen_seed(128)
                pkj.append(pk)
            R.append(pkj)
    return R

#@click.command()
def GenKey():
    # Generate a public/private key pair
    
    sk = []
    pk = []
    for j in range(128):
        
        # generate 2 random secret keys. 
        s1 = gen_seed(128)
        s2 = gen_seed(128)
        sk.append((s1,s2))
        
        # use each secret key as the seed to the PRG that will generate the public key
        pk1 = PRG(s1)        
        pk2 = PRG(s2) 
        pk.append(format((int(pk1,2)^int(pk2,2)), '0384b'))
    
    return (sk, pk)


# In[7]:


def RSign(R, skl, l, m):
    """
    Performs a ring signature
    
    args:
        R: The ring used
        skl: The secret key
        l: the position we are in R Note: maybe this should be the pk, and we can check for pk match in R
        m: the message signed
    """
    x = []
    r = []
    c=[]
    for i in range(128):
        ri=[]
        ci=[]
        xi = format(secrets.randbits(128), '0128b')

        # This is our ring position
        if i == l:
            for j in range(128):
                cij=PRG(skl[j][0])                
                ci.append(cij)
                
        # for everyone else, use a random number as seed
        else:            
            for j in range(128):
                rij = format(secrets.randbits(128), '0128b')                                
                prg_rij=PRG(rij)
                if xi[j] is '0':
                    cij=prg_rij
                else:
                    cij=format(int(prg_rij,2)^int(R[i][j], 2), '0384b')
                ci.append(cij)
                ri.append(rij)
        c.append(ci)
        x.append(xi)
        r.append(ri)
        
    # hash it!
    z = hashlib.shake_128("{R}{m}{c}".format(R=str(R), m=m, c=str(c)).encode('utf-8')).hexdigest(length=16)
    z2 = int(z, 16)

    # get the ⊕x[i!=l]
    xl=0
    for i in range(128):
        if i==l:
            pass
        else:
            xl=int(x[i],2)^xl
    
    # set x[l] such that ⊕x[i]==z2
    x[l]=format(xl^z2, '0128b')
    
    # set the random seed for l, so that we always end up with PRG[r[l][j]]==PRG(sk[j][0])
    r[l]=[0 for x in range(128)]    
    for j in range(128):        
        r[l][j]=skl[j][int(x[l][j])]
    
    return (x, r)


# In[8]:


def RVerify(R, sigma, m):
    """
    Verifies a ring signature
    
    args:
        R: The ring used
        sigma: The signature to verify
        m: the message signed
    """
    # parse sigma into x and r
    x=sigma[0]
    r=sigma[1]
    c=[]
    
    for i, xi in enumerate(x):
        ci=[]
        for j in range(128):
                                
            prg_rij=PRG(r[i][j])
            if xi[j] is '0':
                cij=prg_rij
            else:
                cij=format(int(prg_rij,2)^int(R[i][j], 2), '0384b')
            ci.append(cij)
        c.append(ci)
    
    # hash it!
    z = hashlib.shake_128("{R}{m}{c}".format(R=str(R), m=m, c=str(c)).encode('utf-8')).hexdigest(length=16)
    z2 = int(z, 16)

    # get ⊕x[i]
    xl=0
    for i in range(128):
        xl=int(x[i],2)^xl    

    # verify that ⊕x[i]==z2
    return xl==z2


# In[12]:


l=0
(sk, pk) = GenKey()
R = GenTestRing(128, pk, l)


# In[13]:


sigma= RSign(R, sk, l, "I'm a test message")


# In[14]:


RVerify(R, sigma, "I'm a test message")


# In[ ]:




