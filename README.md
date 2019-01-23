# One Time Ring Signature

### Background

A digital signature is a cryptographic method for verifiying the authenticity 
of messages. A ring signature is a subset of digital signatures where the 
signature can be performed by any member of a group of users.

This particular construction of ring signature has the special property: 
a member of the ring can only sign once with guaranteed anonymity. Any user
that uses their key more than once loses anonymity.

### Usage

`pipenv shell`

`OTRS.py genkey`
