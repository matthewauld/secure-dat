# Secure Dat Library

##Install instruction
simply clone repo, and run ```npm run install```
NOTE: Relies on the OpenABEJS library, which compiles from source.

## Source Files
### secure-dat.js
Contains a wrapper around a Dat instance (using compositon instead of inheritance, since the dat codebase is still in flux, and there will be breaking changed. Also to prevent users with access to underlying read/write functions), adding add and remove user functions, as well as read and write functions that encrypt data.

### secure-params.js
Simple class that manages user parameters and serialization/deserialization of those params.


## Files

### /.sdat/config
Public key used for diffie hellman exchange, pubic key for encrypting abe key, other config(key_size/algorithms used, etc.)

### /.sdat/pub_params
Public params used for abe encryption

### /.sdat/users/xxx
- accesses granted for each user
- diffie hellman key exchange between /.sdat/pub and dat we want to grant access to, then hashed to form xxx
- contains their private key

### Secure param files
 - created when a new SecureDat is created, contains json object with private keys and user lists for the
 - if passed into ```SecureDat.load()``` with the full
