# Secure Dat



## Files


### /.sdat/config
Public key used for diffie hellman exchange, other config(key_size/algorithms used, etc.)

### /.sdat/pub_params
Public params used for encryption

### /.sdat/groups
- List of groups and their current key_IDs. Group names could be meaningful (like "family" and "friends") or not.  TODO: SHOULD I ENCRYPT THIS FILE? PERHAPS?


### /.sdat/users/xxx
- accesses granted for each user
- diffie hellman key exchange between /.sdat/pub and dat we want to grant access to, then hashed to form xxx
- contains one or more keys for basic groups in the following format, encrypted with that users public key
```
type:   | id     | key              |
length: | 1 byte | |key|            |
```

### /.sdat/keys/xxx
- xxx is an incrementing counter, used as key_id
- there are two formats: one for basic group, and one for composite groups
- NOTE: |key| represents the size of an encrypted key - which may be larger that the key itself. should be specified in /.sdat/index_key

#### Basic Keys
- inital_key_id: what was the ID of the first key with this name.
- prev_key ID and prev_key: previous key used for this name. If there was no previous key, 000.
- dependant_key_id: ordered list of all composite keys that this key grants access to.
```
type:   | inital_key_id   | prev_key ID     | prev_key | dependant_key_id| ... |
length: | 1 byte          | 1 byte          | |key|    | 1 byte          | ... |
```

#### Composite Keys
- keys encoded with one or more basic keys
- operation: 0 for AND, 1 for OR
- id1 and id2: keys needed to decode this key.
- key1 and key2: If operation is AND, key1 is the key encrypted by keys represented by id1 and id2, with key2 unused. If operation is OR, key1 is compsite key encrypted by key at id1,  and likewise for |key2|
```
type:   | operation | id1    | id2    | key1  | key2 | dependant_key_id |
length: | 1 byte    | 1 byte | 1 byte | |key| | |key|| 1 byte           |
```



## Functions
Just like any other user, the main user has a userID and user file, which must have access to all the files.

### GetKeys
1. Read /.sdat/config - perform key exchange with your private key and hash it. this is your index, _i_.
2. Access /.sdat/users/_i_, and decrypt using private keys. These are the groups you belong to.

### Encrypt
1. Assume you already have your keys.
2. Check to see if the group you want to encrypt under already exists.
2. If it does, perform a breath-first search
