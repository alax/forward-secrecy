Overview
--------
fsec this is derived from `forward-secrect`
''' 
`forward-secrecy` is a simple implementation of the Axolotl key-ratcheting protocol written in Javascript. It uses NaCl (in this case, [TweetNacl](https://github.com/dchest/tweetnacl-js)) for encryption, meaning sessions are secured with Curve25519 keys and Salsa20 encryption.
'''
which can be found @ https://github.com/alax/forward-secrecy


`fsec` aims to become a fully contained, easy to read, test and expand, implementation of the omemo protocol.


Milestones
--------

**current:**
''' 
8-10 june 2017:  forward-secrecy clones, built and tested 
11 june 2017: reading axolotl/olm spec as well as further omemo protocol inspection to identify missing pieces
'''
**upcoming**
''' 
11-18 june 2017: fsec gets prepared to implement omemo by creating a skeleton of
missing functions between axolotl/olm and omemo.
'''
**future 1**
19 june onwards
'''
implementing said functions
'''
**future 2**
'''
implementing tests for the added functions
'''
**future 3**
'''
adding xmpp layer, look into the possibility of protocol modularity to see if an omemo session can benefit something else other than xmpp.
'''


**projected preliminary completion date**
august 30th.
