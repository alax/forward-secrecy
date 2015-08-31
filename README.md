Overview
--------
`forward-secrecy` is a simple implementation of the Axolotl key-ratcheting protocol written in Javascript. It uses NaCl (in this case, [TweetNacl](https://github.com/dchest/tweetnacl-js)) for encryption, meaning sessions are secured with Curve25519 keys and Salsa20 encryption.

The primary goal of this project is to have a simple, easy-to-understand implementation of the ratcheting protocol so that developers can easily understand how the internals work. As such, the entirety of the protocol implementation code is contained in one thoroughly-commented file.

This library does not handle pre-key generation and other things necessary for a fully turnkey solution. If you're looking for such things, check out a much more complete implementation of Axolotl:

https://github.com/joebandenburg/libaxolotl-javascript

`forward-secrecy` deals strictly with only the code necessary for the protocol itself to work. Some knowledge of how asymmetric crypto systems work is assumed. In the interest of keeping the code concise, you are expected to handle key storage, transmission, and creation yourself.

**This library has not been audited, meaning that it is absolutely unsafe to use for any real security. You have been warned.**

Installation
------------

Simply install the library with NPM:

```javascript
npm install forward-secrecy
```

And then require the project:

```javascript
var SecretSession = require('forward-secrecy')
```

This is compatible with browsers using tools such as browserify or webpack.

Usage
-----
This library implements the no-header-keys, role-select version of Axolotl. Meaning, headers are not encrypted, and when setting up a session, you must explicitely set your role as the `initiator` or the `receiver`.

It also depends on [TweetNacl](https://github.com/dchest/tweetnacl-js)'s implementation of keypairs for all keys. 

*The hardest part about using this library for beginners will be understanding key generation, transmission, and which keys to use where.*

Example:

```javascript
var aliceSession = new SecretSession();

aliceSession
    .identity(YOUR_IDENTITY_KEYS)
    .handshake(YOUR_HANDSHAKE_KEYS)
    .theirIdentity(OTHER_PARTY_IDENTITY.publicKey)
    .theirHandshake(OTHER_PARTY_HANDSHAKE.publicKey)
    .setRole('initiator')
    .computeMasterKey()
    .then(function () { console.log('ready!'); })
```

`YOUR_IDENTITY_KEYS` should be a NaCl keypair created from TweetNacl, which you should store securely and keep indefinitely.

`YOUR_HANDSHAKE_KEYS` are a temporary key set (commonly called pre-keys) which are used to setup the session. These also need to be stored securely, but can be safely discarded after the session has been setup.

`OTHER_PARTY_IDENTITY` is the other party's identity public key, which ensures the identity of the remote party. This key needs to be obtained in a secure, trusted manner, and held indefinitely. There will be no security at all in the protocol if this key is not obtained safely.

`OTHER_PARTY_HANDSHAKE` is the other party's handshake key, which allows you to setup a new session with the other party. This key also should be obtained securely, but doesn't need strict verification, because if it is not one the other party controls, the handshake will fail *AS LONG AS THEIR IDENTITY KEY IS TRUSTED.* If the identity key is compromised, another party could easily perform a man-in-the-middle attack.

In order for the receiver to start communicating, the initiator must first send their handshake public key to the receiving party, as well as inform them of which of the receiver's public handshake keys they used to setup the session so that the reciever will pick the right handshake key pair.

```javascript
var bobSession = new SecretSession();

bobSession
    .identity(YOUR_IDENTITY_KEYS)
    .handshake(YOUR_HANDSHAKE_KEYS)
    .theirIdentity(OTHER_PARTY_IDENTITY.publicKey)
    .theirHandshake(OTHER_PARTY_HANDSHAKE.publicKey)
    .setRole('receiver')
    .computeMasterKey()
    .then(function () { console.log('ready!'); })
```

If everything is done correctly, you will now be able to exchange messages using the `encrypt()` and `decrypt()` methods.

Example:

```javascript
aliceSession.encrypt('Hello Bob!').then(function (encryptedMessage) {
	bobSession.decrypt(encryptedMessage).then(function (result) {
		// result.cleartext should equal "Hello Bob!"
	})
})
```

That's it! Easy, right? 

If you'd like to be able to resume these sessions at a later time, simply pass a storage function to the session:

```javascript
aliceSession.storage(function (data, callback) {
	// Note that the session object is highly sensitive, and should be encrypted! Not stored in plaintext like we are doing here.
	localStorage['session'] = JSON.stringify(data)
	
	// Callback on success.
	callback()
})
```

Then, when you'd like to resume a session, you can simply setup a new session and call resume() on it with the data you saved:

```javascript
aliceSession = new SecretSession().resume(JSON.parse(localStorage['session']))
```

It bears repeating: *The session object is highly sensitive! Do not save it to disk or other locations without first encrypting it using another method.*

