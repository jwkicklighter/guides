# The thoughtbot Guide to Application Security

## Threat modeling

The task of identifying concrete attacks and understanding their relationship
with the code is the core task of threat modeling. We can understand this from
two perspectives:

- identify what can go wrong, and
- don't account for things that cannot go wrong.

Identifying what can go wrong is what is most often [written about when
discussing threat](https://www.owasp.org/index.php/Application_Threat_Modeling)
modeling. There are [many
techniques](https://insights.sei.cmu.edu/sei_blog/2018/12/threat-modeling-12-available-methods.html),
but the summary is:

1. Figure out what an attacker can do on your app. For a Web app, they might be
   able to spoof HTTP headers, submit malicious data, or embed a Web page in an
   `iframe`.
2. Identify the weak points of the app. These will likely be places where you
   are doing something non-standard, which the frameworks don't know how to
   protect.
3. Prioritize these. Take into account factors such as difficulty of attack,
   likelihood of attack, ease of mitigating the attack, and severity of attack.

Anything not in the list are things you cannot use as a reason to do something.
Since the list is prioritized, you can use it to help it to prioritize tickets
or split tickets.

## Library updates

The easiest line of defense we have as a developer is applying security fixes
for our dependencies as they are released.

On the flip perspective, when releasing a security fix for one of our projects,
make it trivial to upgrade: don't include new features or unrelated bug fixes,
if possible.

There are a few ways to keep up with security fixes:

- Any playform-specific tool, such as
  [bundler-audit](https://github.com/rubysec/bundler-audit#readme).
- The [#security](https://thoughtbot.slack.com/messages/security) channel.
- [Any official CVE feed](https://cve.mitre.org/cve/data_updates.html).

## User data

Any data from the user is malicious until proven innocent. Examples of user
input are data from forms, HTTP headers, keyboard-entered input into an Android
app, IP address, MAC address, email headers, file paths, GraphQL queries,
uploaded files, and stdin. And more.

When possible, rely on a framework to parse the user data. Don't parse HTTP
headers by hand, use the Rails validations, pass JSON data through a schema
validator, send addresses straight to the shipping or map API, etc.

If you can't rely on a library, handle user data in two stages: verify, then
work with it. For example, if someone uploads a file with a filename ending in
`.jpg`, use libmagic to confirm that it is a JPEG, and then consider it less
tainted and ready for use.

### SQL injection

We know about this one, so let's make sure it does not happen.

Whenever you run a SQL query, don't insert user input into it. If you must
insert user data into it, use a [bind
variable](https://www.ibm.com/developerworks/library/se-bindvariables/index.html).
(The details of how bind variables work depends on your ORM.)

### YAML

[YAML is too vulnerable to
attacks](https://trailofbits.github.io/rubysec/yaml/index.html) to consider for
new projects.

### Client-side validation

All client-side validation, such as a React component that tells the user that
their email address is not in a valid format, is for presentation. These
checks, and more, must be duplicated on the backend. Any attacker can use curl
to bypass your client-side validations.

## Randomization

Most modern cryptography is dependant on really big prime numbers and access to
solid randomization. If you find yourself in a place where you need a random
number, here are some things to keep in mind.

- Do not restrict the randomized space with a modulo or floating-point
  multiplication [bias](http://www.pcg-random.org/posts/bounded-rands.html).
  Instead, try generating a random number in a loop, returning when the value
  is within the desired range.
- Use an unpredictable seed. Do not use the current time, or the seconds since
  boot, or `0`, or your age, or the result from calling rand seeded on
  a predictable seed. If possible, use a random number generator that you do
  not seed yourself, such as `arc4random(4)` or `/dev/random`.
- Use a non-blocking random number generator. If an attacker discovers that the
  random number generator blocks, such as Linux's `/dev/urandom`, that is
  a potential denial of service attack vector.
- Don't do this yourself. If you can use Ruby's `SecureRandom` or functions
  like `arc4random_buf(3)` and `arc4random_uniform(3)`, do that instead.

## Hashing

A hashing function provides a one-way encoding of an object. Use this any time
we don't actually care what the value _is_, but instead we care that we have it
at all. The only operation you'll want to perform against a hashed object is an
equality check.

(As a side note, when people refer to dictionary data structures as "hashes",
they're referring to the fact that a hashing function is used to turn the key
into a unique number.)

(As a second side note, when people refer to blockchains as "cryptocurrency",
they're making reference to the fact that they used a hashing function. Twice.)

Hashing algorithms are as strong as their ability to generate a unique,
one-direction hash. When someone finds a way to generate the same hash for two
different inputs, the hashing function is considered insecure. The American
National Institute of Standards and Technology (NIST) maintains [a list of
approved hash algorithms](https://csrc.nist.gov/Projects/Hash-Functions); as of
this writing they recommend a SHA-3 algorithm.

Note that base64 encoding is not a hashing function, since it intentionally can
be decoded.

Use an approved secure hashing alorithm to verify that something has not been
tampered with. Some examples of that are tarballs (both ones you download and
also ones you provide to other devs -- always send a hash of the file so the
downloader can confirm the file before opening it) and API request bodies.

A fun example is to make a "precommit" statement among friends: create
a sentence predicting an outcome, then share the hash of the sentence. When the
outcome comes true, share the original text.

### Passwords

Note that for passwords, the attacker does not need to know the user's
password _per se_; the attacker needs to know a string which will generate the
desired hash. This is known as a collision attack.

A rainbow table attack is done with a rainbow table: a giant list of every
possible string and its resulting hash. Using such a list, the attacker can
quickly look up the password given a hash.

A similar attack is to, given one hash, run through every possible string,
hashing each one, until you find a match.

Rainbow table-style attacks have been on the rise since the early 1990s, making
typical secure hashing functions inappropriate for passwords.

The first solution is to use a salt: generate a random number, add that to the
user's password, and hash _that_ string. Store the salt alongside the hashed
password; each user gets their own salt.

Salts destroy rainbow tables and cause headaches for hashing each string one at
a time. But not enough of a headache: GPUs are at a point now where they can
run secure hashing functions quickly. Too quickly.

The solution is to use a key derivation algorithm. These are much like normal
hashing algorithms (they're actually quite different, but that difference is
negligible), except they are intentionally slow.

The three most common password hashing algorithms are bcrypt, scrypt, and
PBKDF2. Each of these require a salt, but handle it themselves: the output of
these functions is a string that contains the salt plus the hashed value. Store
that entire string as the hashed password.

Never compare hashed passwords using the built-in string equality function;
this sets you up for a timing attack.

### Timing attacks

An attacker can learn a lot from _how long_ it takes to be denied access. If
it's instant, that means the input didn't even pass validation; if it's kinda
long, that means that the input got past validation and computed a hash but one
of the first few characters of the hash were incorrect; a longer delay means
that most of the hash was right. Knowing how much of the hash was right allows
the attacker to narrow the attack space.

The solution: use a constant-time equality check for comparing the hashed
values. Bcrypt libraries ship with a function that does everything for you.
ActiveSupport ships with `secure_compare` for constant-time comparisons. Worst
case: pad the string to a fixed length then make sure your loop goes through
every character even after you know the answer.

## Encryption

An encryption algorithm is one where a string can be made illegible and then
returned back to the original string again, and where decrypting requires an
out-of-band secret.

Less abstractly: a string can be encrypted, and then to decrypt you must know
the password.

There are two kinds of encryption algorithms: symmetric and asymmetric.
A symmetric algorithm is one where the same secret is used to encrypt it and
decrypt it. An asymmetric algorithm is one where the string can be encrypted
and decrypted using different secrets -- where the person encrypting cannot
necessarily decrypt it.

The most popular symmetric algorithms you'll encounter are AES and Twofish.
These might be useful for encrypting a file to share with a group of people or
for encrypting your filesystem. Rumor has it that 1Password uses something like
it AES to encrypt an entire vault; it is encrypted at rest, and only decrypted
when you enter the passphrase.

Asymmetric encryption algorithms, also known as public/private keypair
encryption, is more well-known -- in large part for how tricky they are to get
right. Some famous ones are SSH, TLS (previously SSL), and PGP.  These start by
generated a pair of encryption secrets known as the public and private keys.
Anyone with the public key can encrypt a string, but only the holder of the
private key can decrypt.

(The math here is cool. I won't go into it.)

In order for any of this to work, you need to get your hands on a confirmed
public key. Each public key has a fingerprint -- an abbreviated and
easily-confirmable portion of the entire secret. How this works in practice
depends on the protocol.

### SSH

SSH defaults to a trust-on-first-use (TOFU) policy: the first time you connect
to a server you are asked to confirm the server's public key fingerprint:

```
The authenticity of host heroku.com can't be established.
RSA key fingerprint is 8tF0wX2WquK45aGKs/Bh1dKmBXH08vxUe0VCJJWOA/o.
Are you sure you want to continue connecting (yes/no)?  ```

The server admin will need to tell you out of band whether that is the correct
fingerprint ([Heroku publishes their fingerprint
online](https://devcenter.heroku.com/articles/git-repository-ssh-fingerprints)).

### PGP

OpenPGP is a way for users to trust each other; therefore, fingerprint
verification happens in person, often in a [keysigning
party](http://mdcc.cx/gnupg/ksp_intro.en.html). People will exchange the
fingerprint of their PGP key face-to-face, often written on paper, and then
later will confirm that the key they have for the person matches the
fingerprint on the paper.

This mechanism is called a web of trust.

### TLS

Transport Layer Security is a way for a browser to trust a server. The browser
ships with a list of trusted public keys. Each Web site serves up its own
public key, plus a signature from another key. If the signature is by one of
the trusted public keys, the browser accepts the Web site's key; otherwise,
it's a failure.

For example, Firefox trusts GlobalSign. thoughtbot.com has a TLS certificate
that was signed by GlobalSign. When you visit thoughtbot.com, it sends its
public key plus the signature from GlobalSign. Firefox trusts GlobalSign, so it
trusts thoughtbot.com's key.

This mechanism is called a central authority.

### Signing

An asymmetric encryption algorithm can be run in reverse to provide for
signing. In this, a private key is used to sign a string, producing a signature
string. The public key can be used to verify the string against the signature.

This is useful for central authorities, as used by TLS, but also useful for
sharing files. You can provide the tarball and the signature, and anyone with
your public key can verify that the tarball was created by you (or, at least,
anyone with your private key). The Debian package system is built around this.

## Encrypting and hashing

Encryption (PGP, AES) is different from hashing (SHA-256, bcrypt, etc.),
because it can be reversed, and this is different from encoding (base64,
base58, etc.) because reversing it requires a password.

It can be handy to combine these technologies:

- Encrypt and hash. The recipient can confirm that they have the right string
  by checking the hash before even attempting to decrypt it. This might save
  them from attempting to decrypt a malicious string.
- Hash and encode. This can be handy for when you need to triple-check that
  a JSON payload made it through safely: hash the JSON, then base64 the hash,
  which encodes it into ASCII, making it safer to send across HTTP.

## TLS

[Transport Layer Security (TLS) is a general-purpose
mechanism](http://rebecca.meritz.com/ggm15/) for confirming the integrity,
confidentiality, and authenticity of data sent over TCP. It combines symmetric
encryption, asymmetric encryption, and hashing functions to transmit data
securely and efficiently.

It does _not_ guarantee that the domain owner is trustworthy. TLS does not
relate to trust. It can only guarantee that the information is sent, untampered
and privately, only to the recipient you are sending it to. It does not
guarantee that you are sending it to the right recipient.

There are two kinds of certificates signed by central authorities: domain
verification and extended verification. Domain verification does what it says
on the tin: it confirms that the holder of the private key is also in control
of the domain name. Extended verification goes further and cannot be automated:
it confirms that the holder of the private key controls the domain name and is
the person or company they claim to be.

Extended verification does not guarantee that the holder of the private key is
trustworthy.

We mostly related to TLS via HTTPS, but it can be used for any TCP connection,
such as email.

The first version of TLS was named Secure Sockets Layer (SSL); at the end of
the last century, SSL was found to be trivially vulnerable and has not been
intentionally used since.

### HSTS

The most common attack vector for a secure protocol is a downgrade attack. Many
protocols have a backward compatibility mechanism that allows the client and
server to negotiate which version of a protocol they both understand.
Convincing the server to downgrade to a version of a protocol with a known bug
is a downgrade attack.

The worst case is when you can convince the server to drop the security
entirely. This is possible with HTTPS with a standard man-in-the-middle attack
of the _unencrypted_ HTTP connection.

It works like this:

1. User visits `thoughtbot.com`.
2. Web browser turns this into `http://thoughtbot.com/`.
3. An eavesdropper intercepts the connection and redirects to their own server,
   secured using TLS, but entirely under their control.

The problem is step (2). The current solution is HTTP Strict Transport Security
(HSTS). Under HSTS, the browser knows about domain names that should always be
HTTPS. It literally has a list. If you enter `thoughtbot.com` into the URL bar,
it will check its list, find `thoughtbot.com` in there, and complete the full
URL as `https://thoughtbot.com/`.

Web sites can add themselves to the list by sending the
`Strict-Transport-Security` header. The value for this header is
`max-age=31536000; includeSubDomains; preload`.

- `max-age` determines how long this domain should remain in the browser's
  list. `31536000` is one year. Feel free to go longer.
- `includeSubDomains` specifies that subdomains should also be considered part
  of the HSTS list.
- `preload` tells the browser maintainer that you are comfortable with this
  domain being part of [the list shipped with the
  browser](https://hstspreload.org/).

Unrelated to HSTS but sort of a collorary of how the attack works: specify the
protocol (`https://`) in all your links, if you can.

---

## TODO

- password complexity
- OTP
   - HTOP
   - TOTP
- cookies
   - sign
   - secure
- logging
   - TLS if networked
   - be careful what you log
- PII
   - send CC data directly to processor
   - don't touch it if you can avoid it
   - don't store any more than you need
- check your return values
- HMAC - probably goes under hashing somewhere. mention encrypt-then-hmac later


## Interesting links

- https://net.cs.uni-bonn.de/fileadmin/user_upload/naiakshi/Naiakshina_Password_Study.pdf
- https://snyk.io/blog/top-ten-most-popular-docker-images-each-contain-at-least-30-vulnerabilities/
- https://twitter.com/SarahJamieLewis/status/1097300029016989696
