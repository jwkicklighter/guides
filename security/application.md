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
password, _per se_; the attacker needs to know a string which will generate the
desired hash. This is known as a collision attack.

A possible attack on a hashing algorithm is called a rainbow table: a giant
list of every possible string and its resulting hash. Similarly, given a hash,
run through every possible string, hashing each one, until you find a match.

These attacks have been on the rise since the early 1990s, making typical
secure hashing functions inappropriate for passwords.

The first solution is to use a salt: generate a random number, add that to the
user's password, and hash _that_ string. Store the salt alongside the hashed
password; each user gets their own salt.

Salts destroy rainbow tables and cause headaches for hashing each string one at
a time. But not enough of a headache: GPUs are at a point now where they can
run secure hashing functions quickly. Too quickly.

The solution is to use a key derivation algorithm. These are much like normal
hashing algorithms, except they are intentionally slow. (They're actually
different, but they serve the same purpose.)

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
that most of the hash was right. Knowing how much of the hash was wrong allows
the attacker to narrow the attack space.

The solution: use a constant time equality check for comparing the hashed
values. Bcrypt libraries ship with a function that does everything for you.
ActiveSupport ships with `secure_compare` for constant-time comparisons. Worst
case: pad the string to a fixed length, make sure your loop goes through every
character even after you know the answer.

---

## TODO

- symmetric vs. asymmetric encryption
  - SSH, TLS, PGP
    - fingerprint verification
    - signing files
  - AES
- hashing vs encryption
  - encrypt, then hash
    - so we can know whether the file is valid before we work on it
- TLS
  - HTTPS
    - HSTS
    - protocol-relative URLs
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


## Interesting links

- https://net.cs.uni-bonn.de/fileadmin/user_upload/naiakshi/Naiakshina_Password_Study.pdf
- https://snyk.io/blog/top-ten-most-popular-docker-images-each-contain-at-least-30-vulnerabilities/
- https://twitter.com/SarahJamieLewis/status/1097300029016989696
