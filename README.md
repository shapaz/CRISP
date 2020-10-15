# CRISP & CHIP
A C++ implementation of the [CRISP and CHIP protocols](https://ia.cr/2020/529).

## Theoretical Background
*Identity-based PAKE (iPAKE)* is a new notion of security for Password Authenticated Key Exchange (PAKE) protocols. It extends the benefits of Asymmetric/Augmented PAKE (aPAKE) to both parties in the symmetric settings. While aPAKE only protects the password against **server** compromise, iPAKE protects it against compromise of **any party**. This means that both parties store a password file, containing is a one-way function of the password. When a party is compromised, the attacker can only mount a brute-force attack to recover the password.
iPAKE also prevents impersonation, by tying identities to password files. A stolen password file allows impersonation of none but the compromised party from which it was stolen.
CHIP is an iPAKE protocol based on combining [Identity-Based Key-Agreement (IB-KA)](http://www.dariofiore.it/wp-content/uploads/ib-ka-journal-final.pdf) with a symmetric PAKE.

*Strong Identity-based PAKE (siPAKE)* notion adds pre-computation resilience to the password file, similar to Strong aPAKE (saPAKE). This means that a brute force attack against a compromsied password file cannot be started before the file is stolen. This is not the case for aPAKE and iPAKE: an attacker might pre-compute a reverse lookup table in advance, so a password can be recovered instantly upon compromise. Pre-computation resilience is achieved by combining random salts into password files. The main challenge of siPAKE is to agree on a shared key between parties with independent salts.
CRISP is a siPAKE protocol based on Bilinear Groups with Hash-to-Group combined with a symmetric PAKE.

## Dependent Libraries
Both CHIP and CRISP require a symmetric PAKE protocol. This implementation uses [cPace](https://tches.iacr.org/index.php/TCHES/article/view/7384/6556) which is a very efficient PAKE and a leading candidate on IETF's [PAKE selection Process](https://github.com/cfrg/pake-selection). Our cPace implementation was inspired by https://github.com/jedisct1/cpace.

We use [libsodium](https://github.com/jedisct1/libsodium) for most cryptographic primitives: SHA-256 for hashing, Argon2id for password file generation and Ristretto255 for group operations.

For Bilinear Group we support both [MCL](https://github.com/herumi/mcl) and [PBC](https://crypto.stanford.edu/pbc/) libraries, preferably the former.

## Usage
Clone and build the code using:
```bash
git clone https://github.com/shapaz/CRISP.git
./depinstall.sh		# Only if you don't have libsodium and MCL
make -j
```

If you have PBC installed and wish to build using it instead of MCL (default), run:
```bash
make -j PAIRING_LIB=PBC
```

The following code snippets show how to run CRISP. To run CHIP instead, simply replace the string "CRISP" with "CHIP" wherever applicable.

### Generating Password Files
```bash
CRISP/gen_pwd_file MyNetwork 'Pa$$Word' Alice > alice.pwd
CRISP/gen_pwd_file MyNetwork 'Pa$$Word' Bob   > bob.pwd
CRISP/gen_pwd_file MyNetwork 'WrOnGPwD' Carol > carol.pwd
```

### Single Local Run
To run the protocol between processes on the same device using local loopback interface:
```bash
CRISP/key_exchange alice.pwd &
CRISP/key_exchange bob.pwd
```
The output shows CPU-time vs. real time for different stages of the protocol.
You might observe different CPU times on different machines.

You can also see what happens when the password files were created using different passwords:
```bash
CRISP/key_exchange alice.pwd &
CRISP/key_exchange carol.pwd
```

### Single Remote Run
The protocol can connect to a remote peer using UDP/IP.
We use UDP hole punching to overcome NAT and firewall obstacles.

On device A run:
```bash
CRISP/key_exchange alice.pwd <B-IP-address> <common-port>
```
On device B run:
```bash
CRISP/key_exchange bob.pwd <A-IP-address> <common-port>
```

You might observe different real times when exchanging messages. Some of these might be due to a fast machine finishing its computation and waiting for response from a slow machine, which is still computing the previous stage. Packet loss might cause the test to hang or fail.

### Repeated Local Runs
The utility `test.py` runs a series of protocols using the same password files, and outputs the median timings for each stage.
It assumes the existance of password files `alice.pwd` and `bob.pwd` inside the protocol sub-directory.
Use `make crisp` or `make chip` to create the password files and run `test.py` with the default number of iterations.
Use `make test` to run both CRISP and CHIP tests.
If you wish to parameterize the utility yourself, run:
```bash
./test.py CRISP --count 1000
```

### Repeated Remote Runs
The `test.py` utility can be run across different devices.

On device A run:
```bash
./test.py CRISP --count 1000 -ip <B-IP-address>
```

On device B run:
```bash
./test.py CRISP --count 1000 -ip <A-IP-address>
```

Sometimes the utility hangs due to unrecoverable packet loss. In this case, interrupt the device waiting in lower iteration number using Ctrl+C and enter "N" to skip to the next iteration. The test should proceed.