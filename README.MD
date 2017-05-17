CRYPTORADIO
===========

Python script to encrypt and publish on Twitter. Also decrypt tweets from file

### Needs

 * Python 2.7 and over
 * Python cryptography module: pip install cryptography
 * Python twitter module: pip install python-twitter

### Usage
**Fernet encryption uses same password for encryption and decryption**

```
$ ./cryptoradio.py -h
usage: cryptoradio.py [-h] [-v] config_file

Crytoradio script.

positional arguments:
  config_file    Config file

optional arguments:
  -h, --help     show this help message and exit
  -v, --verbose  Display operations on screen
```

#### Encrypt and publish to twitter
 1. Download script and make it executable ``chmod +x cryptoradio.py``
 1. Install dependencies
 1. Copy .config_sample to .config_enc and edit it: password, inputfile... and twitter tokens if you want
 1. Be sure to set ``mode: encrypt``
 1. Run encryption with ``./cryptoradio.py .config_enc``

#### Decrypt messages
 1. Copy all tweets to a file (one per line)
 1. Copy .config_enc to .config_dec and edit it.
 1. Be sure to set ``mode: decrypt``
 1. Run encryption with ``./cryptoradio.py .config_dec``

#### Security advices
**Protect your .config_enc and .config_dec files!!! They both store password**

``$chmod 600 .config_enc .config_dec``


### Release Notes

#### 170517 - First functional version
   * Takes an input file, divides it in blocks, encrypts each block using the specified password and send them to a twitter account and/or print them on screen
   * Takes an input file decrypting each line using specified password and printing them on to screen
   * Takes all options from config file

### Future featurers
 * Improved command line options
 * Decrypt directly from user timeline -> "cryptoradio -d @user"
 * Install as a service
