CRYPTORADIO
===========

Python script to encrypt and publish on Twitter. Also decrypt tweets

### Needs

 * Python 2.7 and over
 * Python cryptography module: pip install cryptography
 * Python twitter module: pip install python-twitter



### Release Notes

#### 170517 - First functional version
   * Takes an input file, divides it in blocks, encrypts each block using the specified password and send them to a twitter account and/or print them on screen
   * Takes an input file decrypting each line using specified password and printing them on to screen
   * Takes all options from config file

### Future featurers
 * Improved command line options
 * Decrypt directly from user timeline -> "cryptoradio -d @user"
