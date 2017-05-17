#!/usr/bin/python

#IMPORT
import sys, argparse, ConfigParser, time, twitter, signal, base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

def signal_handler(signal, frame):
    sys.stderr.write('Exiting...\n')
    exit(0)

def get_key(password):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(password)
    return base64.urlsafe_b64encode(digest.finalize())

def TestConfig(config):
    try:
        option = config.get("Encryption","password")
        option = config.get("Encryption","input")
        option = config.get("Encryption","mode")

    except:
        print 'Error in config file'
        exit(1)

def RunEncryption(config, args):

    key = get_key(config.get("Encryption","password"))
    inputfile = config.get("Encryption","input")
    blocksize = config.getint("Encryption","blocksize")
    offset = config.getint("Encryption","offset")
    interval = 1

    twitter_flag = False
    if config.getboolean("Twitter","send_to_twitter"):
        twitter_flag = True
        interval = config.getint("Twitter","interval")
        twitter_api = twitter.Api(
                      consumer_key=config.get("Twitter","consumer_key"),
                      consumer_secret=config.get("Twitter","consumer_secret"),
                      access_token_key=config.get("Twitter","access_token_key"),
                      access_token_secret=config.get("Twitter","access_token_secret"),
                      sleep_on_rate_limit=True)

    cryptomachine = Fernet(key)

    with open(inputfile, 'r') as file:
        file.seek(blocksize*offset,0)
        while True:
            token = file.read(blocksize)
            if not token: break
            encToken = cryptomachine.encrypt(token)
            if args.verbose:
                print encToken
            if twitter_flag:
                try:
                    twitter_api.PostUpdate(encToken)
                except twitter.error:
                    print "Unable to post to twitter"
                    exit(1)

            time.sleep(interval)



def RunDecryption(config,args):
    key = get_key(config.get("Encryption","password"))
    inputfile = config.get("Encryption","input")

    cryptomachine = Fernet(key)

    with open(inputfile, 'r') as file:
        while True:
            token = file.readline()
            if not token: break
            try:
                decToken = cryptomachine.decrypt(token)
            except:
                print "Invalid input"
                exit(1)
            sys.stdout.write(decToken)
    print

if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)

    #parse arguments
    parser = argparse.ArgumentParser(description='Crytoradio script.')
    parser.add_argument('config_file', help='Config file')
    parser.add_argument('-v',"--verbose", help="increase output verbosity",
                        action="store_true")
    parser.add_argument("--generate_key",
                        help="Generate encryption/decryption key",
                        action="store_true")

    args = parser.parse_args()

    if args.generate_key:
        generate_key()

    config = ConfigParser.ConfigParser()
    if config.read(args.config_file):
        TestConfig(config);
        if config.get("Encryption","mode") == "encrypt":
            RunEncryption(config,args)
        elif config.get("Encryption","mode") == "decrypt":
            RunDecryption(config,args)
        else:
            print "Unexpected mode of operation. Check config file"
            exit(1)

    else:
        print 'Config file "' + args.config_file + '" not found';
        exit(1);
