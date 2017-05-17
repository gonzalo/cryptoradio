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
        option = config.get("General","password")
        option = config.get("General","input")
        mode = config.get("General","mode")

        if mode == "encrypt":
            option = config.getboolean("Encryption","keep_pagination")
            option = config.getint("Encryption","blocksize")
            option = config.getint("Encryption","offset")
            option = config.getint("Encryption","interval")

        if mode == "decrypt":
            option = config.getboolean("Encryption","keep_pagination")
            option = config.getint("Encryption","blocksize")
            option = config.getint("Encryption","offset")
            option = config.getint("Encryption","interval")

        option = config.get("Twitter","send_to_twitter")
        if option:
            option = config.get("Twitter","consumer_key")
            option = config.get("Twitter","consumer_secret")
            option = config.get("Twitter","access_token_key")
            option = config.get("Twitter","access_token_secret")

    except:
        print 'Error in config file'
        exit(1)

def RunEncryption(config, args):

    key = get_key(config.get("General","password"))
    inputfile = config.get("General","input")
    blocksize = config.getint("Encryption","blocksize")
    offset = config.getint("Encryption","offset")
    interval = config.getint("Encryption","interval")

    twitter_flag = False
    if config.getboolean("Twitter","send_to_twitter"):
        twitter_flag = True
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

            offset+=1
            config.set("Encryption","offset", offset)
            with open(args.config_file, 'wb') as configfile:
                config.write(configfile)
                configfile.close()
            time.sleep(interval)



def RunDecryption(config,args):
    key = get_key(config.get("General","password"))
    inputfile = config.get("General","input")

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

    #catch Ctrl + C 
    signal.signal(signal.SIGINT, signal_handler)

    #parse arguments
    parser = argparse.ArgumentParser(description='Crytoradio python script. Encode and post to Twitter')
    parser.add_argument('config_file', help='Config file')
    parser.add_argument('-v',"--verbose", help="Display operations on screen",
                        action="store_true")

    args = parser.parse_args()

    config = ConfigParser.ConfigParser()
    if config.read(args.config_file):
        TestConfig(config);
        if config.get("General","mode") == "encrypt":
            RunEncryption(config,args)
        elif config.get("General","mode") == "decrypt":
            RunDecryption(config,args)
        else:
            print "Unexpected mode of operation. Check config file"
            exit(1)

    else:
        print 'Config file "' + args.config_file + '" not found';
        exit(1);
