#!/usr/bin/python

#IMPORT
import sys, argparse, ConfigParser, time, twitter, signal
from cryptography.fernet import Fernet

   #
   # #CONSTS
   # key="UdU9JhVqFz2QtygmODnUM8XU56WV3TBq3i-QsGy1dR4="
   # inputfile="input.txt"
   # blocksize=47
   # offset=0
   # screenflag=0
   #
   #
   # #start encrypt
   # cryptomachine = Fernet(key)
   # with open(inputfile, 'r') as file:
   #    file.seek(blocksize*offset,0)
   #    while True:
   #       token = file.read(blocksize)
   #       if not token: break
   #       encToken = cryptomachine.encrypt(token)
   #       if screenflag:
   #          print encToken
   # file.close()

def signal_handler(signal, frame):
        print('Exiting...')
        exit(0)


def TestConfig(config):
    try:
        option = config.get("Encryption","key")
        option = config.get("Encryption","input")

    except:
        print 'Error in config file'

def RunEncryption(config, args):

    key = config.get("Encryption","key")
    inputfile = config.get("Encryption","input")
    blocksize = config.getint("Encryption","blocksize")
    offset = config.getint("Encryption","offset")


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



def RunDecryption(config):
    print "TODO"

if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)

    #parse arguments
    parser = argparse.ArgumentParser(description='Crytoradio script.')
    parser.add_argument('config_file', help='Config file')
    parser.add_argument('-v',"--verbose", help="increase output verbosity",
                        action="store_true")

    args = parser.parse_args()

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
