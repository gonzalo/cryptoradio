#!/usr/bin/python

#IMPORT
import sys, getopt
from cryptography.fernet import Fernet

def main(argv):
   #CONSTS
   key="UdU9JhVqFz2QtygmODnUM8XU56WV3TBq3i-QsGy1dR4="
   inputfile="input.txt"
   blocksize=47
   offset=0
   screenflag=0

   try:
      opts, args = getopt.getopt(argv,"hsi:k:",["ifile=","key="])
   except getopt.GetoptError:
      print 'cryptoradio.py -i <inputfile>'
      sys.exit(2)
   for opt, arg in opts:
      if opt == '-h':
         print 'cryptoradio.py [-k encryption_key] [-s] -i <inputfile>'
         sys.exit()
      elif opt in ("-i", "--ifile"):
         inputfile = arg
      elif opt in ("-k", "--key"):
         key = arg
      elif opt in ("-s", "--screen"):
         screenflag = 1

   #start encrypt
   cryptomachine = Fernet(key)
   with open(inputfile, 'r') as file:
      file.seek(blocksize*offset,0)
      while True:
         token = file.read(blocksize)
         if not token: break
         encToken = cryptomachine.encrypt(token)
         if screenflag:
            print encToken
   file.close()

if __name__ == "__main__":
   main(sys.argv[1:])
