#!/usr/bin/env python

from sys import stdin, stdout, stderr, argv as arguments
from os import urandom, stat
from time import time
from syslog import syslog, LOG_CRIT as Critical
from base64 import b64encode as encode
from hmac import HMAC as hash
from argparse import ArgumentParser

salt_size = 16
one_day = 60 * 60 * 24

def salt(salt_filename):
  try:
    if time() > stat(salt_filename).st_mtime + one_day:
      return new_salt()
    return file(salt_filename, "rb").read(16)
  except Exception, e:
    try:
      return new_salt(salt_filename)
    except Exception, ee:
      syslog(Critical, str(ee))
      return urandom(salt_size)

def new_salt(salt_filename):
  try:
    r = urandom(salt_size)
    f = file(salt_filename, "wb")
    f.write(r)
    f.flush()
    f.close()
    return r
  except Exception, e:
    syslog(Critical, str(e))

def hash_ip(ip, salt_filename):
  return encode(hash(salt(salt_filename), ip).digest())[:6]

if __name__ == "__main__":
  parser = ArgumentParser(description='A program to encrypt the IP addresses in web server logs, to be used within an Apache CustomLog line. It assumes that the IP address is the first space-separated field in the log line. Input comes in the form of log lines from stdin.')
  parser.add_argument('-s', 
      dest='salt', 
      default='/tmp/cryptolog_salt', 
      help='filename to store the salt in (default: /tmp/cryptolog_salt)')
  parser.add_argument('-w',
      dest='write', 
      help='filename to write logs to')
  parser.add_argument('-c',
      dest='command', 
      help='pipe logs to this external program')
  args = parser.parse_args()

  try:
    #log_file = None
    #if(args.write != None):
    #  log_file = file(args.write, 'ab')

    line = stdin.readline()
    while(line):
      ip, rest = line.split(" ", 1)
      crypted_log = " ".join(hash_ip(ip, args.salt), rest)

      if(args.write != None):
        f = open(args.write, 'a')
        f.write(crypted_line)
        f.close()
        #log_file.write(crypted_log)

      #if(args.command != None):

      line = stdin.readline()

    #if(log_file != None):
    #  log_file.flush()
    #  log_file.close()
  except Exception, e:
    stderr.write(__doc__)
    syslog(Critical, str(e))

