#!/usr/bin/env python

from sys import stdin, stdout, stderr, argv as arguments
from os import urandom, stat
from time import localtime, time
from syslog import syslog, LOG_CRIT
from base64 import b64encode as encode
from hmac import HMAC as hash
from argparse import ArgumentParser
from subprocess import Popen, PIPE
import re

salt_size = 16
one_day = 60 * 60 * 24
entities_to_hashed_sizes = {
  'IP': 6,
  'UA': 22,
  'TIMESTAMP': 22,
  'TARGET_URL': 6,
  }

def salt(salt_filename):
  try:
    cur_time = localtime()
    cur_day = (cur_time.tm_year, cur_time.tm_yday)
    salt_time = localtime(stat(salt_filename).st_mtime)
    salt_day = (salt_time.tm_year, salt_time.tm_yday)
    if cur_day != salt_day:
      return new_salt()
    return file(salt_filename, "rb").read(16)
  except Exception, e:
    try:
      return new_salt(salt_filename)
    except Exception, ee:
      syslog(LOG_CRIT, str(ee))
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
    syslog(LOG_CRIT, str(e))

def hash_entity(ip, salt_filename, hashed_size):
  return encode(hash(salt(salt_filename), ip).digest())[:hashed_size]


class LogParseError(Exception):
  pass


class UninitializedCryptoFilter(Exception):
  pass


class CryptoFilter(object):
  """Class to control cryptographic logging."""
  
  def __init__(self, regex=None, field_list=None, salt_filename=None):
    """
    Args:
      regex: re.compile(r'(?P<A>)(?P<B>)) object, with
        named groups
      field_list: what to encrypt that matches named groups
        above, e.g. ["IP", "UA"]
      salt_filename: where the salt is stored that we're using
    """
    if regex:
      self.SetRegex(regex)
    if field_list:
      self.SetFields(field_list)
    if salt_filename:
      self.SetSaltfile(salt_filename)

  def SetRegex(self, regex):
    self._regex = regex

  def SetFields(self, field_list):
    self._field_list = field_list
  
  def SetSaltfile(self, salt_filename):
    self._salt_filename = salt_filename

  def IsInitialized(self):
    return self._regex and self._field_list and self._salt_filename
  
  def Reset(self):
    self._regex = None
    self._field_list = None
    self._salt_filename = None

  def EncryptSingleLogEntry(self, log_entry):
    """From self.regex, picks out relevant fields from 
    self._field_list and replaces them with crypt hashes.

    Args:
      log_entry
    Returns:
      crypto_log_entry
    """
    # Make sure we are initialized
    if not self.IsInitialized():
      raise UninitializedCryptoFilter("Not initialized")
    results = self._regex.search(log_entry)
    if not results:
      raise LogParseError("Log format does not match regex.")
    split_log = list(results.groups())
    # TODO(dtauerbach): this is inefficient but regex
    # doesn't seem quite powerful enough to avoid it
    # by being able to bulk replace named groups.
    # (the concern is if one group is just, say "a",
    # then the find-and-replace operation can't just replace
    # the relevant instance of "a" in the named group)
    # measure then optimize if necessary
    for field in self._field_list:
      # TODO(dtauerbach): below might fail if you pass in
      # an entity to be hashed that isn't in the spec.
      # deal with this
      res = results.group(field)
      if not res:
          # TODO(dtauerbach): Figure out the convention here
          # probably a warning is all that we want since fields
          # could legitimately be empty
        continue
      split_log[split_log.index(res)] = self.EncryptField(res, 6)
    return '%s\n' % (''.join(split_log))

  def EncryptField(self, field, hashed_size):
    """Encrypt relevant field (e.g. IP) using salted hash."""
    return hash_entity(field, self._salt_filename, 6)


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
  parser.add_argument('-e',
      dest='entities',
      default='IP',
      help='comma-separated list of entities to filter')
  args = parser.parse_args()

  log_file = None
  if(args.write != None):
    log_file = file(args.write, 'ab')

  p = None
  if(args.command != None):
    p = Popen(args.command, stdin=PIPE, shell=True)

  entities = args.entities.split(',')

  regex = re.compile(r'(?P<IP>\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?)( )(?P<OTHER>.*)')
  cryptor = CryptoFilter(regex, entities, args.salt)

  log = stdin.readline()
  while(log):
    crypted_log = cryptor.EncryptSingleLogEntry(log)
    if(log_file != None):
      log_file.write(crypted_log)
      log_file.flush()

    if(p != None):
      p.stdin.write(crypted_log)
      p.stdin.flush()

    log = stdin.readline()

  if(log_file != None):
    log_file.close()

  if(p != None):
    p.stdin.close()
    p.wait()


