#!/usr/bin/env python

from sys import stdin
from os import urandom
from time import localtime
from types import NoneType
from syslog import syslog, LOG_CRIT
from base64 import b64encode
from hmac import HMAC
from argparse import ArgumentParser
from subprocess import Popen, PIPE
import re

salt_data = None
salt_day = None
salt_size = 16

entities_to_hashed_sizes = {
  'IP': 6,
  'UA': 22,
  'TIMESTAMP': 22,
  'TARGET_URL': 6,
}

def salt():
  global salt_data, salt_day, salt_size

  t = localtime()
  now = (t.tm_year, t.tm_yday)
  if salt_day != now:
    salt_data = urandom(salt_size)
    salt_day = now
  return salt_data

def hash_entity(entity, hashed_size, salt_param=None):
    salt_var = salt_param or salt()
    return b64encode(HMAC(salt_var, entity).digest())[:hashed_size]

class LogParseError(Exception):
  pass


class UninitializedCryptoFilter(Exception):
  pass


class CryptoFilter(object):
  """Class to control cryptographic logging."""
  
  def __init__(self, regex=None, field_list=None, delete_list=None):
    """
    Args:
      regex: re.compile(r'(?P<A>)(?P<B>)) object, with
        named groups
      field_list: what to encrypt that matches named groups
        above, e.g. ["IP", "UA"]
    """
    self._salt = None
    if regex:
      self.SetRegex(regex)
    if field_list:
      self.SetFields(field_list, delete_list)

  def SetRegex(self, regex):
    self._regex = regex
    # get a list of named groups from the regex, in order
    self._named = map(lambda x: x[0], sorted(self._regex.groupindex.items(), key=lambda x: x[1]))

  def SetFields(self, field_list, delete_list):
    self._field_list = field_list
    self._delete_list = delete_list
  
  def IsInitialized(self):
    return self._regex and self._field_list
  
  def Reset(self):
    self._regex = None
    self._named = None
    self._field_list = None

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
    print self._regex.groupindex.items()

    # create a list of matches based on named gropus, preserving order
    results_dict = results.groupdict()
    split_log = map(lambda x: results_dict[x], self._named)

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
    for field in self._delete_list:
      res = results.group(field)
      split_log[split_log.index(res)] = '-'
    split_log = filter(lambda x: type(x) != NoneType, split_log)
    return '%s\n' % (' '.join(split_log))

  def SetSaltfile(self, salt_file):
    self._salt = open(salt_file, 'r').read()

  def EncryptField(self, field, hashed_size):
    """Encrypt relevant field (e.g. IP) using salted hash."""
    return hash_entity(field, 6, self._salt)


if __name__ == "__main__":
  parser = ArgumentParser(description='A program to encrypt the IP addresses in web server logs, to be used within an Apache CustomLog line. It assumes that the IP address is the first space-separated field in the log line. Input comes in the form of log lines from stdin.')
  parser.add_argument('-r',
      dest='regex',
      help='file providing regex for log format')
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
  parser.add_argument('-s',
      action='store_true',
      dest='strip_uas_and_refs',
      default=False)
  args = parser.parse_args()

  log_file = None
  if(args.write != None):
    log_file = file(args.write, 'ab')

  p = None
  if(args.command != None):
    p = Popen(args.command, stdin=PIPE, shell=True)

  entities = args.entities.split(',')
  ipv6_exp = '([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]{1,}|::(ffff(:0{1,4}){0,1}:){0,1}((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])\.){3,3}(25[0-5]|(2[0-4]|1{0,1}[0-9]){0,1}[0-9])'
  ipv4_exp = '\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?'
  if args.regex:
    with open(args.regex, 'r') as regex_file:
      expression = regex_file.read().replace('*IPV6*', ipv6_exp).replace('*IPV4*', ipv4_exp)
      regex = re.compile(expression)
  else:
    regex = re.compile(r'(?P<IP>'+ipv4_exp+'|'+ipv6_exp+')( )(?P<OTHER>.*)')

  # todo:dta improve this regex for common log format
  apache_regex = re.compile(r'(?P<IP>'+ipv4_exp+'|'+ipv6_exp+') (?P<SAVE1>-) (?P<SAVE2>-) (?P<DATETIME>\[.*\]) (?P<REQUEST>".*") (?P<SAVE3>\d*|\-) (?P<SAVE4>\d*|\-) (?P<OTHER>.*)')
  delete_list = []

  # hack for pound logs
  if args.strip_uas_and_refs:
    regex = apache_regex
    delete_list = ['OTHER']

  cryptor = CryptoFilter(regex, entities, delete_list)

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


