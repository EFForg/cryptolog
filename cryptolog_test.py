#!/usr/bin/env python

import unittest
import cryptolog
import os
import re

TMP_TEST_OUTPUT_FILE = 'testdata/testoutput.txt'
TEST_SALT_FILE = 'testdata/testsaltfile'
SIMPLE_REGEX = re.compile(r'(?P<IP>\d\d?\d?\.\d\d?\d?\.\d\d?\d?\.\d\d?\d?) (?P<OTHER>.*)')
TEST_LOG_ENTRY = """127.0.0.1 - - [06/Apr/2011:00:00:00 -0700] "GET /br/br.gif HTTP/1.1" 301 249 - -"""

class TestCryptoFilter(unittest.TestCase):


    def setUp(self):
        self.cryptofilter = cryptolog.CryptoFilter()
        self.cryptofilter.SetSaltfile(TEST_SALT_FILE)

    def tearDown(self):
        self.cryptofilter.Reset()
        if os.path.isfile(TMP_TEST_OUTPUT_FILE):
            os.remove(TMP_TEST_OUTPUT_FILE)
        self.cryptofilter = None
        
    def testCryptifyOnlyIp(self):
        self.cryptofilter.SetFields(['IP'], [])
        self.cryptofilter.SetRegex(SIMPLE_REGEX)
        res = self.cryptofilter.EncryptSingleLogEntry(TEST_LOG_ENTRY)
        self.assertEqual(res[:6], "EF9k26")
        self.assertEqual(len(res), 78)


if __name__ == '__main__':
    unittest.main()
