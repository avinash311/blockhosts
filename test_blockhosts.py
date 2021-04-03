#!/usr/bin/env python3
# Run like this: python3 -m unittest test_blockhosts

'''
Unit tests for blockhosts.py

Run from current directory, should have blockhosts.py and
blockhosts.cfg files and the test_data/ directory available.
Command:
   python3 blockhosts_tests.py

'''

TEST_BLOCKFILE='test_data/test_hosts.allow'
TEST_LOG_FILE='test_data/test_all.log'

# TEST_CONFIG_FILE='test_data/test_v203.cfg' # failing matches, version 2.0.3
TEST_CONFIG_FILE= './blockhosts.cfg'

SCRIPT_ID='test_blockhosts'
VERSION='0.4.0'
VERSION_DATE='September 2012'
AUTHOR='Avinash Chopde'
AUTHOR_EMAIL='avinash@aczoom.com'
URL='http://www.aczoom.com/blockhosts/'
LICENSE='http://creativecommons.org/licenses/publicdomain/'
DESCRIPTION='test blockhosts.py functionality'
LONG_DESCRIPTION=DESCRIPTION


import unittest
import io
import sys
import re
import traceback
import syslog

import blockhosts
from blockhosts import Log

class TestBlockHosts(unittest.TestCase):

    BH_OBJ = None
    CONFIG = None

    ERRORS_RE = re.compile(r"^(error|warning):", re.IGNORECASE | re.MULTILINE)

    def setUp(self):

        Log.SetPrintLevel(Log.MESSAGE_LEVEL_DEBUG)
        #Log.SetPrintLevel(Log.MESSAGE_LEVEL_INFO)
        #Log.SetPrintLevel(0) # disable all non-error messages

        # reset log archive to empty before each test
        Log.MESSAGE_ARCHIVE = []

        # always recreate BH_OBJ each time for every test, don't
        # reuse old object

        args = ['--quiet', '--configfile=' + TEST_CONFIG_FILE]

        config = blockhosts.Config(args, VERSION, LONG_DESCRIPTION)
        # Load file and all default values for all args.
        config.load_file()
        config.add_section(blockhosts.CommonConfig())
        config.add_section(blockhosts.BlockHostsConfig())
        config.add_section(blockhosts.HostsFiltersConfig())
        config.add_section(blockhosts.MailConfig())
        config.add_section(blockhosts.IPBlockConfig())

        config.parse_args()

        Log.Info('%s %s test run: %s' % (SCRIPT_ID, VERSION, blockhosts.Config.START_TIME_STR))

        bh_obj = blockhosts.BlockHosts(config['blockfile'],
                                       config['blockline_ipv4'], config["blockline_ipv6"])

        TestBlockHosts.CONFIG = config
        TestBlockHosts.BH_OBJ = bh_obj

    def testLogsMatch_IgnoreDups(self):
        self._run_TestLogsMatch(ignore_duplicates=True)

    def testLogsMatch_CountDups(self):
        self._run_TestLogsMatch(ignore_duplicates=False)

    def _run_TestLogsMatch(self, ignore_duplicates):

        # All these IP addresses should be matched, and no others
        table = (
            # Third number is parsed as count of the IP address
            '10.100.1.1', '10.100.1.2', '10.100.1.3', '10.100.1.4',
            '10.100.2.5', '10.100.1.6', '10.100.1.7', '10.100.1.8',
            '10.100.6.9', '10.100.1.10', '10.100.1.11',
            '10.101.1.1', '10.101.1.2', '10.101.1.3', '10.101.1.4',
            '10.101.1.5', '10.101.1.6',
            '10.102.1.1', '10.102.1.3', '10.102.1.4', '10.102.1.5',
            '10.102.1.6', '10.102.1.7', '10.102.1.8',
            '10.103.1.1',
            '10.104.1.1', '10.104.1.2',
            '10.105.1.1',
            '10.106.1.1', '10.106.1.2',
            '10.107.1.1',
            '10.108.1.1', '10.108.1.2', '10.108.1.4', '10.108.1.5',
            '10.108.1.6',
            # IPv6
            'beef:beef:1:dead::3', 'beef:beef:7:dead::a',
            )
        # This IP address has duplicate log statements, and if IGNORE_DUPLICATES
        # is True, it should show up the count actually listed in duplicates:
        duplicates = { '10.100.6.9' : 4, }

        Log.Info(' Test scanning log')

        failed = [] # maintain list of failure messages

        sl = blockhosts.SystemLog(TEST_LOG_FILE)

        offset = blockhosts.SystemLogOffset(0,'') # offset 0, read from start
        sl.open(offset)

        # enable all regexs/rules
        self.BH_OBJ.set_all_reobjs(self.CONFIG["ALL_REGEXS"], ".*", ignore_duplicates)
        # setting IGNORE_DUPLICATES to True, which is different from default.
        # But default is easy, so no need to test for that, test the complicated
        # case instead.  

        while 1:
            line = sl.readline()
            if not line: break

            line = line.strip()
            if not line: continue

            host_entry = self.BH_OBJ.match_line(line)
            if host_entry:
                ip = host_entry[0]
                count = host_entry[1].count
                Log.Debug('  ... checking IP', ip, count)
                if ip not in table:
                    failed.append('** Watched IP %s unexpected, in line:\n   %s' % (ip, line))
            
        sl.close()

        (blocked, watched) = self.BH_OBJ.get_hosts_lists()
        watched_ips = list(watched.keys())
        for ip in table:
            if ip not in watched_ips:
                # check that no required IP address is missing
                failed.append('** Required IP %s not matched in log' % (ip))
            else:
                # check that counts are correct
                count = watched[ip].count
                if ignore_duplicates and ip in list(duplicates.keys()):
                    needed = duplicates[ip]
                else:
                    if ':' in ip:
                        needed = (int( (ip.split(':'))[2] ))
                    else:
                        needed = (int( (ip.split('.'))[2] ))

                if count != needed:
                    failed.append('** Watched IP %s count %d not %d' % (ip, count, needed))

        self.assertFalse(failed, 'Scanning failed, Errors:\n%s' % ('\n'.join(failed)))

    def _run_main(self, args):
        output = io.StringIO()
        save_stdout = sys.stdout
        save_stderr = sys.stderr
        sys.stdout = output
        sys.stderr = output
        got_exception = None
        etype = None
        try:
            blockhosts.main(args)
        except Exception as e:
            etype, evalue, etraceback = sys.exc_info()
            pass

        sys.stdout = save_stdout
        sys.stderr = save_stderr

        value = output.getvalue()
        # print 'got stdout and stderr', output.getvalue()

        if etype:
            print("got exception ")
            print(traceback.print_exception(etype, evalue, etraceback))

        return value

    def testMainMessages(self):
        args = [ '--dry-run', '--mail', '--ipblock=iptables',
                 '--logfiles=' + TEST_LOG_FILE,
                 '--quiet',  '--configfile=' + TEST_CONFIG_FILE,
                 '--blockfile=' + TEST_BLOCKFILE,
               ]

        Log.Info(' Test main messages - errors/warnings')
        Log.Debug('  ... main(%s)' % (args))

        value = self._run_main(args)

        # print 'got stdout and stderr', output.getvalue()
        self.assertFalse(TestBlockHosts.ERRORS_RE.search(value), 
                    'main() output contains ERROR or WARNING:\n%s' % value)


    def testMainFilters(self):
        args = [ '--dry-run', '--ipblock=ip route',
                 '--logfiles=' + TEST_LOG_FILE,
                 '--debug',  '--configfile=' + TEST_CONFIG_FILE,
                 '--blockfile=' + TEST_BLOCKFILE,
                 '--blacklist=255.0.231.1, 100.0.0.2, 10.0.0.1, 10\.102\..*',
                 '--whitelist=10\.0\..*',
               ]

        Log.Info(' Test main filters - blacklist and whitelist')
        Log.Debug('  ... main(%s)' % (args))

        value = self._run_main(args)

        # print 'got stdout and stderr', output.getvalue()
        lookfor = [
            "Notice: blacklist: blocking host:     255.0.231.1",
            "Notice: blacklist: blocking host:       100.0.0.2",
            "Notice: blacklist: blocking watched host:      10.102.1.1, matched '10\.102\..*'",
            "Notice: whitelist: removing blocked host:        10.0.0.1, matched '10\.0\..*'",

            ]

        for str in lookfor:
            self.assertTrue(value.find(str) >= 0,
                            'main() output does not contain (%s) \n%s' %
                            (str, value))

        # print 'got stdout and stderr', output.getvalue()
        self.assertFalse(TestBlockHosts.ERRORS_RE.search(value), 
                    'main() output contains ERROR or WARNING:\n%s' % value)


    def testIPBLock(self):
        args = [ '--dry-run',
                 '--logfiles=' + TEST_LOG_FILE,
                 '--verbose',  '--configfile=' + TEST_CONFIG_FILE,
                 '--blockfile=' + TEST_BLOCKFILE,
               ]

        ipblocks = [ '--ipblock=iptables', '--ipblock=ip route', 
                     '--ipblock=/sbin/iptables', '--ipblock=/sbin/ip route', 
                   ]

        for ipblock in ipblocks:
            Log.Info(' Test --ipblock, subtest: %s - errors/warnings' % ipblock)

            args.append(ipblock)
            Log.Debug('  ... main(%s)' % (args))

            value = self._run_main(args)

            # print 'got stdout and stderr', output.getvalue()
            self.assertFalse(TestBlockHosts.ERRORS_RE.search(value), 
                        'main() output contains ERROR or WARNING:\n%s' % value)

            args.remove(ipblock)


if __name__ == '__main__':
    syslog.openlog(SCRIPT_ID)
    # don't syslog anything (EMERG is 0, so can't use it, use ALERT)
    syslog.setlogmask(syslog.LOG_ALERT)
    unittest.main()
