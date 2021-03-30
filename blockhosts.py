#!/usr/bin/env python
# vim: set fileencoding=latin-1 :
#blockhosts.py

"""Automatic updates to hosts.allow to block IP addresses based on failed
login accesses for ssh/ftp or any such service.

Script to record how many times "sshd" or other service is being attacked,
and when a particular IP address exceeds a configured number of
failed login attempts, that IP address is added to /etc/hosts.allow with
the deny flag to prohibit access.
Script uses /etc/hosts.allow to store (in comments) count
of failed attempts, and date of last attempt for each IP address
By default, hosts.allow is used, but program can be configured to use any
other file, including /etc/hosts.deny, as needed.
IP addresses with expired last attempt dates (configurable)
can be removed, to keep /etc/hosts.allow size manageable.
This script can be run as the optional command in /etc/hosts.allow
itself, so will kick off only when someone connects to a specific service
controlled by tcpwrappers, or use cron to periodically run this script.

TCP_WRAPPERS should be enabled for all services, which allows use of
hosts.allow file.
hosts_options should also have been enabled, which requires compile time
PROCESS_OPTIONS to be turned on. This allows extensions to the
basic hosts.* file line format.  The extensible language supports lines
of this format in /etc/hosts.allow:
    daemon_list : client_list : option : option ...
See the man pages for hosts_options and hosts_access(5) for more
information.


Null Routing and Packet Filtering Blocking
Many services do not use libwrap, so cannot use TCP_WRAPPERS blocking
methods. Those services can be protected by this script, by using
the null routing, or iptables packet filtering to completely block all
network communication from a particular IP address.
Use the --ipblock=<how> option to enable null routing or packet filtering
blocking.
Root permission for the run of blockhosts.py script is needed, since
only root can change routing tables or install iptables rules. This works
fine if using hosts.access/hosts.deny to run this script.
Null routing/packet filtering could be used for example, to scan Apache
web server logs, and based on that, block an IP address so neither
Apache or any other service on the computer will see any network
communication that IP address.

Mail Notification Support
Email notifications can be sent periodically using a cron script, or
email can be sent provided a a given IP address is being blocked by
blockhosts. Such email notifications include all currently blocked
IP addresses in the email message. Will not send email if given IP address
is not yet blocked, or if not a single address is being blocked. SMTP is
required for sending email.

Whitelist and Blacklist Support
Lists can be specified to force particular IP addresses to be
never blocked (whitelist), or to be immediately blocked (blacklist).
The lists contain IP addresses or regular expressions representing IP
addresses. This built-in method of whitelist and blacklist provides
an easy way to make sure IPs are blocked or never-blocked whatever the
configuration of blockhosts.py - using cron or hosts.allow invocation, or
using hosts.allow or iptables or route command blocking.

Example hosts.allow script:
Warnings:
* Be sure to keep a backup of your initial hosts.allow (or hosts.deny)
  file, in case it gets overwritten due to an error in this script.
* Do read up on the web topics related to security, denial-of-service,
  and IP-address spoofing.
  Visit the blockhosts home page for references.

Usage:
For more info, run this program with --help option.

The blockfile (hosts.allow, or if needed, hosts.deny) layout needs to
have a certain format:
  Add following sections, in this order:
  -- permament whitelist and blacklist of IP addresses using hosts.allow syntax
  -- blockhosts marker lines - two lines
  -- execute command to kick off blockhosts.py on connects to services

See "man 5 hosts_access" and "man hosts_options" for more details on
hosts.* files line formats.

The two HOSTS_MARKER_LINEs define a section, this is the
region where blockhosts will read/write IP blocking data in the
hosts.allow file. It will use comments to store bookkeeping data needed
by this script in that section, too.
Lines before and after the two HOST_MARKER_LINEs will be left unchanged
in the hosts.allow file

See the "INSTALL" file in the blockhosts.py source package for a
detailed example of the hosts.allow file.

====
Requirements:
    1: Python 2.3 or later, need the optparse module.

    2: Primarily uses host control facility and related files such as
       hosts.access. If not using TCP/IP blocking, then the extensions to
       the access control language as described in the man 5 hosts_options
       page are required, which allow use of :allow and :deny keywords.
       ["...extensions  are  turned  on  at program build time by
       building with -DPROCESS_OPTIONS..."]

    3: If not using host control facilities (tcpd, hosts.access, etc),
       then there needs to be a way to trigger the run of blockhosts.py,
       or blockhosts.py should be run periodically using cron. Secondly,
       there must be some way to update a file to list the blocked ip
       (for example, hosts.deny file, or Apache .htaccess file, etc).
       Alternately, all TCP/IP communication can be blocked by using the
       null-routing or packet filtering options of blockhosts.py

====
BlockHosts Script License
This work is hereby released into the Public Domain.
To view a copy of the public domain dedication, visit
http://creativecommons.org/licenses/publicdomain/ or send a letter to
Creative Commons, 559 Nathan Abbott Way, Stanford, California 94305, USA.

Author: Avinash Chopde <avinash@aczoom.com>
Created: May 2005
http://www.aczoom.com/blockhosts/

"""

# script metadata, also used by setup.py
SCRIPT_ID="blockhosts"
VERSION="2.7.0"
VERSION_DATE="September 2012"
AUTHOR="Avinash Chopde"
AUTHOR_EMAIL="avinash@aczoom.com"
URL="http://www.aczoom.com/blockhosts/"
LICENSE="http://creativecommons.org/licenses/publicdomain/"
DESCRIPTION="Block IP Addresses based on system logs showing patterns of undesirable accesses."
LONG_DESCRIPTION="""Block IP Addresses based on login or access failure
information in system logs.

Updates a hosts blockfile (such as hosts.allow) automatically,
to block IP addresses. Will also expire previously blocked addresses
based on age of last failed login attempt, this keeps the blockfile
size manageable.
In addition to TCP_WRAPPERS, can also execute iptables or ip route commands
to block all TCP/IP network input from an IP address, so all services, even
those that do not run under libwrap TCP_WRAPPERS, can be protected.
Can handle both IPv4 and IPv6 addresses, as long as the system tools also
support such addressess.

Facilities for whitelists and blacklists, and email notification on major
events are also available.

"""
import locale
locale.setlocale(locale.LC_ALL, '')

import os
import os.path
import sys
import traceback
import time
import errno
import fcntl
import ConfigParser
import syslog
import re
try:
    from optparse import OptionParser, OptionGroup, BadOptionError
except ImportError, e:
    print "Missing module: optparse\nWill not work with earlier python versions - 2.3 or later needed.\n", e
    raise

# -------------------------------------------------------------
# This script was inspired by: DenyHosts, which has been developed
#    by Phil Schwartz: http://denyhosts.sourceforge.net/
#
# Mail: 29/12/06 patch by Erik Ljungström      erik [-at-] ibiblio dot 0rg
#    http://www.aczoom.com/forums/blockhosts/patch-enabling-email-alerts
# -------------------------------------------------------------

# ======================= LOGGING FUNCTIONS ========================

def die(msg, *args):
    """Exit, serious error occurred"""
    # function not used

    string = "FATAL ERROR: " + " ".join([str(msg)] + map(str, args))
    # print >> sys.stderr, string # sys.exit prints message
    syslog.syslog(syslog.LOG_ERR, string)
    sys.exit(string)

# --------------------------------

class Log:
    """Log support variables and functions, including keeping track
       of last few messages at each level

    """

    # logging levels - each higher level includes lower level messages
    MESSAGE_LEVEL_ERROR = 0    # 0 -> error
    MESSAGE_LEVEL_WARNING = 1  # 1 -> warning
    MESSAGE_LEVEL_NOTICE = 2     # 2 -> notice
    MESSAGE_LEVEL_INFO = 3     # 3 -> info
    MESSAGE_LEVEL_DEBUG = 4    # 4 -> debug

    # level to use for this run of the program, set in config or command line
    MESSAGE_LEVEL = MESSAGE_LEVEL_WARNING

    # store all messages here, to be sent out in email, if so configured
    MESSAGE_ARCHIVE = []
    MESSAGE_ARCHIVE_LEN_MAX = 1024

    def SetPrintLevel(cls, level):
        """Set message level to determine die, error, info, debug print outs.
        
        verbosity_level is the value assigned to options.verbose by the
        OptionParser
        """
        if cls.MESSAGE_LEVEL_ERROR <= level <= cls.MESSAGE_LEVEL_DEBUG:
            cls.MESSAGE_LEVEL = level 
        else:
            raise IndexError, "Invalid Log message level: %s" % str(level)

    SetPrintLevel = classmethod(SetPrintLevel)

    def PrintLevel(cls, level, msg, *args):
        """Print message to stderr, but only if level is >= MESSAGE_LEVEL"""

        string = " ".join([str(msg)] + map(str, args))
        if cls.MESSAGE_LEVEL >= level:
            print >> sys.stderr, string
            # store messages, may be used to send in email notifications
            cls.MESSAGE_ARCHIVE.append(string)
            # keep archive from becoming too large
            if len(cls.MESSAGE_ARCHIVE) > cls.MESSAGE_ARCHIVE_LEN_MAX:
                del cls.MESSAGE_ARCHIVE[0]

        # hand over for any syslog printing
        cls.PrintSysLog(level, string)

    PrintLevel = classmethod(PrintLevel)

    def Error(cls, msg, *args):
        """Print error message, a level 0 message, using print_level"""
        cls.PrintLevel(cls.MESSAGE_LEVEL_ERROR, "ERROR: ", msg, *args)
    Error = classmethod(Error)

    def Warning(cls, msg, *args):
        """Print warning message, a level 1 message, using print_level"""
        cls.PrintLevel(cls.MESSAGE_LEVEL_WARNING, "Warning: " + msg, *args)
    Warning = classmethod(Warning)

    def Notice(cls, msg, *args):
        """Print notice message, a level 2 message, using print_level"""
        cls.PrintLevel(cls.MESSAGE_LEVEL_NOTICE, "Notice: " + msg, *args)
    Notice = classmethod(Notice)

    def Info(cls, msg, *args):
        """Print info message, a level 3 message, using print_level"""
        cls.PrintLevel(cls.MESSAGE_LEVEL_INFO, msg, *args)
    Info = classmethod(Info)

    def Debug(cls, msg, *args):
        """Print debug message, a level 4 message, using print_level"""
        cls.PrintLevel(cls.MESSAGE_LEVEL_DEBUG, msg, *args)
    Debug = classmethod(Debug)

    # ------------ syslog logging
    # normally enabled, disabled for dry-run or load-only runs
    _ENABLE_SYSLOG = True

    def OpenSysLog(cls):
        syslog.openlog(SCRIPT_ID, syslog.LOG_PID, syslog.LOG_USER)

    OpenSysLog = classmethod(OpenSysLog)

    def EnableSysLog(cls, flag):
        previous = cls._ENABLE_SYSLOG
        if flag:
            cls._ENABLE_SYSLOG = True
        else:
            cls._ENABLE_SYSLOG = False
        return previous

    EnableSysLog = classmethod(EnableSysLog)

    def PrintSysLog(cls, level, string):
        if not cls._ENABLE_SYSLOG:
            # print >> sys.stderr, "PrintSyslog - got level %d, but not enabled\n" % level
            return

        # notice, warning, errors are always written to syslog
        if level == cls.MESSAGE_LEVEL_ERROR:
            syslog.syslog(syslog.LOG_ERR, string)
        elif level == cls.MESSAGE_LEVEL_WARNING:
            syslog.syslog(syslog.LOG_WARNING, string)
        elif level == cls.MESSAGE_LEVEL_NOTICE:
            syslog.syslog(syslog.LOG_NOTICE, string)

    PrintSysLog = classmethod(PrintSysLog)

# ======================= CONFIGURATION CLASSES ========================
# defaults for parameters follow this order:
# 1 -> use the value provided as an argument in argv[] to this script
# 2 -> if not, then use the value defined in CONFIGFILE
# 3 -> if not, then use the value hard-coded in this script - HC_OPTIONS

class Config(object):
    """
    Keep track of configuration - priority order: values provided on
    command line, then in the config file then program hard-coded
    defaults.
    """

    HC_OPTIONS = {
        "CONFIGFILE": "/etc/blockhosts.cfg",
        }

    # --------------------------------
    # Class Variables - Start Time Values, Time Formats

    # global time definitions, may be used by other scripts importing blockhosts
    START_TIME = time.time()

    # use ISO time formats to display time, store and decode in /etc/hosts.allow
    # %z is better than %Z, but python2.4 has bug - always displays as +0000,
    # so can't use %Z%z which would be preferable for human-readable displays
    # - but note that %z is not accepted by strptime, so stick with %Z for now
    # so, instead of using single time format, need to use another one for UTC
    # 2011-Jun: Found that even %Z is now a problem on some systems.
    # Python strptime problem. On some systems, fails to read time written
    # by strftime, get this error:
    # ValueError: time data '2011-06-16 10:46:10 WEST' does not match format '%Y-%m-%d %H:%M:%S %Z'
    # Code changed to not rely on Python time.strptime anymore, uses epoch UTC 
    # number of seconds now. The orignal reason for using strftime was to show
    # human readable date/time in hosts.allow. That is still done, but in
    # hosts.allow comments only.
    # See bug report in: http://www.aczoom.com/forums/blockhosts/mar-10-151801-domains-blockhosts5599-error-failed-to-parse-date-for-ip-18911419951#comment-5386
    ISO_STRFTIME = "%Y-%m-%d %H:%M:%S %Z" # don't use strptime, %Z may fail
    ISO_UTC_STRFTIME = "%Y-%m-%d %H:%M:%S+0000"

    START_TIME_STR = time.strftime(ISO_STRFTIME, time.localtime(START_TIME))
    START_TIME_UTC_STR = time.strftime(ISO_UTC_STRFTIME, time.gmtime(START_TIME))
    #before version 2.6.0, block file hosts.allow used date/time like this:
    #bh: ip:   10.0.0.46 :   8 : 2011-06-17 16:07:53 EDT
    #from version 2.5 onwards, it looks like:
    #bh: ip:   10.0.0.46 :   8 : 1308341273.0 # 2011-06-17 16:07:53 EDT
    PRE260_STRFTIME = "%Y-%m-%d %H:%M:%S %Z"
    PRE260_STRFTIME_RE = re.compile(r"^\d+-\d+-\d+ \d+:\d+:\d+.*$")

    #before version 1.0.4, block file hosts.allow used date/time like this:
    #bh: ip:   10.0.0.136 :   8 : 2007-02-22-14-20
    # to support reading the old format, use the following variables; remove
    # all support for old times after 2008 or so, if everyone has upgraded...
    PRE104_STRFTIME = "%Y-%m-%d-%H-%M"
    PRE104_STRFTIME_RE = re.compile(r"^\d+-\d+-\d+-\d+-\d+$")

    # constants, to recognize markers in the blockfile
    HOSTS_MARKER_LINE       = "#---- BlockHosts Additions"
    HOSTS_MARKER_WATCHED    = "#bh: ip:"
    HOSTS_MARKER_FIRSTLINE  = "#bh: first line:"
    HOSTS_MARKER_OFFSET     = "#bh: offset:"
    HOSTS_MARKER_LOGFILE    = "#bh: logfile:"

    # IPv4 addresses are matched using this regular-expression string
    HOST_IPv4_RE = (
        r'((::ffff:|::)?' # optional IPv4 prefix for IPv6 notation
        r'(?P<IPv4>'
        r'(25[0-5]|2[0-4]\d|[01]?\d\d?)' # 1st octet
        r'(\.(25[0-5]|2[0-4]\d|[01]?\d\d?)){3}))' # 2nd, 3rd, 4th octet
    )
    # IPv6 addresses are matched using this regular-expression string
    # This matches more than just IPv6 addresses, but since it is only used in locations
    # where an address is expected, a loose regex is fine. If needed, use the helper function
    # is_IPv6_address(str) to confirm it is a IPv6 address.
    HOST_IPv6_RE = (
        # a loose but good enough IPv6 regex, also covers IPv4
        r'(?P<IPv6>([.:A-Fa-f0-9]{1,4})+)'
    )
    # For reading IP addresses, we use HOST_IP_RE
    HOST_IP_RE = ''.join(['(?P<ip>', HOST_IPv4_RE, '|', HOST_IPv6_RE, ')'])
    # Compiled regexps
    HOST_IP_REOBJ = re.compile("^" + HOST_IP_RE + "$")
    HOST_IPv4_REOBJ = re.compile("^" + HOST_IPv4_RE + "$")
    HOST_IPv6_REOBJ = re.compile("^" + HOST_IPv6_RE + "$")

    # Config lines may need this placeholder to denote a IP address
    HOST_IP_KEY = r'{HOST_IP}'

    # --------------------------------
    class BHOptionParser(OptionParser):
        def error(self, msg):
            """Print message and raise"""
            # this allows message to get into syslog, so does not get
            # lost if just printed to stdout as base OptionParser does
            Log.Error("BHOptionParser: ", msg)
            raise InvalidOptionError(msg)

    # --------------------------------
    def __init__(self, args, ver, desc):

        self._args = args

        self._oparser = Config.BHOptionParser(version=ver, description=desc)

        self._oparser.set_defaults(configfile=self.HC_OPTIONS["CONFIGFILE"])
        self._oparser.add_option("--configfile", type="string", metavar="FILE",
            help="Name of configuration file to read. A configuration file must exist, blockhosts cannot run without a configuration file. (%s)" % self.HC_OPTIONS["CONFIGFILE"])

        # self.config first stores all the values from hard coded program
        # defaults.
        # Its values will be updated from the configuration file values
        defaults = self._oparser.get_default_values()

        self._config = {}
        self._config["CONFIGFILE"] = defaults.configfile
        self._options = {}

        # data from self.config, updated with values from command-line
        # options - this will sent to parse_args, to use as
        # optparse.Values instance, this is what will be used by the
        # program to read values for all config options

        # check option arguments to see if a config file has been specified
        # note: accepts --configfile=<name>, errors on --configfile <name>
        carg = [arg for arg in args if arg.startswith('--configfile')]

        if carg:
            (self._options, rest_args) = self._oparser.parse_args(carg)
            self._config["CONFIGFILE"] = self._options.configfile

        # print "debug: Config filename: ", self["configfile"]

    def __str__(self):
        return "Configuration: " + str(self._config) + "\nOptions: " + str(self._options)

    def add_section(self, section):
        # add all program hard-coded defaults
        self._config.update(section.HC_OPTIONS)

        # load up the config from the specified config file
        self._load_configfile(section.NAME)

        section.setup_options(self._oparser, self._config)

    def parse_args(self):
        (self._options, rest_args) = self._oparser.parse_args(self._args)
        return rest_args

    def get(self, option):
        """Find value assigned to option in command-line, configfile, or
        hard-coded in program

        Note that case matters, all command line options are lower case,
        and all configuration file options are upper case
        """

        try:
            val = getattr(self._options, option)
            # print "debug: got optparse ", option, ", val ", val
        except AttributeError:
            val = self._config[option]
            # print "debug: failed optparse ", option, ", got config val ", val

        return val

    def __getitem__(self, option):
        return self.get(option)

    # --------------------------------
    def _load_configfile(self, section):
        """Read in the configuration file, given section."""

        filedata = ConfigParser.SafeConfigParser()
        filedata.optionxform = str # leaves tags same case - upper/lower

        configfile = self._config["CONFIGFILE"]

        try:
            fp = open(configfile, "r") # for error report - check existence
            filedata.read(configfile)
        except:
            Log.Error("Config file '%s' missig/invalid? Cannot continue." % configfile)
            raise
        else:
            fp.close()

        #debug print " loading config %s section %s" % (configfile, section)

        try:
            allitems = dict(filedata.items(section))
        except ConfigParser.NoSectionError:
            Log.Error("Config file '%s' missing required section '%s'" % (configfile, section))
            raise

        keys = allitems.keys()
        for key in keys:
            if key in self._config:
                try:
                    self._config[key] = eval(allitems[key])
                    #debug print " got config %s = %s" % (key, self._config[key])
                except:
                    Log.Error("Config file Error: invalid line or value found:\n    %s = %s" % (key, allitems[key]))
                    raise
            else:
                Log.Warning("Config '%s': found invalid/unneeded definition: %s" % (configfile, key))

    # --------------------------------
    def replace_host_ip_key(cls, line):
        if line.find(cls.HOST_IP_KEY):
            line = line.replace(cls.HOST_IP_KEY, cls.HOST_IP_RE)
        else:
            msg = "line %s is missing required %s part" % (line, cls.HOST_IP_KEY)
            Log.Error(msg)
            raise InvalidOptionError(msg)
        return line

    replace_host_ip_key = classmethod(replace_host_ip_key)


# --------------------------------
class ConfigSection(object):
    """Abstract base class - all following members need to be defined."""
    NAME = "Undefined"
    HC_OPTIONS = {}
    def setup_options(self, option_parser, config_dict):
        raise NotImplemented

class CommonConfig(ConfigSection):
    """
    Keep track of common configuration, command line options, used by all
    utilities - blockfile reader/updater, mail notifications, ip route
    blocking.
    """

    # Defaults, hard-coded options, these values are used last if no args
    # and no config file provided
    HC_OPTIONS = {
        "VERBOSE": Log.MESSAGE_LEVEL,
        "HOSTS_BLOCKFILE": "/etc/hosts.allow",
        # the prefix and suffix of line to output, to turn on blocking of some IP address.
        "HOST_BLOCKLINE_IPv4": ("ALL: ",   " : deny"),
        "HOST_BLOCKLINE_IPv6": ("ALL: [", "] : deny"),
    }

    NAME = "common"  # config file section name is [NAME]

    def setup_options(self, oparser, config):
        """Update the parser with values for defaults and option parsing
        """
        oparser.set_defaults(verbose=config["VERBOSE"],
            dry_run=False,
            echo="",
            blockfile=config["HOSTS_BLOCKFILE"],
            blockline_ipv4=config["HOST_BLOCKLINE_IPv4"],
            blockline_ipv6=config["HOST_BLOCKLINE_IPv6"],
            )
        defaults = oparser.get_default_values()

        oconfig = OptionGroup(oparser, "Common options",
        """Each option is shown below with its current value in parentheses ().
Nearly all of these options can be specified in the configuration file,
and that is the recommended way.
""")

        oconfig.add_option("-q", "--quiet",
            action="store_const",
            const=Log.MESSAGE_LEVEL_ERROR, dest="verbose",
            help="Be as quiet as possible - only print out error messages")

        oconfig.add_option("-v", "--verbose",
            action="store_const",
            const=Log.MESSAGE_LEVEL_INFO, dest="verbose",
            help="Be verbose - print errors, warnings, and info messages")

        oconfig.add_option("-g", "--debug",
            action="store_const",
            const=Log.MESSAGE_LEVEL_DEBUG, dest="verbose",
            help="Be chatty - print out debug level messages also")

        oconfig.add_option("--dry-run", action="store_true",
            help="Don't write the block file or send email or block routes, just print out blockhosts section of output block file file to stdout instead (%s)" % defaults.dry_run)

        oconfig.add_option("--echo", type="string", metavar="TAG",
            help="Prints TAG on stderr and syslog, may be used to identify a run of this script (%s)" % defaults.echo)

        oconfig.add_option("--blockfile", type="string", metavar="FILE",
            help="Name of hosts-block-file to read/write (%s)" % defaults.blockfile)

        oparser.add_option_group(oconfig)

# ======================= MAIL SECTION ========================
class MailConfig(ConfigSection):
    """Manage setup related to sending of email

    Keep track of configuration, command line options, and general setup.
    """

    # Defaults, hard-coded options, these values are used last if no args
    # and no values in config file
    HC_OPTIONS = {
        "MAIL": False,
        "NOTIFY_ADDRESS": 'root@localhost.localdomain',
        "SMTP_SERVER": "localhost",
        "SMTP_USER": '',
        "SMTP_PASSWD": '',
        "SENDER_ADDRESS": 'BlockHosts <blockhosts-do-not-reply@localhost.localdomain>',
    }

    NAME = "mail"  # config file section name is [NAME]

    def setup_options(self, oparser, config):
        """Update the parser with values for defaults and option parsing

           Calls add_option for all the options used by mail process
        """

        oparser.set_defaults(
            notify_address=config["NOTIFY_ADDRESS"],
            mail=config["MAIL"],
            check_ip="",
            )

        defaults = oparser.get_default_values()

        oconfig = OptionGroup(oparser, "Mail specific options",
            """These options apply to the process of sending email.
    """)

        oconfig.add_option("--mail", action="store_true",
            help="Enable e-mail capability - send message with list of newly blocked or expired hosts, if any. Email is sent only if there are error/warning/notice messages in the log output. (%s)" % defaults.mail)

        oconfig.add_option("--check-ip", type="string", metavar="IPADDRESS",
            help="DEPRECATED. Instead of always mailing entire list of blocked address, just send email if given IP address is being blocked (%s).\nDEPRECATED - this is no longer useful since --mail will automatically send email only on errors/warnings/notices, and the notice level includes newly blocked or expired addresses." % defaults.check_ip)

        oconfig.add_option("--notify-address", metavar="ADDRESS",
            help="Address to send notification emails to (%s)" % defaults.notify_address)

        oparser.add_option_group(oconfig)

def do_mail(config, blocked_ips, watched_hosts):
    """send email with list of blocked and/or watched addresses"""

    import smtplib

    # trim the check-ip argument, same regex as used to match log lines
    check_host = None
    if config["check_ip"]:
        m = Config.HOST_IP_REOBJ.search(config["check_ip"])
        if m:
            try:
                check_host = m.group("ip")
            except IndexError:
                check_host = None
        if not check_host:
            Log.Error("** Input error: ignoring --check-ip, invalid IP address '%s'?" % (config["check_ip"]))

    found_check_host = False

    subject = SCRIPT_ID + ": "
    lines = []

    # always include all blocked hosts in output, only send email if
    # there are some blocked hosts
    # split the watched_hosts into two dicts - one containing all blocked
    # hosts with the data, and second containing all watched but not yet
    # blocked addresses
    if blocked_ips:
        lines.append("Blocking hosts:")
        for host in blocked_ips:
            line = " %15s" % (host)
            lines.append(line)
            if host == check_host:
                found_check_host = True
                subject += "Blocked %s. " % (host)

        lines.append("")

        # add watched hosts
        hosts = sort_by_value(watched_hosts, reverse = True)
        if hosts:
            lines.append("Watching hosts:")
        for host in hosts:
            data = watched_hosts[host]
            line = " %15s   count: %4d   updated at:  " % (host, data.count)
            t = time.localtime(data.time)
            line += time.strftime(Config.ISO_STRFTIME, t)
            lines.append(line)
        lines.append("")

    # add all important log messages - errors/warnings/notices
    # messages always added - check if such messages exists in log lines
    found_important_lines = False
    test = re.compile(r"^(error|warning|notice):", re.IGNORECASE)
    for l in Log.MESSAGE_ARCHIVE:
        if test.search(l):
            found_important_lines = True
            # add the log messages, and exit testing loop
            lines.append("Log messages:")
            lines += Log.MESSAGE_ARCHIVE
            break

    subject += "Blocking %d, Watching %d." \
               % (len(blocked_ips), len(watched_hosts))

    # all done with mail body, now send it
    if (found_check_host or found_important_lines):
        Log.Info(" ... sending email notification")
        mailer = MailMessage(config, subject, lines)
        try:
            mailer.send_mail(config["dry_run"])
        except smtplib.SMTPException, e:
            Log.Error(e)
    else:
        Log.Info(" ... no email to send.")

# --------------------------------
class MailMessage:
    """Compose an email message, and then send it
    
    Constructor takes an dict with all mail header info, as well as a
    string specifying subject, and an array of strings specifying body of
    message
    """

    def __init__(self, config, subject, lines):
        # mail header info is in the config object
        self.__address = config["notify_address"].replace('\@', '@')
        self.__sender_address = config["SENDER_ADDRESS"].replace('\@', '@')
        self.__smtp_server = config["SMTP_SERVER"]
        self.__smtp_user = config["SMTP_USER"].replace('\@', '@')
        self.__smtp_passwd = config["SMTP_PASSWD"]
        # If smtp_user and passwd is empty, no authentication is necessary

        # mail subject (string) and lines (list of strings)
        self.__subject = subject
        self.__lines = lines

    def send_mail(self, dry_run = False):

        import smtplib
        import socket

        if len(self.__address) == 0:
            Log.Debug("   ... no email address specified, not sending any mail")
            return

        message = "To: " + self.__address
        message += "\nFrom: "+ self.__sender_address
        message += "\nSubject: " + self.__subject + "\n\n"
        message += "\n".join(self.__lines)
        if dry_run:
            print "\n-----", SCRIPT_ID, ": dry-run, email message-------\n"
            print message
            print "-----"
            return

        try:
            session = smtplib.SMTP(self.__smtp_server)
        except socket.error, (value,message): 
            Log.Error("Mail: Could not open SMTP connection to '%s', error '%s'." % (self.__smtp_server, message))
            return

        if len(self.__smtp_user) > 0:
            Log.Debug("%s: calling SMTP login..." % SCRIPT_ID)
            session.login(self.__smtp_user, self.__smtp_passwd)
        Log.Debug("%s: calling SMTP sendmail..." % SCRIPT_ID)
        smtpresult = session.sendmail(self.__sender_address, self.__address, message)
        if smtpresult:
            errstr = ""
            for recip in smtpresult.keys():
                errstr = """Unable to deliver mail to: %s Server responded: %s %s %s"""\
                         % (recip, smtpresult[recip][0], smtpresult[recip][1], errstr)
                raise smtplib.SMTPException, errstr
        
# ======================= TCP/IP BLOCKING SECTION ========================
class IPBlockConfig(ConfigSection):
    """Manage setup related to using ip/iptables commands to block IP addresses

    Keep track of configuration, command line options, and general setup.
    """

    # Defaults, hard-coded options, these values are used last if no args
    # and no values in config file
    HC_OPTIONS = {
        "IPBLOCK": "",
    }

    NAME = "ipblock"  # config file section name is [NAME]

    def setup_options(self, oparser, config):
        """Update the parser with values for defaults and option parsing

           Calls add_option for all the options used by mail process
        """

        oparser.set_defaults(
            ipblock=config["IPBLOCK"],
            )

        defaults = oparser.get_default_values()

        oconfig = OptionGroup(oparser, "TCP/IP level blocking options",
            """These options apply to the process of using ip route/iptables commands to block IP addresses.
Root permission for the run of this script is needed, since
only root can change routing tables or install iptables rules. [This works
fine if using hosts.access/hosts.deny to run this script.]
All communication to the IP address is blocked at route or packet,
therefore, this method of disabling a host will protect even
non-tcpwrapper services.
""")

        oconfig.add_option("--ipblock",
            action="store", type="string", dest="ipblock", metavar="IP-COMMAND",
            help="""Enable IP address block capability, using "iptables" or "ip6tables" or "ip route" command. All communication to the IP address is blocked using packet filtering. Use --ipblock=iptables or --ipblock="ip route", as needed. Full path can also be provided, e.g. --ipblock=/sbin/ip6tables or --ipblock="/sbin/ip route" (%s)""" % defaults.ipblock)

        oparser.add_option_group(oconfig)

# --------------------------------
def do_ipblock(config, blocked_ips):
    """Use ip (null-route) or iptables (packet filtering) to block addresses"""

    ipblock = config["ipblock"]
    if re.search("ip\s+route$", ipblock):
        _do_iproute(ipblock, config["dry_run"], blocked_ips)
    elif (ipblock.endswith("iptables") or ipblock.endswith("ip6tables")):
        _do_iptables(ipblock, config["dry_run"], blocked_ips)
    else:
        Log.Error("Invalid value for ipblock '%s', ignoring. See --help for syntax." % ipblock)

def _do_cmd(cmd, dry_run, expect=None):
    """Executes command, and returns a tuple that is command return
    status if os.WIFEXITED(waitstatus) is true, otherwise returns
    (waitstatus, output) as received from commands.getstatusoutput()
    Prints error if expect code is not same as waitstatus
    """

    import commands

    Log.Debug("Running: ", cmd)
    if dry_run:
        return (0, '')

    (waitstatus, output) = commands.getstatusoutput(cmd)
    Log.Debug("   returned waitstatus: ", waitstatus)
    if output.strip():
        Log.Debug("   output: ", output)

    if os.WIFEXITED(waitstatus):
        waitstatus = os.WEXITSTATUS(waitstatus)

    if None != expect != waitstatus:
        Log.Error("Failed command: %s (%d)\n%s" % (cmd, waitstatus, output))

    return (waitstatus, output)

# --------------------------------
def _do_iptables(path, dry_run, blocked_ips):

    chain = SCRIPT_ID

    # use a user-defined iptables chain, named as SCRIPT_ID ("blockhosts")
    # a rule is added to the INPUT chain to jump to the blockhosts chain
    # the blockhosts chain uses DROP action for each blocked IP address
    # IP addresses in blockhosts chain will be synced up to the blocked
    # list, so deletions as well as additions may occur

    # to remove the chains created by this program, run these commands
    # as root, "blockhosts" is the chain name (SCRIPT_ID)
    #   iptables --flush blockhosts
    #   iptables --delete INPUT -j blockhosts    (same for FORWARD chain too)
    #   iptables --delete-chain blockhosts
    # to see rules:
    #   iptables --list INPUT --numeric          (same for FORWARD chain too)
    #   iptables --list blockhosts --numeric
    # Note: use iptables or ip6tables as needed above.

    if dry_run:
        print "Commands (tentative) to run for IPTables filtering:"

    # check that user-defined chain exists
    # iptables --new blockhosts [ok to run multiple times]
    cmd = path + " --new %s" % chain
    (waitstatus, output) = _do_cmd(cmd, dry_run, None)
    if waitstatus != 0:
        # iptables: Chain already exists
        Log.Debug(" ... user-defined chain %s already exists, or error occurred " % chain)
    else:
        Log.Info(" ... created user-defined chain %s" % chain)

    # create jump from both INPUT and FORWARD chain to block all traffic
    # coming from rogue host. To handle the case when default policy
    # for INPUT/FORWARD chains is DROP, will insert at top of the INPUT
    # chain.  This will also work when the default policy is ACCEPT
    drop_regex = re.compile(r"\b%s\b.+?0.0.0.0" % chain)
    Log.Debug("   pattern to search for INPUT/FORWARD chain jump: ",drop_regex)
    for from_chain in ('INPUT', 'FORWARD'):
        # check if from_chain jumps to user-defined chain already
        #   iptables --list <from_chain> --numeric
        # Outputs: blockhosts  all  --  0.0.0.0/0            0.0.0.0/0
        cmd = path + " --list %s --numeric" % from_chain
        (waitstatus, output) = _do_cmd(cmd, dry_run, 0)
        if waitstatus != 0:
            return

        if not drop_regex.search(output):
            Log.Info(" ... creating jump from %s to %s chain" % (from_chain, chain))
            cmd = path + " --insert %s 1 -j %s" % (from_chain, chain)
            (waitstatus, output) = _do_cmd(cmd, dry_run, 0)
            if waitstatus != 0:
                return
        else:
            Log.Debug("   jump rule from %s to %s chain exists" % (from_chain, chain))

    # get current list of filtered hosts, and do two things:
    # 1 -> delete rule for host, if not on blocked list
    # 2 -> delete host from blocked list, if rule already exists
    # iptables --list blockhosts --numeric
    # DROP       all  --  10.99.99.99          0.0.0.0/0
    cmd = path + " --list %s --numeric" % chain
    (waitstatus, output) = _do_cmd(cmd, dry_run, 0)
    if waitstatus != 0:
        return

    drop_regex = r"DROP.+?" + Config.HOST_IP_RE + r"\s+"
    Log.Debug("   pattern to search for iptables blocked ip: ", drop_regex)
    drop_regex = re.compile(drop_regex)

    blocked = blocked_ips[:]
    for line in output.splitlines():
        m = drop_regex.search(line)
        if not m: continue
        try:
            host = m.group("ip")
            if host in blocked:
                blocked.remove(host)
                Log.Debug("  rule already exists for host ", host)
            else:
                Log.Debug("  rule found for non-blocked host, removing from chain ", host)
                cmd = path + " --delete %s --source %s -j DROP" % (chain, host)
                Log.Info(" ... iptables: removing rule to block: ", host)
                (waitstatus, output) = _do_cmd(cmd, dry_run, 0)
                if waitstatus != 0:
                    return
        except IndexError:
            pass

    # now blocked contains all IP addresses that need to have DROP rules
    for host in blocked:
        cmd = path + " --append %s --source %s -j DROP" % (chain, host)
        Log.Info(" ... iptables: adding rule to block: ", host)
        (waitstatus, output) = _do_cmd(cmd, dry_run, 0)
        if waitstatus != 0:
            return

# --------------------------------
def _do_iproute(path, dry_run, blocked_ips):
    """Use ip route routing table to block addresses.

    Will delete IP addresses from route if they are no longer blocked,
    and only add new IP addresses if they are not yet being blocked.

    """

    # http://www.tummy.com/journals/entries/jafo_20060727_140652

    if dry_run:
        print "Commands (tentative) to run for ip null-route blocking:"

    # get current list of blackhole'd hosts, and do two things:
    # 1 -> delete route for host, if not on blocked_ips
    # 2 -> delete host from blocked_ips, if route already exists
    # ip route list [table <id>]
    # 10.99.99.98 via 127.0.0.1 dev lo

    via = "127.0.0.1"
    cmd = path + " list"
    (waitstatus, output) = _do_cmd(cmd, dry_run, 0)
    if waitstatus != 0:
        return

    drop_regex = "^" + Config.HOST_IP_RE + r".+?via\s+" + via
    Log.Debug("   pattern to search for ip route blocked ip: ", drop_regex)
    drop_regex = re.compile(drop_regex)

    blocked = blocked_ips[:]
    for line in output.splitlines():
        m = drop_regex.search(line)
        if not m: continue
        try:
            host = m.group("ip")
            if host in blocked:
                blocked.remove(host)
                Log.Debug("  route already exists for host ", host)
            else:
                Log.Debug("  route found for non-blocked host, removing ", host)
                cmd = path + " del %s" % host
                (waitstatus, output) = _do_cmd(cmd, dry_run, 0)
                if waitstatus != 0:
                    return
                Log.Info(" ... ip route, removing null routing for: ", host)
        except IndexError:
            pass

    # now blocked contains all IP addresses that need to have null-routes
    for host in blocked:
        Log.Info(" ... ip route, adding null route for: ", host)
        cmd = path + " add %s via %s" % (host, via)
        (waitstatus, output) = _do_cmd(cmd, dry_run, 0)
        if waitstatus != 0:
            return

# ======================= HELPER CLASSES ========================
def sort_by_value(d, reverse = False):
    """ Returns the keys of dictionary d sorted by their values """
    items=d.items()
    backitems=[ [v[1],v[0]] for v in items]
    backitems.sort()
    if reverse:
        backitems.reverse()
    return [ backitems[i][1] for i in range(0,len(backitems))]
    # return sorted(d.iteritems(), key=lambda (k,v): (v,k), reverse) # Python 2.5+ only
    # L.sort(key=lambda x: x.lower())

import socket

def is_IPv6_address(addr):
    # Test for valid address by using socket functions to convert address string to packed
    # binary format. If conversion works, assume string is valid address.
    try:
        # socket.inet_aton(addr) # ipv4
        socket.inet_pton(socket.AF_INET6, addr) # ipv6
        return True # legal address
    except socket.error:
        return False # not legal

class HostData:
    """
    simple record structure to keep track of count seen and time last seen
    for a particular IP host address

    .count is in integer
    .time is same as time.time() - secs since the epoch (1970)
    """
    def __init__(self, count=0, secs = None):
        self.count = count
        self.time = secs

    def __repr__(self):
        return "HostData(" + repr(self.count) + ", " + repr(self.time)  + ")"

    def __cmp__(self, other):
        return cmp(self.time, other.time)

# ======================= EXCEPTIONS ========================
class Error(Exception):
    """Base class for exceptions in this module."""
    pass

class MissingMarkerError(Error):
    "Error: No blockhosts marker found in blockfile (hosts.*) file."
    pass

class SecondMarkerError(Error):
    "Error: Blockhosts section in blockfile (hosts.*) missing second marker."
    pass

class InvalidOptionError(Error):
    "Error: invalid option or invalid argument for option."

    def __init__(self, msg):
        self.message = msg

    def __str__(self):
        return self.message

# ======================= BLOCKHOSTS SECTION ========================
# Classes: BlockHostsConfig, LockFile, SystemLog, SystemLogOffset, BlockHosts

class BlockHostsConfig(ConfigSection):
    """Manage setup related to handling a blockfile (hosts.allow)

    Keep track of configuration, command line options, and general setup.
    """

    # Defaults, hard-coded options, these values are used last if no args
    # and no config file provided
    HC_OPTIONS = {

        "LOGFILES": ("/var/log/secure",),
            # default list of logs to process, multiple files can be listed

        "LOCKFILE": "/tmp/blockhosts.lock",
            # need create/write access to this file, used to make sure
            # only one instance of blockhosts.py script writes the
            # HOSTS_BLOCKFILE at one time 
            # note that the mail/iptables/iproute parts of the program
            # do not serialize

        "LOAD_ONLY": False,
            # don't update blockfile, just read it, and prepare list of
            # blocked and watched hosts, possibly for emailing it out, or
            # to update ip/iptables blocks

        ##############################################################
        # ALL_REGEXS: All expressions that match a failed access.
        # Each entry is:  {name} = pattern_string

        "ALL_REGEXS": {}, # blockhosts.cfg file has all the patterns

        "ENABLE_RULES": r'(sshd|.*ftpd).*', # enable patterns in ALL_REGEXS

        "IGNORE_DUPLICATES": False,
            # Sometimes (like for SSHD), a single failed login attempt may
            # print two or # more messages in the log file. This may be rare,
            # and in any case, not much of a problem - that IP will still be
            # blocked (though sooner, due to duplicate messages). The code does
            # have a way to try to detect duplicates, which is turned off by
            # default, use the variable below to turn it to True
            #IGNORE_DUPLICATES = False # False is default, can be set to True

        }

    # ALL_REGEXS contains keywords {LOG_PREFIX{service_name}} and {HOST_IP}
    SERVICE_NAME_KEY = r'{SERVICE_NAME}'
    LOG_PREFIX_KEY_RE = r'{LOG_PREFIX{(?P<service>[^{}]*)}}'
    LOG_PREFIX_KEY_REOBJ = re.compile(LOG_PREFIX_KEY_RE)
    LOG_PREFIX_RE = (
        r'^((' # ---- syslog or metalog format follows
        r'\w\w\w .?\d \d\d:\d\d:\d\d ' # time stamp Mmm dd hh:mm:ss
        r'(([^[:\]]+ )|(\[))' # host name (syslogd) or [ (metalog)
        ) + SERVICE_NAME_KEY + ( # service name (syslog and metalog)
        r'((\[(?P<pid>\d+)]:?)|(])|:)' # [pid]:? or (syslogd) or ] (metalog)
        r'( \[ID [^[:\]]+])?' # optional [ID msgid facility.priority]
        r')|(' # ---- multilog format follows
        r'@[\d\w]+'
        # ---- 
        r'))'
        )

    NAME = "blockhosts"  # config file section name is [NAME]

    def setup_options(self, oparser, config):
        """Update the parser with values for defaults and option parsing

           Calls add_option for all the options used by blockhosts
        """

        oparser.set_defaults(
            load_only=False,
            logfiles=",".join(config["LOGFILES"]),
            ignore_offset=False,
            lockfile=config["LOCKFILE"],
            enable_rules=config["ENABLE_RULES"],
            )

        defaults = oparser.get_default_values()

        oconfig = OptionGroup(oparser, "BlockHosts blockfile specific options",
        """These options apply to the process of updating the list of
blocked hosts in the blockfile.
Note that all of these options can be specified in the config file
instead of the command-line.
""")

        oconfig.add_option("--load-only",
            action="store_true",
            help="Load the blockfile, the blocked/watched host list, but do not prune/add or write back the data (%s)" % defaults.load_only)

        oconfig.add_option("--ignore-offset",
            action="store_true",
            help="Ignore last-processed offset, start processing from beginning.  This is useful for testing or special uses only. (%s)" % defaults.ignore_offset)

        # logfiles are handled specially - since optparse can't do
        # eval(), and I did not want to add a new optparse type, command
        # line arg for logfiles only accepts string, unlike the config file,
        # which accepts the full python syntax - list elements, characters
        # escaped as needed, etc.  Therefore, command line is one string
        # separated by ",", while config file is a python list with multiple
        # filenames
        oconfig.add_option("--logfiles", type="string", metavar="FILE1,FILE2,...",
            help="The names of log files to parse (\"%s\")" % defaults.logfiles)

        oconfig.add_option("--lockfile", metavar="FILE",
            help="Prevent multiple instances from writing to blockfile at once - open this file for locking and writing (%s)" % defaults.lockfile)

        oconfig.add_option("--enable-rules", type="string", metavar="REGEX", help="A regular expression to match names of rules that are to be enabled. Rule names are defined in the blockhosts config file. '.*' will enable all patterns. ('%s')" % defaults.enable_rules)

        oparser.add_option_group(oconfig)

    def expand_regex_keywords(cls, regex):
        """Replace {LOG_PREFIX{service}} and {HOST_IP}."""

        # expand the ALL_REGEXS from the config file into all_regexs
        # replace {HOST_IP}
        regex = Config.replace_host_ip_key(regex)

        # replace {LOG_PREFIX{servicename}}
        m = cls.LOG_PREFIX_KEY_REOBJ.search(regex)
        if m:
            try:
                service = m.group("service")
            except IndexError:
                # pattern did not have LOG_PREFIX, which is fine
                return regex

            # replace {LOG_PREFIX{...}} with the actual LOG_PREFIX_RE regex
            regex = cls.LOG_PREFIX_KEY_REOBJ.sub(cls.LOG_PREFIX_RE, regex)
            # the LOG_PREFIX_RE contains {SERVICE_NAME} - replace that
            regex = regex.replace(cls.SERVICE_NAME_KEY, re.escape(service))

        return regex

    expand_regex_keywords = classmethod(expand_regex_keywords)


class LockFile:
    """Create exclusive advisory lock on given file, which must be opened
    for write access atleast
    """
    def __init__(self, path):
        self._path = path
        self._locked = 0

    def lock(self):
        try:
            # use mode a+ to prevent trashing the file
            self._fp = open(self._path, "a+")
        except IOError, e :
            if e.errno == errno.ENOENT: # no such file
                # "w+" will trash existing file, or create new one
                self._fp = open(self._path, "w+")
                Log.Debug(" ... first r+ lock file open failed, so opened with w+ mode")
            else:
                raise

        try:
            rv = fcntl.lockf(self._fp.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except IOError, e :
            if e.errno == errno.EAGAIN:
                Log.Debug("File '%s' already locked, EAGAIN." % self._path)
            elif e.errno == errno.EACCES:
                Log.Debug("File '%s' permission denied, EACCES." % self._path)
            else:
                Log.Debug("File '%s' fcntl.lockf failed." % self._path, e)
            raise
        else:
            self._locked = 1


    def unlock(self):
        if not self._locked:
            Log.Debug("  debug warning: LockFile: called unlock when no lock was held, file ", self._path)
            return

        try:
            rv = fcntl.lockf(self._fp.fileno(), fcntl.LOCK_UN)
            self._fp.close()
        except IOError, e:
            Log.Debug("  debug warning: LockFile: failed to unlock or close file ", self._path, e)
        else:
            self._fp = None
            self._locked = 0


    def get_path(self):
        return self._path

# --------------------------------
class SystemLogOffset:
    """Simple record structure to keep track of location into a system
    log like message/secure file.

    Uses a offset, along with the entire first line of the file at the
    time, to allow detection of log rotation
    """
    def __init__(self, offset=0L, first_line=""):
        self.offset = long(offset)
        self.first_line = first_line

    def load_string(self, line):
        if line.startswith(Config.HOSTS_MARKER_OFFSET):
            value = line[ len(Config.HOSTS_MARKER_OFFSET) : ]
            try:
                self.offset = long(value.strip())
            except ValueError, e:
                Log.Warning("could not decode offset, using 0:", e)
                self._last_offset = 0
                return False
        elif line.startswith(Config.HOSTS_MARKER_FIRSTLINE):
            self.first_line = line[ len(Config.HOSTS_MARKER_FIRSTLINE) : ]
        return True

    def dump_string(self):
        return "%s %ld\n%s%s\n\n" % (Config.HOSTS_MARKER_OFFSET, self.offset,
                                Config.HOSTS_MARKER_FIRSTLINE, self.first_line)

    def __repr__(self):
        return 'SystemLogOffset(%ld, %s)' % (self.offset, repr(self.first_line))

# --------------------------------
class SystemLog:
    """
    Handles read operations on the system log like messages/secure log
    which contains all the sshd/proftpd or other logging attempts.
    Read operations skip previously scanned portion of the log file, if
    that is applicable.
    """
    def __init__(self, logfile):
        self._offset = SystemLogOffset()
        self._logfile = logfile
        self._fp = None

    def open(self, offset):
        try:
            self._fp = open(self._logfile, "r")
            self._offset.first_line = self._fp.readline()[:-1]
            self._fp.seek(0, 2)
            self._offset.offset = self._fp.tell()
        except IOError:
            Log.Error("Can't open or read: %s" % self._logfile)
            raise

        Log.Debug("SystemLog open:")
        Log.Debug("   first_line:", repr(self._offset.first_line))
        Log.Debug("   file length:", self._offset.offset)

        if self._offset.first_line.strip() != offset.first_line.strip():
            # log file was rotated, start from beginning
            self._offset.offset = 0L
            Log.Debug("   log file new, or rotated, ignore old offset, start at 0")
            Log.Debug("   needed first_line:", repr(offset.first_line))
        elif self._offset.offset > offset.offset:
            # new lines exist in log file, start from old offset
            self._offset.offset = offset.offset
        else:
            # no new entries in log file
            # Log.Debug("   log file offset unchanged, nothing new to read")
            pass

        Log.Info(" ... loading log file %s, offset: %d" % ( self._logfile, self._offset.offset))

        self._fp.seek(self._offset.offset)

        return self._fp != None

    def close(self):
        try:
            return self._fp.close()
        except IOError, e:
            Log.Warning("could not close logfile ", self._logfile, e)

        return None

    def readline(self):
        try:
            line = self._fp.readline()
            self._offset.offset = self._fp.tell()
        except IOError, e:
            line = None
            Log.Warning("readline: could not read logfile", self._logfile, e)

        return line

    def get_offset(self):
        return self._offset


# --------------------------------
class BlockHosts:
    def __init__(self, blockfile, blockline_ipv4, blockline_ipv6):
        self._watched_hosts = {} # hosts -> HostData [count, last seen]
        self._blocked_ips = [] # ip addressess blocked
        self._offset_first_marker = -1L
        self._remaining_lines = [] # all lines after the 2nd end marker
        self._blockfile = blockfile
        self._blockline_ipv4 = blockline_ipv4
        self._blockline_ipv6 = blockline_ipv6
        self._all_reobjs = {} # compiled patterns to match log lines
        self._ip_pid = None
        self.ignored_failures_count = 0

        # pattern to get IP address from a blocked IP address line
        # in between the blockhosts marker section in blockfile
        Log.Debug("   {HOST_IP} matched using this re: ", Config.HOST_IP_RE)

    def load_hosts_blockfile(self, logoffsets = {}):
        self._remaining_lines = []

        Log.Debug(" ... load blockfile:", self._blockfile)

        state = 0
        # state = 0 -> error state
        # state = 1 -> have not seen first marker
        # state = 2 -> have seen first marker, not seen second marker
        # state = 3 -> have seen second marker
        found_first_marker = False
        try:
            fp = open(self._blockfile, "r")
            state = 1
            # skip all lines to first marker
            while fp and state < 2:
                offset = fp.tell()
                line = fp.readline()
                if not line: break

                line = line.strip()
                if not line: continue

                # Log.Debug("1: got line: ", line)
                if line.startswith(Config.HOSTS_MARKER_LINE):
                    self._offset_first_marker = offset
                    found_first_marker = True
                    Log.Debug(" ... seen all state 1 lines, now inside blockhosts markers at offset ", offset)
                    state = 2

            if not found_first_marker:
                raise MissingMarkerError

            # read all lines to second marker, fill in watched_hosts
            state = self._process_state_2(fp, logoffsets, line)

            # read all lines from second marker to end of file
            if fp and state == 3:
                Log.Info(" ... loaded %s, starting counts: blocked %d, watched %d" % (self._blockfile, len(self._blocked_ips), len(self._watched_hosts)))
                self._remaining_lines = fp.readlines()

            fp.close()

        except IOError, e:
            Log.Error("could not read block-file, last state: ", state)
            state = 0
            raise

        Log.Debug("block-file: Got initial watched hosts data:")
        Log.Debug(self._watched_hosts )
        Log.Debug("-------------------")
        Log.Debug("block-file: Got remaining lines:")
        Log.Debug(self._remaining_lines)
        Log.Debug("-------------------")

        return state > 2

    # --------------------------------
    def _process_state_2(self, fp, logoffsets, line):
        state = 2
        logfile = ""

        found_second_marker = False
        while fp and state == 2:
            line = fp.readline()
            if not line: break

            # bh: first line may contain trailing spaces, strip() removes
            # leading and trailing spaces, remember this when comparing
            line = line.strip()
            if not line: continue

            if line.startswith(Config.HOSTS_MARKER_LINE):
                found_second_marker = True
                state = 3
            elif line.startswith(Config.HOSTS_MARKER_LOGFILE):
                logfile = line[ len(Config.HOSTS_MARKER_LOGFILE) : ]
                logfile = logfile.strip()
                Log.Debug("2: found logfile name line: ", logfile)
                logoffsets[ logfile ] = SystemLogOffset()
            elif line.startswith(Config.HOSTS_MARKER_OFFSET) or line.startswith(Config.HOSTS_MARKER_FIRSTLINE):
                if logfile:
                    logoffsets[logfile].load_string(line)
                else:
                    Log.Warning("... log file name not known, ignoring offset or first_line info: ", line)
            elif line.startswith(Config.HOSTS_MARKER_WATCHED):
                line = line[ len(Config.HOSTS_MARKER_WATCHED) : ]

                # While : is a IPv6 address character, we can still use spaces around it,
                # like " : " to keep the blockhosts internal lines, and split using that.
                name, value = line.split(" : ", 1)
                if not name: return state # all done reading watched IPs

                name = name.strip()
                if not Config.HOST_IP_REOBJ.match(name): 
                    Log.Error("ignoring watched IP line, invalid IP '%s'" % (name))
                    continue

                self._watched_hosts[name] = HostData(1, Config.START_TIME)

                if ":" in value:
                    value, datestr = value.split(":", 1)
                    # Version 2.6.0 added a float number followed by #,
                    # if # found, then only need first number - epoch seconds
                    datestr = datestr.split("#", 1)[0]
                    datestr = datestr.strip()
                    try:
                        self._watched_hosts[name].count = int(value)
                    except ValueError, e:
                        Log.Error("failed to parse count for ip %s, using 1:\n  " % (name), e)

                    try:
                        if Config.PRE104_STRFTIME_RE.match(datestr):
                            # is old date format, remove in 2008 or later
                            self._watched_hosts[name].time = time.mktime(time.strptime(datestr, Config.PRE104_STRFTIME))
                        elif Config.PRE260_STRFTIME_RE.match(datestr):
                            # is old date format, remove in 2012 or later?
                            self._watched_hosts[name].time = time.mktime(time.strptime(datestr, Config.PRE260_STRFTIME))
                        else:
                            # is new date format, epoch secs. strptime keeps
                            # breaking, fails to read %Z written by strftime,
                            # so don't depend on strptime at all.
                            self._watched_hosts[name].time = float(datestr)
                    except ValueError, e:
                        # strange: could not read date that blockhosts.py wrote?
                        # either file was manually edited, or time.strptime
                        # cannot read what time.strftime wrote out to blockfile.
                        Log.Warning("failed to parse date for ip %s, using default time, error was:\n  " % (name), e)

                    Log.Debug("2: got host-count-date ", name, value, self._watched_hosts[name].time)

                else:
                    Log.Warning("2: invalid line, no date, just count", name, value)
                    self._watched_hosts[name].count = int(value)
            else:
                # not a blockhosts line, but in between blockhosts markers
                # this is a blocked host, store its ip address
                host = self._find_blockline_host(line)
                if host:
                    self._blocked_ips.append(host)
                    Log.Debug("2: found blocked host: %s" % host)
                else:
                    Log.Error("Expected to find group <ip> in match: ", line)

        if not found_second_marker:
            raise SecondMarkerError

        return state

    # --------------------------------
    def _increment_host(self, host):
        try:
            stat = self._watched_hosts[host]
        except KeyError:
            self._watched_hosts[host] = HostData()
            stat = self._watched_hosts[host]
            Log.Debug(" ... First failed connect, created host entry ", host)

        stat.count += 1
        stat.time = Config.START_TIME
        # date time is aggresive - exact would be to parse the log line,
        # but that much accuracy is not necessary
        return stat

    # --------------------------------
    def update_hosts_lists(self, config, filters):
        """Update blocked and watched list by calling the list of plugins"""
        self._blocked_ips = []
        for filter in filters:
            Log.Debug("calling hosts filter ", filter)
            filter(config, self._blocked_ips, self._watched_hosts)

        return(self._blocked_ips, self._watched_hosts)

    # --------------------------------
    def update_hosts_blockfile(self, logoffsets, load_only = False):

        lines = []

        #Log.Debug(" here are new hosts from get_deny_hosts:", self._blocked_ips)

        # first collect all the lines that will go in the blockhosts
        # section of blockfile - this is stored in lines[]
        status = False

        lines.append("%s\n" % Config.HOSTS_MARKER_LINE) # first marker line

        # blocked hosts
        for host in self._blocked_ips:
            lines.append(self._make_blockline(host))
            lines.append("\n")

        if self._blocked_ips: lines.append("\n")

        # watched hosts
        Log.Debug("Collecting watched_hosts counts info for block-file")
        hosts = sort_by_value(self._watched_hosts, reverse = True)
        for host in hosts:
            nsecs = self._watched_hosts[host].time
            date = time.localtime(nsecs)
            date = time.strftime(Config.ISO_STRFTIME, date)
            # Using " : " as markers, not just : since : is part of IPv6 address
            lines.append("%s %15s : %3d : %.1f # %s\n" % (Config.HOSTS_MARKER_WATCHED, host, self._watched_hosts[host].count, nsecs, date))
            # Log.Debug("adding line to blockfile: ", host)

        if len(self._watched_hosts) > 0: lines.append("\n")

        # log file offset recording for next time around
        Log.Debug("Collecting log file offset info for block-file")
        files = logoffsets.keys()
        for name in files:
            lines.append("%s %s\n" % (Config.HOSTS_MARKER_LOGFILE, name))
            lines.append(logoffsets[name].dump_string())

        lines.append("%s\n" % Config.HOSTS_MARKER_LINE) # second marker line
        lines = lines + self._remaining_lines;

        Log.Info(" ... final counts: blocked %d, watched %d" % (len(self._blocked_ips), len(self._watched_hosts)))
        if load_only:
            sys.stdout.writelines(lines)
            return True

        # update blockfile with blocked/watched hosts 
        # open file in read/write mode
        try:
            fp = open(self._blockfile, "r+")
            try:
                if self._offset_first_marker > -1:
                    # have seen first marker, go to start of first marker
                    fp.seek(self._offset_first_marker)
                else:
                    # no marker, go to end of existing file
                    # may not come here, depends on if not seeing a marker
                    # was considered an error in the load_hosts_blockfile function,
                    # but if it does come here, then don't overwrite any
                    # existing data
                    fp.seek(0, 2)
                    Log.Debug(" no hosts marker found, positioning for writing at end of '%s'" % self._blockfile)

                fp.writelines(lines)
                fp.truncate()
                status = True

            finally:
                fp.close()
        except IOError, e:
            traceback.print_exc()
            Log.Error("Could not update blockfile ", self._blockfile)

        return status

    # --------------------------------

    def set_all_reobjs(self, all_regexs, enable_rules, ignore_duplicates=False):
        """Create the list of compiled patterns to search the log lines."""

        enable_reobj = re.compile(enable_rules)
        Log.Debug("   ... enabled (+) and disabled (-) patterns:   ")
        for (name, regex) in all_regexs.iteritems():
            # compile all regular expression patterns
            if enable_reobj.match(name):
                expanded = BlockHostsConfig.expand_regex_keywords(regex)
                self._all_reobjs[name] = re.compile(expanded)
                Log.Debug("   + ", name, expanded)
            else:
                Log.Debug("   - ", name)

        # if trying to ignore duplicate log messages for same attempt,
        # keep a dict of pattern names in a dict of IP-PIDs
        if ignore_duplicates:
            self._ip_pid = {} 
        else:
            self._ip_pid = None 


    # --------------------------------
    def _count_failed_access(self, m, host, pattern_name):
        """Tries to ignore multiple log lines that may refer
        to same login attempt. Probably only happens with
        SSHD-Fail and SSHD-Invalid matches printed for same attempt,
        for some sshds. It is probably ok to count duplicates anyway,
        so this is not really necessary, should always return True."""

        count = True # default is to count this failed access

        # check if config says don't do this, based on if ip_pid is a dict
        if self._ip_pid is None:
            return count

        # ok to have no pid in the log line
        pid = None
        try:
            pid = m.group("pid")
        except IndexError:
            pass

        # if this hostip and processid already seen before,
        # then this attempt has already been counted, don't
        # double count, break out of here.  This may happen with both
        # SSHD-Fail and SSHD-Invalid match printed for same attempt.
        # Need to handle cases of multiple duplicates, so somewhat complicated.
        # Keep track of counts of each pattern matched. If the max count changes,
        # then this is a new failed access, otherwise not, for this IP-PID key.
        if pid:
            ip_pid_key = host + "-" + pid
            try:
                names = self._ip_pid[ip_pid_key]
            except KeyError:
                names = self._ip_pid[ip_pid_key] = { pattern_name : 0 }
            current_max = max(names.values())

            try:
                names[pattern_name] += 1
            except KeyError:
                names[pattern_name] = 1
            new_max = max(names.values())

            if new_max <= current_max:
                count = False
                Log.Debug("      ignoring duplicate failure line:", pattern_name, ", IP-pid:", ip_pid_key)

        return count

    # --------------------------------

    def match_line(self, line):
        """Check if the log line matches, & update the BlockHosts IP count"""

        matched = False
        for (name, reobj) in self._all_reobjs.iteritems():
            m = reobj.search(line)
            if m:
                try:
                    host_v4 = m.group("IPv4")
                    host_v6 = m.group("IPv6")
                except IndexError:
                    Log.Error("** Program error: pattern matched line:\n%s\n  but no 'IPv4 or IPv6' group defined in regex: '%s'" % (line, name))
                    raise

                host = (host_v4 or host_v6)

                if host is None:
                    Log.Error("** Program error: did not find IP address in line:\n%s\n   regex: '%s'" % (line, name))
                    continue

                # if we can count this failure (not a duplicate message for a single
                # failed login attempt), then consider this matched.
                if self._count_failed_access(m, host, name):
                    matched = (host, self._increment_host(host))
                    Log.Debug("    found failed access for ", name, ", IP:", host)
                else:
                    self.ignored_failures_count += 1

                break

        return matched

    # --------------------------------
    def get_hosts_lists(self):
        """Return list of blocked hosts, and a dict of watched hosts.
        
        First list is of all IP addresses being blocked, and second dict
        has IP as the key and HostData as value which contains count
        and last seen.
        """

        return (self._blocked_ips, self._watched_hosts)

    # --------------------------------
    def _make_blockline(self, host):
        """For the given host, return the appropriate IPv4 or IPv6 blockline """

        if Config.HOST_IPv4_REOBJ.match(host): 
            line = self._blockline_ipv4[0] + host + self._blockline_ipv4[1]
        else:
            line = self._blockline_ipv6[0] + host + self._blockline_ipv6[1]

        return line

    # --------------------------------
    def _find_blockline_host(self, line):
        """From the given line, return the appropriate IPv4 or IPv6 host """

        host = None
        index = None
        if (line.startswith(self._blockline_ipv4[0])
                and line.endswith(self._blockline_ipv4[1])):
            index = len(self._blockline_ipv4[0])
            end = line.rfind(self._blockline_ipv4[1])
            ipstr = line[index:end].strip()
            m = Config.HOST_IPv4_REOBJ.search(ipstr)
            if m:
                try:
                    host = m.group("IPv4")
                    return host
                except IndexError:
                    host = None # ignore error, look for IPv6

        if (line.startswith(self._blockline_ipv6[0])
                and line.endswith(self._blockline_ipv6[1])):
            index = len(self._blockline_ipv6[0])
            end = line.rfind(self._blockline_ipv6[1])
            ipstr = line[index:end].strip()
            m = Config.HOST_IPv6_REOBJ.search(ipstr)
            if m:
                try:
                    host = m.group("IPv6")
                    # maybe not needed.... if is_IPv6_address(host):
                    return host
                except IndexError:
                    host = None # suppress error, will check next

        if index:
            # We found a candidate line, but no address
            Log.Error("expected a IPv4 or IPv6 valid address in blockline match '%s'" % line)
        else:
            # We did not find a candidate line
            Log.Warning("Unrecognized line found between blockhosts markers: ", line)

        return None


# ======================= FILTERS ========================

class HostsFilters:
    """These functions all filter the watched and/or blocked lists based
       on their own criteria. They read their required configuration
       values from config, and will scan and update blocked and watched lists.

       [This uses classmethods now, but could be moved into a separate
       file and use module level methods.]
   """

    # --------------------------------
    def prune_watched_by_date(cls, config, blocked_ips, watched_hosts):
        """Prune watched list based on age, blocked is untouched"""

        prune_time = config.START_TIME - config["discard"]*60*60

        Log.Info(" ... discarding all entries older than %.1f %s" % (prune_time, time.strftime(Config.ISO_STRFTIME, time.localtime(prune_time))))

        ips = sort_by_value(watched_hosts, reverse = True)
        for ip in ips:
            data = watched_hosts[ip]
            # first remove all records that are considered old/expired
            # use <= instead of <, to allow --discard=0 to remove all hosts
            if data.time <= prune_time:
                Log.Notice("removing expired host: %15s " % ip, data)
                del watched_hosts[ip]

    prune_watched_by_date = classmethod(prune_watched_by_date)

    def add_blocked_by_count(cls, config, blocked_ips, watched_hosts):
        """Watched list hosts added to blocked list based on count"""

        count_threshold = config["blockcount"]
        for ip in sort_by_value(watched_hosts, reverse = True):
            data = watched_hosts[ip]
            # check if number of invalid attempts exceeds threshold
            if data.count > count_threshold:
                blocked_ips.append(ip)
                # for logging, check if this host was just blocked
                # floating point compare, epsilon is 0.1 seconds
                if data.time >= (config.START_TIME - 0.1):
                    Log.Notice("count=%d, blocking host: %15s " % (data.count, ip))

    add_blocked_by_count = classmethod(add_blocked_by_count)

    def add_blocked_blacklist(cls, config, blocked_ips, watched_hosts):
        """Add blacklisted hosts to the blocked list, watched list untouched"""
        blacklist = config["blacklist"].split(",")
        for ip in blacklist:
            # ip could be a ip address or a regular expression for an ip addr
            ip = ip.strip()
            Log.Debug(" add_blocked_blacklist: testing ip: '%s'" % ip)
            if Config.HOST_IP_REOBJ.match(ip):
                # if there are any non-regular expression IPs in blacklist,
                # immediately add them to the blocked_ips
                blocked_ips.append(ip)
                Log.Notice("blacklist: blocking host: %15s" % ip)
            else:
                # not an IP address, so treat it as a regular expression
                # if any of the regular expressions in blacklist match
                # a watched host, immediately add it to the blocked list
                try:
                    test = re.compile("^" + ip + "$")
                except re.error, e:
                    Log.Error("blacklist option: regexp '%s' failed to compile: " % (ip), e)
                    raise

                for watched in watched_hosts:
                    if test.match(watched) and watched not in blocked_ips:
                        blocked_ips.append(watched)
                        Log.Notice("blacklist: blocking watched host: %15s, matched '%s'" % (watched, ip))

    add_blocked_blacklist = classmethod(add_blocked_blacklist)

    # remove_watched_whitelist
    # check if any of the watched addresses should be removed 
    # another option is to apply whitelist on blocked list - that
    # way it can be applied before or after the blacklist filter
    def remove_watched_whitelist(cls, config, blocked_ips, watched_hosts):
        """Remove whitelisted hosts from the watched list only"""
        whitelist = config["whitelist"].split(",")
        # TODO: if watched list is much larger than whitelist, may be
        # better to flip the 2-level nested loop below
        for ip in whitelist:
            try:
                test = re.compile("^" + ip + "$")
            except re.error, e:
                Log.Error("whitelist option: regexp '%s' failed to compile: " % (ip), e)
                raise

            for watched in watched_hosts.keys():
                if test.match(watched):
                    count = watched_hosts[watched].count
                    del watched_hosts[watched]
                    Log.Notice("whitelist: removing watched host: %15s, count=%d, matched '%s'" % (watched, count, ip))

    remove_watched_whitelist = classmethod(remove_watched_whitelist)

    # remove_blocked_whitelist
    # check if any of the blocked addresses should be removed 
    # another option is to apply whitelist on watched list - that
    # way IP can be removed from watch list and not be continually
    # re-added to blocked list when count is exceeded
    def remove_blocked_whitelist(cls, config, blocked_ips, watched_hosts):
        """Remove whitelisted hosts from the blocked list only"""
        whitelist = config["whitelist"].split(",")
        # TODO: if blocked_ips list is much larger than whitelist, may be
        # better to flip the 2-level nested loop below
        for ip in whitelist:
            try:
                test = re.compile("^" + ip + "$")
            except re.error, e:
                Log.Error("whitelist option: regexp '%s' failed to compile: " % (ip), e)
                raise

            for blocked in blocked_ips[:]:
                if test.match(blocked):
                    blocked_ips.remove(blocked)
                    Log.Notice("whitelist: removing blocked host: %15s, matched '%s'" % (blocked, ip))

    remove_blocked_whitelist = classmethod(remove_blocked_whitelist)


class HostsFiltersConfig(ConfigSection):
    """Manage setup related to filtering blocked and watched list. """

    # Defaults, hard-coded options, these values are used last if no args
    # and no values in config file
    HC_OPTIONS = {
        "COUNT_THRESHOLD": 7,
            # number of invalid attempts after which host is blocked
            # note that actual denial make take one or more attempts - depends
            # on the timing of when LOGFILES are updated by the system,
            # and when this script gets to run

        "AGE_THRESHOLD": 12,
            # number of hours after which host entry is discarded from
            # hosts.allow 24 -> one day, 168 -> one week, 720 -> 30 days,
            # integer values only most attackers go away after they
            # are blocked, so to keep hosts.allow file size small,
            # no reason to make this any more than, say, half-a-day

        "WHITELIST": ("127.0.0.1",),
            # A list of IP (IPv4 or IPv6) addresses or regular expressions that
            # represent a IP address - this is the list of
            # white-listed IP addresses.

        "BLACKLIST": (),
            # blacklist IPv4 or IPv6 addresses or regular expressions
    }

    NAME = "filters"  # config file section name is [NAME]

    def setup_options(self, oparser, config):
        """Update the parser with values for defaults and option parsing

           Calls add_option for all the options used by mail process
        """

        oparser.set_defaults(
            blockcount=config["COUNT_THRESHOLD"],
            discard=config["AGE_THRESHOLD"],
            whitelist=",".join(config["WHITELIST"]),
            blacklist=",".join(config["BLACKLIST"]),
            )

        defaults = oparser.get_default_values()

        oconfig = OptionGroup(oparser, "Blocking and watching IP lists filtering",
            """These options apply to the pruning and updating of the blocked
and watched lists of IP addresses.
""")

        oconfig.add_option("--blockcount", metavar="COUNT", type="int",
            help="Number of invalid tries allowed, before blocking host (%d).  Integer values only." % defaults.blockcount)

        oconfig.add_option("--discard", type="int", metavar="AGE",
            help="Number of hours after which to discard record - if most recent invalid attempt from IP address is older, discard that host entry (%d).  Integer values only." % defaults.discard)

        # whitelist/blacklist handled specially - since optparse can't do
        # eval(), and I did not want to add a new optparse type, command
        # line arg for logfiles only accepts string, unlike the config file,
        # which accepts the full python syntax - list elements, characters
        # escaped as needed, etc.  Therefore, command line is one string
        # separated by ",", while config file is a python list with multiple
        # IP addresses or regular expressions

        oconfig.add_option("--whitelist", type="string", metavar="IP1,IP2,...",
            help="A list of IP (IPv4 or IPv6) addresses or regular expressions that represent a IP. When considering IPs to block, if that IP address matches any item in this list, then it will be rejected for the block list - never blocked. ('%s')" % defaults.whitelist)

        oconfig.add_option("--blacklist", type="string", metavar="IP1,IP2,...",
            help="When considering IPs to block, if that IP address matches any item in this list, then it will be immediately added to the block list, even if blockcount/COUNT_THRESHOLD may not have been reached.  IP addresses directly specified in this list without using a regular expression will be immediately added to the blocked list.  The whitelist takes precedence over blacklist - so a match in both will mean it is white-listed. ('%s')" % defaults.blacklist)

        oparser.add_option_group(oconfig)

# ======================= MAIN ========================

def main(args=None):
    """Collect args, open block-file, search log files, block IP addresses"""

    Log.OpenSysLog()

    if args is None:
        args = sys.argv[1:]

    config = Config(args, VERSION, LONG_DESCRIPTION)

    config.add_section(CommonConfig())
    config.add_section(BlockHostsConfig())
    config.add_section(HostsFiltersConfig())
    config.add_section(MailConfig())
    config.add_section(IPBlockConfig())

    try:
        rest_args = config.parse_args()
    except InvalidOptionError:
        return 2

    Log.SetPrintLevel(config["verbose"])

    # --------------------------------
    Log.Info("%s %s started: %s" % (SCRIPT_ID, VERSION, Config.START_TIME_STR))

    Log.Debug("Debug mode enabled.")
    Log.Debug("Got config and options:", config)

    if config["echo"]:
        Log.Info(" ... echo tag: %s" % config["echo"])

    if rest_args:
        Log.Warning("ignoring positional arguments - there should be none!", rest_args)

    load_only = config["load_only"] 
    dry_run = config["dry_run"]

    if (load_only or dry_run):
        Log.EnableSysLog(False)

    # --------------------------------
    if not (load_only or dry_run):
        lock = LockFile(config["lockfile"])
        try:
            lock.lock()
        except IOError, e:
            if e.errno == errno.EAGAIN:
                msg = "Exiting: another instance running? '%s' already locked" % lock.get_path()
                Log.Info(msg)
                return 1
            else:
                Log.Error("Lock error: file '%s', failed to get lock." % lock.get_path())
                raise

        Log.Debug("File lock obtained '%s' for excluding other instances" % lock.get_path())

    # --------------------------------
    # load block file data with current list of blocked and watched hosts

    dh = BlockHosts(config["blockfile"], config["blockline_ipv4"], config["blockline_ipv6"])
    prev_logoffsets = {}
    new_logoffsets = {}

    try:
        dh.load_hosts_blockfile(prev_logoffsets)
    except (MissingMarkerError, SecondMarkerError):
        Log.Error("Failed to load blockfile - block-file marker error\n Expected two marker lines in the file, somewhere in the middle of the file:\n%s\n%s\n" % (Config.HOSTS_MARKER_LINE, Config.HOSTS_MARKER_LINE))
        raise
    except:
        Log.Error("Failed to load blockfile, unexpected error")
        raise

    # --------------------------------
    # scan logfiles for IP hosts illegally accessing services, update
    # host IP access failure counters 

    if load_only:
        logfiles = ""
    else:
        logfiles = config["logfiles"].split(",")
        # compile all regular expression patterns
        dh.set_all_reobjs(config["ALL_REGEXS"], config["enable_rules"], config["IGNORE_DUPLICATES"])


    for logfile in logfiles:
        Log.Debug(" ------- looking into log file: ", logfile)
        sl = SystemLog(logfile)

        offset = SystemLogOffset(0,"")
        if not config["ignore_offset"]:
            if logfile in prev_logoffsets:
                offset = prev_logoffsets[logfile]
            else:
                if prev_logoffsets:
                    Log.Warning("no offset found, will read from beginning in logfile:", logfile)
                else:
                    Log.Info("no logoffsets found, will read from beginning in logfile:", logfile)

        sl.open(offset)

        while 1:
            line = sl.readline()
            if not line: break

            line = line.strip()
            if not line: continue

            dh.match_line(line)

        sl.close()

        new_logoffsets[logfile] = sl.get_offset()

        Log.Debug(" ------- finished looking into log file: ", logfile)

    # --------------------------------
    # prune hosts list, determine new blocked and watched lists

    if not load_only:
        Log.Debug(" ------- collecting block file updates --- ")
        dh.update_hosts_lists(config,
            [
                HostsFilters.prune_watched_by_date,
                HostsFilters.remove_watched_whitelist,
                HostsFilters.add_blocked_by_count,
                HostsFilters.add_blocked_blacklist,
                HostsFilters.remove_blocked_whitelist,
            ]
        )

    # collect data for mailing and/or ip blocking
    (blocked, watched) = dh.get_hosts_lists()

    if dh.ignored_failures_count > 0:
        Log.Notice("ignored duplicate log lines: ", dh.ignored_failures_count)

    if not load_only:
        Log.Debug(" ------- writing final blocked/watched list --- ")
        # update the blockfile or print to stdout based on dry_run
        dh.update_hosts_blockfile(new_logoffsets, dry_run)
        if not dry_run: lock.unlock()

    # ---- use routing or filtering to block ip addresses
    if config["ipblock"]:
        do_ipblock(config, blocked)

    # ---- send mail
    if config["mail"]:
        do_mail(config, blocked, watched)

    return 0

# --------------------------------
if __name__ == '__main__':
    sys.exit(main())
