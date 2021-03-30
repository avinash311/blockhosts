from os.path import dirname, isdir
from distutils.core import setup
from blockhosts import VERSION, DESCRIPTION, LONG_DESCRIPTION, AUTHOR, AUTHOR_EMAIL, LICENSE, URL, Config

# installs blockhosts.py in /bin or /usr/bin
# installs blockhosts.cfg usually in /etc (CONFIG_FILE)
# installs logrotate.d/blockhosts in /etc/logrotate.d

LOGROTATE_DIR = '/etc/logrotate.d'
LOGWATCH_SCRIPTS_DIR = '/etc/logwatch/scripts/services'
LOGWATCH_CONF_DIR = '/etc/logwatch/conf/services'

DATA_FILES=[(dirname(Config.HC_OPTIONS["CONFIGFILE"]), ['blockhosts.cfg'])]

if isdir(LOGROTATE_DIR):
    DATA_FILES.append((LOGROTATE_DIR, ['logrotate.d/blockhosts']),)

if isdir(LOGWATCH_SCRIPTS_DIR) and isdir(LOGWATCH_CONF_DIR):
    DATA_FILES.append((LOGWATCH_SCRIPTS_DIR, ['logwatch/blockhosts']),)
    DATA_FILES.append((LOGWATCH_CONF_DIR, ['logwatch/blockhosts.conf']),)
    
setup(name="BlockHosts",
      version=VERSION,
      description=DESCRIPTION,
      long_description=LONG_DESCRIPTION,
      author=AUTHOR,
      author_email=AUTHOR_EMAIL,
      url=URL,
      license=LICENSE,
      scripts=['blockhosts.py',],
      data_files=DATA_FILES,
     )
