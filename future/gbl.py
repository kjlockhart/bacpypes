''' globals.py - Global namespace
'''
#--- standard Python modules ---
import json
import logging
from logging.config import dictConfig

#--- 3rd party modules ---
#--- this application's modules ---

#------------------------------------------------------------------------------

logging_config = dict(
    version = 1,
    formatters = { 
        'f': {'format': '%(asctime)s %(name)s %(levelname)s: %(message)s'} 
        },
    handlers = {
        'h': {'class': 'logging.StreamHandler', 'formatter': 'f', 'level': logging.DEBUG}
        },
    root = { 'handlers': ['h'], 'level': logging.DEBUG },
)

dictConfig(logging_config)
LOGGER = logging.getLogger()


def load_config(fname):
    with open(fname,'r') as f:
        config= json.load(f)
    return(config)


def save_config(fname,config):
    with open(fname,'w') as f:
        json.dump(config,f,indent=4,sort_keys=True)
