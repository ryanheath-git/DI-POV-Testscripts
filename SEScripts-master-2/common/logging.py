import sys
import logging

LOGGING_LEVEL = logging.WARNING  # Modify if you just want to focus on errors
logging.basicConfig(level=LOGGING_LEVEL,
                    format='%(asctime)s %(levelname)-8s %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S',
                    stream=sys.stdout)

