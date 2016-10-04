""" cMiniHomeNet example, connecting to RELAY and keeping session up, receiving messages

Run script unbuffered using python -u
"""
import time
from minihomenet import *

newConn = minihomenet()
if (newConn.login()):
	while True:
		newConn.run()
		time.sleep(0.2)

