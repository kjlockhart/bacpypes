''' 
simple1.py  - Demonstrate the usage of bacpypes in its simplest form.
'''

#--- standard Python modules ---
#--- 3rd party modules ---
#--- this application's modules ---

#------------------------------------------------------------------------------

import BACnet

bacnet= BACnet.BACnet()


# Simple Objects
#
value= bacnet.read('1000.AI1')        # read Present_Value of Device 1000's Analog Input #1
value= bacnet.read('1200.AO3')        # read Present_Value of Device 1200's Analog Output #3

#bacnet.write('2321.AV2',34.0)         # set Present_Value of Device 2321's Analog Value #2
