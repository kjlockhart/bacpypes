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
value= bacnet.read('2300.AV1')        # read Present_Value of Device 2300's Analog Value #1
flag = bacnet.read('2300.AV1','Out_Of_Service')     # read one specific property

properties= ['Out_Of_Service','High_Limit','Low_Limit']
values= bacnet.read('2300.AV1',properties)        # read specific properties


value= bacnet.read('1200.AO3')        # read Present_Value of Device 1200's Analog Output #3

#bacnet.write('2321.AV2',34.0)         # set Present_Value of Device 2321's Analog Value #2
