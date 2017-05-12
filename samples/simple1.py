''' 
simple1.py  - Demonstrate the usage of bacpypes in its simplest form.
'''

#--- standard Python modules ---
#--- 3rd party modules ---
#--- this application's modules ---

#------------------------------------------------------------------------------

import BACnet
import time

bacnet= BACnet.connect()
#bacnet= BACnet.BACnet()


'''
# Simple Objects
#
value= bacnet.read('2300.AV1')        # read Present_Value of Device 2300's Analog Value #1
#flag = bacnet.read('2300.AV1','Out_Of_Service')     # read one specific property
flag = bacnet.read('2300.AV1','outOfService')     # read one specific property
'''

'''#properties= ['Out_Of_Service','High_Limit','Low_Limit']
properties= ['presentValue','outOfService','units','statusFlags']
values= bacnet.read('2300.AV1',properties)        # read specific properties
print(values)
'''
p= ['objectName','vendorName','modelName','objectList']
v= bacnet.read('2300.DEV2300',p)
print(v)

#for o in v['objectList']:
#    print(o)
    
while True:
    print('2300.AV28= ',bacnet.read('2300.AV28'))
    time.sleep(5)
    
    

print('1200.AI1=', bacnet.read('1200.AI1') )
print('2000.AI2=', bacnet.read('2000.AI2'))

#value= bacnet.read('1200.AO3')        # read Present_Value of Device 1200's Analog Output #3

#bacnet.write('2321.AV2',34.0)         # set Present_Value of Device 2321's Analog Value #2

pass
