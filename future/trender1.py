''' 
simple2.py  - Demonstrate simple trender.
'''

#--- standard Python modules ---
import time

#--- 3rd party modules ---

#--- this application's modules ---
import BACnet

#------------------------------------------------------------------------------

'''
Given:
- base-case: 15 min polled.  
- time resolution is 15 min.  aka 
    0:00:00 - 0:14:59 = 0:00 <value>
    0:15:00 - 0:29:59 = 0:15 <value>
- reduced precision: 1 decimal place. (xx.x) [??needed]
- one sample per interval.  any time within interval is deemed = to interval start.  
- time-length compression.  like COV on fixed intervals.  Graphed as a square-wave, not an 
    averaged slope (graph tools receive same value at segment start & end then the changed 
    value).  High compression ratio for infrequent values (setpoints, temperatures).  
    Worst-case = 1 sample/interval (i.e. 15 min/polled).  [1:1]
    Best-case = 1 sample/day bucket. [96:1]
    Expecting: compressions of
         4:1 (hourly) temperature, fan cycle    [24 samples]
        32:1 (twice daily) day/night SP change  [3 samples]
        96:1 (no change) static value           [1 sample]
    ___        ___        ____
       \__    |      ____/    \___    __/\_/\_
          \___|        
    0:00 <valueA>    00:00 <valueA>    10:00 <A>
    4:45 <valueB>    08:00 <valueB>    11:00 <B>
    5:00 <valueC>    17:30 <valueA>    12:00 <A>
    7:30 <valueA>
'''

'''
Simplistic Auto trender:
- WhoIs(universe)
- for all responses:   [beware WhoIs storm; dropped responses; ...]
    read device.DEV.objectList
    add all I/O,SCH,CO? to poll list
    
- every 15 min
    poll the poll list    [beware network overload]
    [ethernet: ~100 read/sec = 15min * 60 * 100 =  90K points]
    [MSTP: ~1 read/sec = 15min * 60 * 1 = 900 points]
    [Cube: 5000 TL/4 hrs= 4*3600 / 5000 = 0.3/sec]
    Target: 2500 points = [mix of enet/MSTP] = 3/sec

    - save current day Poll values to Pending db.

[in Background/CRON]:
- every 4hrs:
    - get Pending values. [mongoDB]
    - apply time-length compression
    - send to Kaizen
    - add to long-term database. [day bucket oriented mongoDB]
'''

'''
Better (friendlier) Auto trender:

- load existing Poll list [built-up over time]
- load device inclusion range
- prune Poll list to match Inclusion range [range may have changed]

- every 15|30 min:
    - poll Poll List
    - if a point times out - skip rest of device's points [retry next scan]
    - if total scan:
        < 15 min: [good] shift/keep scan interval @ 15 min.
        > 15 min: [bad] shift/keep scan interval @ 30 min.
        > 30 min: [very bad] reduce Poll list (drop N newest points). Complain??

[in background]
- whois(range [in 1000's])
- add new devices to device table
    read device.DEV.objectList
    add all I/O,SCH,CO? to poll list

[in Background/CRON]:
- every 4hrs:
    - get Pending values. [mongoDB]
    - apply time-length compression
    - send to Kaizen
    - add to long-term database. [day bucket oriented mongoDB]
'''

'''
Fixed trender:
- load user defined Poll list.
- every 15|30 min:
    - poll Poll List
    - if a point times out - skip rest of device's points [retry next scan]
    - if total scan:
        < 15 min: [good] shift/keep scan interval @ 15 min.
        > 15 min: [bad] shift/keep scan interval @ 30 min.
        > 30 min: [very bad] reduce Poll list (disable N last points). Complain??

[in Background/CRON]:
- every 4hrs:
    - get Pending values. [mongoDB]
    - apply time-length compression
    - send to Kaizen
    - add to long-term database. [day bucket oriented mongoDB]
'''


#------------------------------------------------------------------------------

bacnet= BACnet.connect()


props= ['objectName','vendorName','modelName','objectList']
vals= bacnet.read('2300.DEV2300',props)
print(vals)

while True:
    print('Scanning....')
    
    for obj in vals['objectList']:
        try:
            print('{}= {}'.format(obj,bacnet.read('2300.{}'.format(obj))))
        except:
            pass
    time.sleep(5)
    
pass
