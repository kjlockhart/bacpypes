''' 
fixed-trender1.py  - Demonstrate simple trender.
'''

#--- standard Python modules ---
import datetime
import time

#--- 3rd party modules ---
import pymongo      # MongoDB
import bson         # MongoDB's native data formats

#--- this application's modules ---
import BACnet
import gbl

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

if __name__ == '__main__':
    gbl.LOGGER.info('trender - starting')

    # Connect to MongoDB
    #dbMongo = pymongo.MongoClient(config.get('connectionStrings')['mongodb'])
    dbMongo = pymongo.MongoClient('mongodb://localhost')
    dbWhoIs = dbMongo['ccConfig']['whois']
    dbIAm   = dbMongo['ccConfig']['iam']
    dbDevices = dbMongo['ccDevices']['Latest']
    dbPoints  = dbMongo['ccPoints']['Latest']
    dbTrends  = dbMongo['ccTrends']['Latest']
    #gbl.LOGGER.info('Connected: {}'.format(config.get('connectionStrings')['mongodb']))
    gbl.LOGGER.info('Connected: mongodb')


    bacnet= BACnet.connect()
    gbl.LOGGER.info('Connected: bacnet')

    ''' load user defined Poll list.
    '''
    try:
        props= ['objectName','vendorName','modelName','objectList']
        vals= bacnet.read('2300.DEV2300',props)
        print(vals)
    except:
        pass
    
    while True:
        gbl.LOGGER.info('Scan start...')
        scan_start= datetime.datetime.now()
        
        for obj in vals['objectList']:
            try:
                print('{}= {}'.format(obj,bacnet.read('2300.{}'.format(obj))))
            except:
                pass
            
        scan_done= datetime.datetime.now()
        duration= scan_done - scan_start
        gbl.LOGGER.info('Scan done. Duration={}'.format(duration))

        '''
            - if total scan:
                < 15 min: [good] shift/keep scan interval @ 15 min.
                > 15 min: [bad] shift/keep scan interval @ 30 min.
                > 30 min: [very bad] reduce Poll list (disable N last points). Complain??
        '''
        #nsec= 900 - duration
        nsec= max(15 - duration.total_seconds(),0)
        gbl.LOGGER.info('sleeping ({} secs)'.format(nsec))
        time.sleep(nsec)
        
        # periodically flush raw_device cache to mongodb
        for k,v in BACnet.raw_whois.items():
            dbWhoIs.update({'_id': k}, {"$set": v}, upsert=True, multi=False, w=1)

        # periodically flush raw_iam cache to mongodb
        for k,v in BACnet.raw_iam.items():
            dbIAm.update({'_id': k}, {"$set": v}, upsert=True, multi=False, w=1)
    
    pass
