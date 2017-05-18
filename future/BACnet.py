#!/usr/bin/python
# -*- coding: utf-8 -*-
#
# Copyright (C) 2017 by Ken Lockhart <klockhart@coppertreeanalytics.com>
# Licensed under LGPLv3, see file LICENSE in this source tree.
#
'''
BACnet.py - A user-friendly wrapper for bacpypes

A bacpypes is a BACnet communications protocol stack written in a purist Object-Oriented 
Programming System (OOPS).  To someone with a very strong Java background, this 
style will seem comfortable.  Other users (developers included) often find this style, 
makes learning to use bacpypes very challenging.  It should not be like this.  Using 
bacpypes to interact with BACnet devices should be an easy experience.  In-depth knowledge
of BACnet, its communication protocols, stack development, threads, and Object-oriented 
programming should not be required.  This wrapper hides all these details, and makes 
bacpypes easy to use, for even the non-technical user.

Usage:
    import BACnet
    bacnet= BACnet.connect()
    
    # Simple Objects
    #
    value= bacnet.read('1000.AI1')        # read Present_Value of Device 1000's Analog Input #1
    value= bacnet.read('1200.AO3')        # read Present_Value of Device 1200's Analog Output #3

    bacnet.write('2321.AV2',34.0)         # set Present_Value of Device 2321's Analog Value #2

    # Trend logs
    list= bacnet.read_trend('800.TL1',from_datetime,to_datetime)
        >>> list= [(timestamp,value),...]


Advanced usage:
    import BACnet
    bacnet= BACnet.connect()

    # Read - specific BACnet Object Properties.
    #
    flag= bacnet.read('1000.AI1','Out_Of_Service')     # read one specific property
        >>> flag = 1

    obj= bacnet.read('1100.BO1','_ALL')                # read all standard BACnet properties.
        >>> obj = {
                'Object_Identifier': '1100.BO1',
                'Object_Name': 'Equipment Enable relay',
                'Object_Type': 'Binary Output',
                'Present_Value': 23.5,
                ... }
                 
    properties= ['Out_Of_Service','High_Limit','Low_Limit']
    values= bacnet.read('1000.AI1',properties)        # read specific properties
        >>> values = {
               'Out_Of_Service': 1, 
               'High_Limit': 80,
               'Low_Limit': 20 }


    # Write -  specific BACnet Object Properties.
    #
    bacnet.write('2100.AV2',1,'Out_Of_Service')       # set one specific property
    
    properties= {
        'Object_Name': 'New name',
        'Description': 'changed by my program',
        'Present_Value': 100,
        'Out_Of_Service': 0  }
        
    bacnet.write('900.AV10',properties)       # set multiple specific properties

    # Exceptions
    try:
        bacnet.write('2100.AV2',1,'Out_Of_Service')       # set one specific property
    except IOError:
        print('Device is off-line')
    except NameError:
        print('Unknown property')
    except ValueError:
        print('Property Value rejected by destination device')
    except:
        print('Some other error')
    
'''
#--- standard Python modules ---
import subprocess
import ipaddress
import sys
from threading import Thread
import re
import datetime
import time

import logging
LOG = logging.getLogger('standard')


#--- 3rd party modules ---

#--- this application's modules ---
import bacpypes.core

#from bacpypes.primitivedata import CharacterString
from bacpypes.constructeddata import Array

from bacpypes.basetypes import ServicesSupported, DeviceStatus
from bacpypes.service.device import LocalDeviceObject
from bacpypes.app import BIPSimpleApplication

from bacpypes.iocb import IOCB

from bacpypes.pdu import Address, GlobalBroadcast

from bacpypes.apdu import PropertyReference, ReadAccessSpecification, \
    ReadPropertyRequest, ReadPropertyACK, \
    ReadPropertyMultipleRequest, ReadPropertyMultipleACK, \
    WhoIsRequest

from bacpypes.object import get_object_class, get_datatype

#--- this application's modules ---

#------------------------------------------------------------------------------

Obj_map= {
    'DEV': 'device',
    'AI': 'analogInput',
    'AO': 'analogOutput',
    'AV': 'analogValue',
    'BI': 'binaryInput',
    'BO': 'binaryOutput',
    'BV': 'binaryValue',
    'MI': 'multiStateInput',
    'MO': 'multiStateOutput',
    'MV': 'multiStateValue',
    'SCH': 'schedule',
    'ACC': 'accumulator'
    }

Obj_reverse= {
    'device': 'DEV',
    'analogInput': 'AI',
    'analogOutput': 'AO',
    'analogValue': 'AV',
    'binaryInput': 'BI',
    'binaryOutput': 'BO',
    'binaryValue': 'BV',
    'multiStateInput': 'MI',
    'multiStateOutput': 'MO',
    'multiStateValue': 'MV',
    'schedule': 'SCH',
    'accumulator': 'ACC' 
    }

Dev_map= {
    '1100': '192.168.87.67:49152',
    '1200': '20020:12',
    '2100': '192.168.87.11:47809',
    '2300': '192.168.87.48:47808',
    '3000': '20002:30',
    }

raw_whois= {}
raw_iam= {}


#------------------------------------------------------------------------------

class BACStack(BIPSimpleApplication):
    ''' bacpypes extensions.
    1. Learn about the BACnet devices visible on our BACnet network(s).
       Use the information we learn (status, routing connections, ...) to minimize 
       our network footprint
    '''  
    def __init__(self, device, address):
        print('BACStack init')
        BIPSimpleApplication.__init__(self, device, address)


    def do_WhoIsRequest(self, apdu):
        ''' Learn about existing devices from their Who-Is requests.
        '''
        key = (str(apdu.pduSource),apdu.deviceInstanceRangeLowLimit,apdu.deviceInstanceRangeHighLimit )
        print('WhoIs: ',key)
        
        src= str(apdu.pduSource)
        lo= apdu.deviceInstanceRangeLowLimit
        hi= apdu.deviceInstanceRangeHighLimit
        
        print('WhoIs: ',src,lo,hi)
        raw_whois[src]= {'ts': datetime.datetime.now() }

        BIPSimpleApplication.do_WhoIsRequest(self, apdu)    # continue with default processing


    def do_IAmRequest(self, apdu):
        ''' Learn about new devices from their I-Am announcements.
        '''
        src= apdu.pduSource
        id= apdu.iAmDeviceIdentifier[1]
        maxlen= apdu.maxAPDULengthAccepted
        seg= apdu.segmentationSupported
        vendor= apdu.vendorID 
        
        key = (str(apdu.pduSource), apdu.iAmDeviceIdentifier[1])
        i_am[key] += 1

        print('{} IAm({})- vendor={} maxlen={},{} '.format(src,id,vendor,maxlen,seg))
        BIPSimpleApplication.do_IAmRequest(self, apdu)      # continue with default processing


#------------------------------------------------------------------------------

class Stack(Thread):
    ''' Wrap bacpypes into its own thread.  Configure as a simple device.  
        Hide as much of its complexity as possible. Expose only a simple 
        intuitive interface.
        
        TODO: allow settings override from a JSON ini file.
    '''
    def __init__(self):
        print('init')
        Thread.__init__(self)
        self.name= 'BACnet'

        self.devId = 4000000
        self.ip_addr= get_hostIP() 

        self.systemStatus = DeviceStatus(1)
        
        print('Create our Local Device')
        self.this_device = LocalDeviceObject(
            objectIdentifier= self.devId,
            objectName= 'BACnet bacpypes',
            vendorIdentifier= 574,
            vendorName= 'CopperTree Analytics',
            modelName= 'BACnet library',
            description= '',
            firmwareRevision= '0.15',
            applicationSoftwareVersion= '1.0',
            systemStatus= self.systemStatus,
            #maxApduLengthAccepted=int(self.maxAPDULengthAccepted),
            #segmentationSupported=self.segmentationSupported,
            protocolVersion=1,
            protocolRevision=14,
            #protocolObjectTypesSupported=
            databaseRevision= 0 )

        '''
        # State the BACnet services we support
        pss = ServicesSupported()
        pss['whoIs'] = 1
        pss['iAm'] = 1
        pss['readProperty'] = 1
        pss['writeProperty'] = 1
        pss['readPropertyMultiple'] = 1
        self.this_device.protocolServicesSupported = pss.value
        '''
        self.this_application= BACStack(self.this_device, self.ip_addr)

        services_supported = self.this_application.get_services_supported()
        self.this_device.protocolServicesSupported = services_supported.value


    def run(self):
        bacpypes.core.enable_sleeping()
        bacpypes.core.run()
        
    
    def read(self,oref,props='presentValue'):
        ''' BACnet read
        '''
        print('read',oref,props)
        
        [(devId,t,i)]= re.findall('(\d+).(\D+)(\d+)',oref)

        if devId not in Dev_map:
            dic= self.whois(devId)
            Dev_map[devId]= dic
        
        dstAddr= Dev_map[devId]
        oType= Obj_map[t]
        #query= [dstAddr,oType,int(i),'presentValue']
        query= [dstAddr,oType,int(i),props]
        
        if isinstance(props, str):
            value= self._readProperty(query)
            return value
        else:
            values= self._readMultiple(query)
            
            # Hack
            if values['objectList']:
                lst= []
                for obj in values['objectList']:
                    try:
                        l= '{}{}'.format(Obj_reverse[obj[0]], obj[1])
                        lst.append(l)
                    except:
                        #l= 'UNK{}'.format(obj[1])
                        pass
                values['objectList']= lst
            
            return values


    def write(self,oref):
        ''' BACnet write
        '''
        print('write',oref)
        pass


    #--------------------------------------------------------------------------

    def whois(self, deviceId):
        ''' Find the network address of the device with the given Device Identifier.
            Broadcast this request to the entire BACnet internetwork.
        '''
        request = WhoIsRequest()
        request.pduDestination = GlobalBroadcast()
        request.deviceInstanceRangeLowLimit = int(deviceId)
        request.deviceInstanceRangeHighLimit = int(deviceId)
        print("    - request: %r" % request)

        iocb = IOCB(request)                            # make an IOCB
        self.this_application.request_io(iocb)          # pass to the BACnet stack

        iocb.wait()                                     # Wait for BACnet response

        if iocb.ioResponse:     # successful response
            apdu = iocb.ioResponse
            if not isinstance(apdu, IAmRequest) and not isinstance(apdu, WhoIsRequest):
                print(WhoisIAm,"    - not an ack")
                return

            # find the datatype
            datatype = get_datatype(apdu.objectIdentifier[0], apdu.propertyIdentifier)
            print("    - datatype: %r", datatype)
            if not datatype:
                raise TypeError("unknown datatype")

            dic= {
                'id': '',
                'maxAPDU': 480,
                'segSupported': False,
                'vendorId': 1
                }
            return dic

        if iocb.ioError:        # unsuccessful: error/reject/abort
            pass

    #--------------------------------------------------------------------------

    '''
    @property
    def devices(self):
        lst = []
        #self.whois()
        #print(self.discoveredDevices)
        for device in self.discoveredDevices:
            try:
                deviceName, vendorName = self.readMultiple('%s device %s objectName vendorName' % (device[0], device[1]))
                lst.append((deviceName, vendorName, device[0], device[1]))
            except NoResponseFromController:
                #print('No response from %s' % device)
                continue
        return pd.DataFrame(lst, columns=['Name', 'Manufacturer', 'Address',' Device ID']).set_index('Name').sort_values('Address')
    '''

    def _readProperty(self,args):
        """
        Build a ReadProperty request, wait for the answer and return the value
            query= ['192.168.87.48:47808','analogValue',1,'presentValue']
        """
        addr,oType,oInst,prop= args[:4]
        
        if oType.isdigit():
            oType = int(oType)
        elif not get_object_class(oType):
            raise ValueError("unknown object type")

        datatype = get_datatype(oType, prop)
        if not datatype:
            raise ValueError("invalid property for object type")

        request = ReadPropertyRequest(
            objectIdentifier=(oType, oInst), propertyIdentifier= prop, propertyArrayIndex= None )
        request.pduDestination = Address(addr)

        try:
            iocb = IOCB(request)                                    # build ReadProperty request
            self.this_application.request_io(iocb)                  # pass to the BACnet stack
        except Exception as e:
            LOG.exception("exception: %r", e)                       # construction error

        iocb.wait()             # Wait for BACnet response

        if iocb.ioResponse:     # successful response
            apdu = iocb.ioResponse
            if not isinstance(apdu, ReadPropertyACK):               # expecting an ACK
                raise IOError('Read- not an ack')

            datatype = get_datatype(apdu.objectIdentifier[0], apdu.propertyIdentifier)
            if not datatype:
                raise TypeError("unknown datatype")

            # special case for array parts, others are managed by cast_out
            if issubclass(datatype, Array) and (apdu.propertyArrayIndex is not None):
                if apdu.propertyArrayIndex == 0:
                    value = apdu.propertyValue.cast_out(Unsigned)
                else:
                    value = apdu.propertyValue.cast_out(datatype.subtype)
            else:
                value = apdu.propertyValue.cast_out(datatype)

            return value

        if iocb.ioError:        # unsuccessful: error/reject/abort
            print('BACnet error: ', iocb.ioError)
            raise IOError()


    def _readMultiple(self, args):
        """ Build a ReadPropertyMultiple request, wait for the answer and return the values

        :param args: String with <addr> ( <type> <inst> ( <prop> [ <indx> ] )... )...
        :returns: data read from device (str representing data like 10 or True)

        *Example*::

            value= bacnet.read('1000.AI1')                     # read Present_Value
        >>> value = 32.56
            flag= bacnet.read('1000.AI1','Out_Of_Service')     # read one specific property
        >>> flag = 1
            obj= bacnet.read('1100.BO1','_ALL')                # read all standard BACnet properties.
        >>> obj = {
                'Object_Identifier': '1100.BO1',
                'Object_Name': 'Equipment Enable relay',
                'Object_Type': 'Binary Output',
                'Present_Value': 23.5,
                ... }
        """
        print('readMultiple({})'.format(args))

        specs= []
        for p in args[3]:
            prop= PropertyReference(propertyIdentifier= p)
            specs.append(ReadAccessSpecification(
                            objectIdentifier=(args[1],args[2]),
                            listOfPropertyReferences= [prop] ))
            
        request = ReadPropertyMultipleRequest(listOfReadAccessSpecs=specs)
        request.pduDestination = Address(args[0])

        try:
            iocb = IOCB(request)                               # build an ReadPropertyMultiple request
            self.this_application.request_io(iocb)             # pass to the BACnet stack

        except Exception as e:
            LOG.exception("exception: %r", e)                  # construction error


        iocb.wait()             # Wait for BACnet response

        if iocb.ioResponse:     # successful response
            apdu = iocb.ioResponse

            if not isinstance(apdu, ReadPropertyMultipleACK):       # expecting an ACK
                log_debug(ReadProperty,"    - not an ack")
                return

            # loop through the results
            dic= {}
            for result in apdu.listOfReadAccessResults:
                objectIdentifier = result.objectIdentifier
                dic['Object_Identifier']= '{}{}'.format(
                     Obj_reverse[objectIdentifier[0]], objectIdentifier[1])
                dic['Object_Type']= objectIdentifier[0]

                # now come the property values per object
                for element in result.listOfResults:
                    propertyIdentifier = element.propertyIdentifier
                    propertyArrayIndex = element.propertyArrayIndex

                    readResult = element.readResult

                    if propertyArrayIndex is not None:
                        print("[" + str(propertyArrayIndex) + "]")

                    if readResult.propertyAccessError is not None:
                        print(" ! " + str(readResult.propertyAccessError))
                    else:
                        propertyValue = readResult.propertyValue

                        # find the datatype
                        datatype = get_datatype(objectIdentifier[0], propertyIdentifier)
                        if not datatype:
                            raise TypeError("unknown datatype")

                        # special case for array parts, others are managed by cast_out
                        if issubclass(datatype, Array) and (propertyArrayIndex is not None):
                            if propertyArrayIndex == 0:
                                value = propertyValue.cast_out(Unsigned)
                            else:
                                value = propertyValue.cast_out(datatype.subtype)
                        else:
                            value = propertyValue.cast_out(datatype)
                        print(propertyIdentifier,value)
                        dic[propertyIdentifier]= value
            return dic

        if iocb.ioError:        # unsuccessful: error/reject/abort
            print('BACnet error: ', iocb.ioError)
            raise IOError()

#------------------------------------------------------------------------------

def get_hostIP():
    """
    Identify host's  IP information
    """
    if 'win' in sys.platform:
        proc = subprocess.Popen('ipconfig', stdout=subprocess.PIPE)
        for l in proc.stdout:
            line= str(l)
            if 'Address' in line:
                ip= line.split(':')[-1]
            if 'Mask' in line:
                mask= line.split(':')[-1]

        ip= ipaddress.IPv4Interface('{}/{}'.format(ip, mask))
    else:
        proc = subprocess.Popen('ifconfig', stdout=subprocess.PIPE)
        for l in proc.stdout:
            line= l.decode('utf-8')
            if 'Bcast' in line:
                _,ipaddr,bcast,mask= line.split()
                _,ip= ipaddr.split(':')
                _,mask= mask.split(':')

                ip= ipaddress.IPv4Interface('{}/{}'.format(ip, mask))
                break 
    
    return str(ip)              # IP Address/subnet


def connect():
    ''' [syntantic sugar] Hide the complexity of stack configuration and 
        start up behind a intuitive 'connect me to the network' call.
    '''  
    thread= Stack()
    thread.daemon= True
    thread.start()
    print('stack started')
    
    return thread
