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

import logging
LOG = logging.getLogger('standard')


#--- 3rd party modules ---

#--- this application's modules ---
from bacpypes.pdu import Address

from bacpypes.core import run as start_bacpypes
from bacpypes.core import stop as stop_bacpypes
from bacpypes.core import enable_sleeping

#from bacpypes.primitivedata import CharacterString
from bacpypes.constructeddata import Array

from bacpypes.basetypes import ServicesSupported, DeviceStatus
from bacpypes.service.device import LocalDeviceObject
from bacpypes.app import BIPSimpleApplication

from bacpypes.iocb import IOCB

from bacpypes.apdu import PropertyReference, ReadAccessSpecification, \
    ReadPropertyRequest, ReadPropertyACK, \
    ReadPropertyMultipleRequest, ReadPropertyMultipleACK 

from bacpypes.object import get_object_class, get_datatype

#--- this application's modules ---

#------------------------------------------------------------------------------

#------------------------------------------------------------------------------

print('BACnet loaded')


class BACnet():

    #class ReadWriteScript(BasicScript, WhoisIAm, ReadProperty, WriteProperty, Simulation):
    """
    Configure bacpypes to accept Read and Write requests.
    Build LocalObject - with BACnet/IP
    spin-up bacpypes in its own thread
    
    Its basic function is to start and stop the bacpypes stack.
    Stopping the stack, frees the IP socket used for BACnet communications. 
    No communications will occur if the stack is stopped.
    
    Bacpypes stack enables Whois and Iam functions, since this minimum is needed to be 
    a BACnet device.  Other stack services can be enabled later (via class inheritance).
     
    """
    def __init__(self):
        print('init')

        self.response = None
        self._started = False
        self._stopped = False

        self._connect()
        pass
    

    def read(self,oref,props=None):
        print('read',oref,props)
        
        #[(dev,oType,oInst)]= re.findall('(\d+).(\D+)(\d+)',oref)

        
        if not props:
            query= ['192.168.87.48:47808','analogValue',1,'presentValue']
            return self._readProperty(query)
        else:
            return self._readMultiple(oref,props)


    def write(self,oref):
        print('write',oref)
        pass


    #--------------------------------------------------------------------------

    def do_WhoIsRequest(self, apdu):
        """Respond to a Who-Is request."""
        print("do_WhoIsRequest %r", apdu)

        # build a key from the source and parameters
        key = (str(apdu.pduSource),
            apdu.deviceInstanceRangeLowLimit,
            apdu.deviceInstanceRangeHighLimit )

        # count the times this has been received
        self.who_is_counter[key] += 1

        # continue with the default implementation
        BIPSimpleApplication.do_WhoIsRequest(self, apdu)


    def do_IAmRequest(self, apdu):
        """Given an I-Am request, cache it."""
        print("do_IAmRequest %r", apdu)

        # build a key from the source, just use the instance number
        key = (str(apdu.pduSource), apdu.iAmDeviceIdentifier[1] )
        self.i_am_counter[key] += 1

        # continue with the default implementation
        BIPSimpleApplication.do_IAmRequest(self, apdu)


    
    def _connect(self):
        """
        Define the local device, including services supported.
        Once defined, start the BACnet stack in its own thread.
        """
        print('connect')

        self.devId = 4000000    # (3056177 + int(random.uniform(0, 1000)))
        self.ip_addr= get_hostIP() 

        self.systemStatus = DeviceStatus(1)
        
        print('Create our Local Device')
        try:
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

            # State the BACnet services we support
            pss = ServicesSupported()
            pss['whoIs'] = 1
            pss['iAm'] = 1
            pss['readProperty'] = 1
            pss['writeProperty'] = 1
            pss['readPropertyMultiple'] = 1
            self.this_device.protocolServicesSupported = pss.value

            self.this_application = BIPSimpleApplication(self.this_device, self.ip_addr)

            self._initialized = True
            self._startAppThread()

        except Exception as error:
            print("bacpypes - startup failure: %s", error)
            raise


    '''
    def disconnect(self):
        """
        Stop the BACnet stack.  Free the IP socket.
        """
        print('Stopping BACnet stack')
        # Freeing socket
        try:
            self.this_application.mux.directPort.handle_close()
        except:
            self.this_application.mux.broadcastPort.handle_close()

        stopBacnetIPApp()           # Stop Core
        self._stopped = True        # Stop stack thread
        self.t.join()
        self._started = False
        print('BACnet stopped')
    '''

    def _startAppThread(self):
        """
        Starts the BACnet stack in its own thread so requests can be processed.
        """
        print('Starting bacpypes thread...')
        enable_sleeping(0.0005)
        self.t = Thread(target=start_bacpypes, name='bacnet', daemon = True)
        #self.t = Thread(target=start_bacpypes, kwargs={'sigterm': None,'sigusr1': None}, daemon = True)
        self.t.start()
        self._started = True
        print('BACnet started')
        

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
            raise IOError()


    def _readMultiple(self, oref, props=None):
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
        print('readMultiple({},{})'.format(oref,props))

        [(d,t,i)]= re.findall('(\d+).(\D+)(\d+)',oref)
        #d= addr lookup(d)
        #query= ['192.168.87.48:47808','analogInput',1,'presentValue units outOfService statusFlags']
        query= ['192.168.87.48:47808','analogValue',1,'presentValue']

        try:
            iocb = IOCB(self.build_rpm_request(query))              # build an ReadPropertyMultiple request
            self.this_application.request_io(iocb)                  # pass to the BACnet stack

        except Exception as e:
            LOG.exception("exception: %r", e)                       # construction error


        iocb.wait()             # Wait for BACnet response

        if iocb.ioResponse:     # successful response
            apdu = iocb.ioResponse

            if not isinstance(apdu, ReadPropertyMultipleACK):       # expecting an ACK
                log_debug(ReadProperty,"    - not an ack")
                return

            # loop through the results
            values= []
            for result in apdu.listOfReadAccessResults:
                objectIdentifier = result.objectIdentifier

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
                        print('\tvalue= {}'.format(value))

                        values.append(value)

            return values
                    

        if iocb.ioError:        # unsuccessful: error/reject/abort
            raise IOError()

                
    def build_rpm_request(self, args):
        props= []
        specs= []
        #query= ['192.168.87.48:47808','analogValue',1,'presentValue']
        props.append(PropertyReference(propertyIdentifier=args[3]))

        spec = ReadAccessSpecification(
            objectIdentifier=(args[1],args[2]),listOfPropertyReferences=props)
        specs.append(spec)

        request = ReadPropertyMultipleRequest(listOfReadAccessSpecs=specs)
        request.pduDestination = Address(args[0])
        LOG.debug('RPM:request: ', request)

        return request

        #------------------
        
        i = 0
        addr = args[i]
        i += 1

        read_access_spec_list = []
        while i < len(args):
            obj_type = args[i]
            i += 1

            if obj_type.isdigit():
                obj_type = int(obj_type)
            elif not get_object_class(obj_type):
                raise ValueError("unknown object type")

            obj_inst = int(args[i])
            i += 1

            prop_reference_list = []
            while i < len(args):
                prop_id = args[i]
                if prop_id not in PropertyIdentifier.enumerations:
                    break

                i += 1
                if prop_id in ('all', 'required', 'optional'):
                    pass
                else:
                    datatype = get_datatype(obj_type, prop_id)
                    if not datatype:
                        raise ValueError(
                            "invalid property for object type : %s | %s" %
                            (obj_type, prop_id))

                # build a property reference
                prop_reference = PropertyReference(propertyIdentifier=prop_id)

                # check for an array index
                if (i < len(args)) and args[i].isdigit():
                    prop_reference.propertyArrayIndex = int(args[i])
                    i += 1

                prop_reference_list.append(prop_reference)

            if not prop_reference_list:
                raise ValueError("provide at least one property")

            # build a read access specification
            read_access_spec = ReadAccessSpecification(
                objectIdentifier=(obj_type, obj_inst),
                listOfPropertyReferences=prop_reference_list )

            read_access_spec_list.append(read_access_spec)

        if not read_access_spec_list:
            raise RuntimeError(
                "at least one read access specification required")

        # build the request
        request = ReadPropertyMultipleRequest(listOfReadAccessSpecs=read_access_spec_list )
        request.pduDestination = Address(addr)
        log_debug(ReadProperty, "    - request: %r", request)

        return request


    def do_read(self, args):
        """read <addr> ( <type> <inst> ( <prop> [ <indx> ] )... )..."""
        args = args.split()
        if _debug: ReadPropertyMultipleConsoleCmd._debug("do_read %r", args)

        try:
            i = 0
            addr = args[i]
            i += 1

            read_access_spec_list = []
            while i < len(args):
                obj_type = args[i]
                i += 1

                if obj_type.isdigit():
                    obj_type = int(obj_type)
                elif not get_object_class(obj_type):
                    raise ValueError("unknown object type")

                obj_inst = int(args[i])
                i += 1

                prop_reference_list = []
                while i < len(args):
                    prop_id = args[i]
                    if prop_id not in PropertyIdentifier.enumerations:
                        break

                    i += 1
                    if prop_id in ('all', 'required', 'optional'):
                        pass
                    else:
                        datatype = get_datatype(obj_type, prop_id)
                        if not datatype:
                            raise ValueError("invalid property for object type")

                    # build a property reference
                    prop_reference = PropertyReference(
                        propertyIdentifier=prop_id,
                        )

                    # check for an array index
                    if (i < len(args)) and args[i].isdigit():
                        prop_reference.propertyArrayIndex = int(args[i])
                        i += 1

                    # add it to the list
                    prop_reference_list.append(prop_reference)

                # check for at least one property
                if not prop_reference_list:
                    raise ValueError("provide at least one property")

                # build a read access specification
                read_access_spec = ReadAccessSpecification(
                    objectIdentifier=(obj_type, obj_inst),
                    listOfPropertyReferences=prop_reference_list,
                    )

                # add it to the list
                read_access_spec_list.append(read_access_spec)

            # check for at least one
            if not read_access_spec_list:
                raise RuntimeError("at least one read access specification required")

            # build the request
            request = ReadPropertyMultipleRequest(
                listOfReadAccessSpecs=read_access_spec_list,
                )
            request.pduDestination = Address(addr)
            if _debug: ReadPropertyMultipleConsoleCmd._debug("    - request: %r", request)

            # make an IOCB
            iocb = IOCB(request)
            if _debug: ReadPropertyMultipleConsoleCmd._debug("    - iocb: %r", iocb)

            # give it to the application
            this_application.request_io(iocb)

            # wait for it to complete
            iocb.wait()

            # do something for success
            if iocb.ioResponse:
                apdu = iocb.ioResponse

                # should be an ack
                if not isinstance(apdu, ReadPropertyMultipleACK):
                    if _debug: ReadPropertyMultipleConsoleCmd._debug("    - not an ack")
                    return

                # loop through the results
                for result in apdu.listOfReadAccessResults:
                    # here is the object identifier
                    objectIdentifier = result.objectIdentifier
                    if _debug: ReadPropertyMultipleConsoleCmd._debug("    - objectIdentifier: %r", objectIdentifier)

                    # now come the property values per object
                    for element in result.listOfResults:
                        # get the property and array index
                        propertyIdentifier = element.propertyIdentifier
                        if _debug: ReadPropertyMultipleConsoleCmd._debug("    - propertyIdentifier: %r", propertyIdentifier)
                        propertyArrayIndex = element.propertyArrayIndex
                        if _debug: ReadPropertyMultipleConsoleCmd._debug("    - propertyArrayIndex: %r", propertyArrayIndex)

                        # here is the read result
                        readResult = element.readResult

                        sys.stdout.write(propertyIdentifier)
                        if propertyArrayIndex is not None:
                            sys.stdout.write("[" + str(propertyArrayIndex) + "]")

                        # check for an error
                        if readResult.propertyAccessError is not None:
                            sys.stdout.write(" ! " + str(readResult.propertyAccessError) + '\n')

                        else:
                            # here is the value
                            propertyValue = readResult.propertyValue

                            # find the datatype
                            datatype = get_datatype(objectIdentifier[0], propertyIdentifier)
                            if _debug: ReadPropertyMultipleConsoleCmd._debug("    - datatype: %r", datatype)
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
                            if _debug: ReadPropertyMultipleConsoleCmd._debug("    - value: %r", value)

                            sys.stdout.write(" = " + str(value) + '\n')
                        sys.stdout.flush()

            # do something for error/reject/abort
            if iocb.ioError:
                sys.stdout.write(str(iocb.ioError) + '\n')

        except Exception as error:
            ReadPropertyMultipleConsoleCmd._exception("exception: %r", error)
    def do_read(self, args):
        """read <addr> ( <type> <inst> ( <prop> [ <indx> ] )... )..."""
        args = args.split()
        if _debug: ReadPropertyMultipleConsoleCmd._debug("do_read %r", args)

        try:
            i = 0
            addr = args[i]
            i += 1

            read_access_spec_list = []
            while i < len(args):
                obj_type = args[i]
                i += 1

                if obj_type.isdigit():
                    obj_type = int(obj_type)
                elif not get_object_class(obj_type):
                    raise ValueError("unknown object type")

                obj_inst = int(args[i])
                i += 1

                prop_reference_list = []
                while i < len(args):
                    prop_id = args[i]
                    if prop_id not in PropertyIdentifier.enumerations:
                        break

                    i += 1
                    if prop_id in ('all', 'required', 'optional'):
                        pass
                    else:
                        datatype = get_datatype(obj_type, prop_id)
                        if not datatype:
                            raise ValueError("invalid property for object type")

                    # build a property reference
                    prop_reference = PropertyReference(
                        propertyIdentifier=prop_id,
                        )

                    # check for an array index
                    if (i < len(args)) and args[i].isdigit():
                        prop_reference.propertyArrayIndex = int(args[i])
                        i += 1

                    # add it to the list
                    prop_reference_list.append(prop_reference)

                # check for at least one property
                if not prop_reference_list:
                    raise ValueError("provide at least one property")

                # build a read access specification
                read_access_spec = ReadAccessSpecification(
                    objectIdentifier=(obj_type, obj_inst),
                    listOfPropertyReferences=prop_reference_list,
                    )

                # add it to the list
                read_access_spec_list.append(read_access_spec)

            # check for at least one
            if not read_access_spec_list:
                raise RuntimeError("at least one read access specification required")

            # build the request
            request = ReadPropertyMultipleRequest(
                listOfReadAccessSpecs=read_access_spec_list,
                )
            request.pduDestination = Address(addr)
            if _debug: ReadPropertyMultipleConsoleCmd._debug("    - request: %r", request)

            # make an IOCB
            iocb = IOCB(request)
            if _debug: ReadPropertyMultipleConsoleCmd._debug("    - iocb: %r", iocb)

            # give it to the application
            this_application.request_io(iocb)

            # wait for it to complete
            iocb.wait()

            # do something for success
            if iocb.ioResponse:
                apdu = iocb.ioResponse

                # should be an ack
                if not isinstance(apdu, ReadPropertyMultipleACK):
                    if _debug: ReadPropertyMultipleConsoleCmd._debug("    - not an ack")
                    return

                # loop through the results
                for result in apdu.listOfReadAccessResults:
                    # here is the object identifier
                    objectIdentifier = result.objectIdentifier
                    if _debug: ReadPropertyMultipleConsoleCmd._debug("    - objectIdentifier: %r", objectIdentifier)

                    # now come the property values per object
                    for element in result.listOfResults:
                        # get the property and array index
                        propertyIdentifier = element.propertyIdentifier
                        if _debug: ReadPropertyMultipleConsoleCmd._debug("    - propertyIdentifier: %r", propertyIdentifier)
                        propertyArrayIndex = element.propertyArrayIndex
                        if _debug: ReadPropertyMultipleConsoleCmd._debug("    - propertyArrayIndex: %r", propertyArrayIndex)

                        # here is the read result
                        readResult = element.readResult

                        sys.stdout.write(propertyIdentifier)
                        if propertyArrayIndex is not None:
                            sys.stdout.write("[" + str(propertyArrayIndex) + "]")

                        # check for an error
                        if readResult.propertyAccessError is not None:
                            sys.stdout.write(" ! " + str(readResult.propertyAccessError) + '\n')

                        else:
                            # here is the value
                            propertyValue = readResult.propertyValue

                            # find the datatype
                            datatype = get_datatype(objectIdentifier[0], propertyIdentifier)
                            if _debug: ReadPropertyMultipleConsoleCmd._debug("    - datatype: %r", datatype)
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
                            if _debug: ReadPropertyMultipleConsoleCmd._debug("    - value: %r", value)

                            sys.stdout.write(" = " + str(value) + '\n')
                        sys.stdout.flush()

            # do something for error/reject/abort
            if iocb.ioError:
                sys.stdout.write(str(iocb.ioError) + '\n')

        except Exception as error:
            ReadPropertyMultipleConsoleCmd._exception("exception: %r", error)


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
