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

#--- 3rd party modules ---

#--- this application's modules ---
'''
from ..core.io.Read import ReadProperty
from ..core.io.Write import WriteProperty
from ..core.functions.GetIPAddr import HostIP
from ..core.functions.WhoisIAm import WhoisIAm
'''

'''
from bacpypes.pdu import Address
from bacpypes.core import run as startBacnetIPApp
from bacpypes.core import stop as stopBacnetIPApp
from bacpypes.core import enable_sleeping

from bacpypes.service.device import LocalDeviceObject
from bacpypes.basetypes import ServicesSupported, DeviceStatus
from bacpypes.primitivedata import CharacterString
'''

#--- this application's modules ---

#------------------------------------------------------------------------------

#------------------------------------------------------------------------------


class BACNet1():

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
    def __init__(self, ip_addr=None):
        log_debug("Configurating app")

        self.ip= ip_addr
        self.response = None
        self._started = False
        self._stopped = False

        #self.startStack()


    def connect(self):
        """
        Define the local device, including services supported.
        Once defined, start the BACnet stack in its own thread.
        """
        self.devId = 4000000    # (3056177 + int(random.uniform(0, 1000)))
        self.ip= get_hostIP() if not ip_addr else ip_addr 

        self.systemStatus = DeviceStatus(1)

        
        log_debug("Create Local Device")
        try:
            self.this_device = LocalDeviceObject()      # use all defaults
            '''
                objectName= self.localObjName,
                objectIdentifier= self.Boid,
                maxApduLengthAccepted=int(self.maxAPDULengthAccepted),
                segmentationSupported=self.segmentationSupported,
                vendorIdentifier= self.vendorId,
                vendorName= self.vendorName,
                modelName= self.modelName,
                systemStatus= self.systemStatus,
                description='http://christiantremblay.github.io/BAC0/',
                firmwareRevision=''.join(sys.version.split('|')[:2]),
                applicationSoftwareVersion=infos.__version__,
                protocolVersion=1,
                protocolRevision=0 )
            '''

            # State the BACnet services we support
            pss = ServicesSupported()
            pss['whoIs'] = 1
            pss['iAm'] = 1
            pss['readProperty'] = 1
            pss['writeProperty'] = 1
            pss['readPropertyMultiple'] = 1
            self.this_device.protocolServicesSupported = pss.value

            # make a simple application
            self.this_application = ScriptApplication(self.this_device, self.localIPAddr)

            log_debug("Starting")
            self._initialized = True
            self._startAppThread()
            log_debug("Running")

        except Exception as error:
            log_exception("bacpypes - startup failure: %s", error)
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
        print('Starting app...')
        enable_sleeping(0.0005)
        self.t = Thread(target=startBacnetIPApp, name='bacnet', daemon = True)
        #self.t = Thread(target=startBacnetIPApp, kwargs={'sigterm': None,'sigusr1': None}, daemon = True)
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
    
    return str(self.interface)              # IP Address/subnet
