#!/usr/bin/python

"""
IOCB Module - I/O Control Block

The interface between the BACnet stack and the caller application.

"""

#--- standard Python modules ---
import sys
import logging
import threading

from time import time as _time
from bisect import bisect_left

#--- 3rd party modules ---

#--- this application's modules ---
from .debugging import bacpypes_debugging, ModuleLogger, DebugContents

from .core import deferred
from .task import FunctionTask
from .comm import Client

#------------------------------------------------------------------------------

# some debugging
_debug = 0
_log = ModuleLogger(globals())
_statelog = logging.getLogger(__name__ + "._statelog")

# globals
local_controllers = {}

#
#   IOCB States
#

IDLE = 0        # has not been submitted
PENDING = 1     # queued, waiting for processing
ACTIVE = 2      # being processed
COMPLETED = 3   # finished
ABORTED = 4     # finished in a bad way

_stateNames = {
    0: 'IDLE',
    1: 'PENDING',
    2: 'ACTIVE',
    3: 'COMPLETED',
    4: 'ABORTED',
    }

#
#   IOQController States
#

CTRL_IDLE = 0       # nothing happening
CTRL_ACTIVE = 1     # working on an iocb
CTRL_WAITING = 1    # waiting between iocb requests (throttled)

_ctrlStateNames = {
    0: 'IDLE',
    1: 'ACTIVE',
    2: 'WAITING',
    }

# special abort error
TimeoutError = RuntimeError("timeout")

# current time formatting (short version)
_strftime = lambda: "%011.6f" % (_time() % 3600,)


#------------------------------------------------------------------------------
#
#   IOCB - Input Output Control Block
#

_identNext = 1
_identLock = threading.Lock()

@bacpypes_debugging
class IOCB(DebugContents):

    _debugContents = \
        ( 'args', 'kwargs'
        , 'ioState', 'ioResponse-', 'ioError'
        , 'ioController', 'ioServerRef', 'ioControllerRef', 'ioClientID', 'ioClientAddr'
        , 'ioComplete', 'ioCallback+', 'ioQueue', 'ioPriority', 'ioTimeout'
        )

    def __init__(self, *args, **kwargs):
        global _identNext

        _identLock.acquire()            # lock the identity sequence number
        ioID = _identNext               # generate a unique identity for this block
        _identNext += 1
        _identLock.release()            # release the lock

        # debugging postponed until ID acquired
        if _debug: IOCB._debug("__init__(%d) %r %r", ioID, args, kwargs)

        self.ioID = ioID                        # save the assigned ID and request parameters
        self.args = args
        self.kwargs = kwargs

        self.ioState = IDLE                     # start with an idle request
        self.ioResponse = None
        self.ioError = None

        self.ioController = None                # blocks are bound to a controller

        self.ioComplete = threading.Event()     # each block gets a completion event
        self.ioComplete.clear()

        self.ioCallback = []                    # applications can set callback functions
        self.ioQueue = None                     # request is not currently queued

        # extract the priority if it was given
        self.ioPriority = kwargs.get('_priority', 0)
        if '_priority' in kwargs:
            if _debug: IOCB._debug("    - ioPriority: %r", self.ioPriority)
            del kwargs['_priority']

        self.ioTimeout = None                   # request has no timeout


    def add_callback(self, fn, *args, **kwargs):
        """Pass a function to be called when IO is complete."""
        if _debug: IOCB._debug("add_callback(%d) %r %r %r", self.ioID, fn, args, kwargs)

        self.ioCallback.append((fn, args, kwargs))
        if self.ioComplete.isSet():             # request has no timeout
            self.trigger()


    def wait(self, *args):
        """Wait for the completion event to be set."""
        if _debug: IOCB._debug("wait(%d) %r", self.ioID, args)

        # waiting from a non-daemon thread could be trouble
        self.ioComplete.wait(*args)


    def trigger(self):
        """Set the completion event and make the callback(s)."""
        if _debug: IOCB._debug("trigger(%d)", self.ioID)

        if self.ioQueue:                        # if it's queued, remove it from its queue
            if _debug: IOCB._debug("    - dequeue")
            self.ioQueue.Remove(self)

        if self.ioTimeout:                      # if there's a timer, cancel it
            if _debug: IOCB._debug("    - cancel timeout")
            self.ioTimeout.SuspendTask()

        self.ioComplete.set()                   # set the completion event

        for fn, args, kwargs in self.ioCallback:
            if _debug: IOCB._debug("    - callback fn: %r %r %r", fn, args, kwargs)
            fn(self, *args, **kwargs)           # call the callback(s)


    def complete(self, msg):
        """Complete a transaction, usually called when ProcessIO has
        shipped the IOCB off to some other thread or function."""
        if _debug: IOCB._debug("complete(%d) %r", self.ioID, msg)

        if self.ioController:                   # pass to controller
            self.ioController.complete_io(self, msg)
        else:
            self.ioState = COMPLETED            # just fill in the data
            self.ioResponse = msg
            self.trigger()


    def abort(self, err):
        """Called by a client to abort a transaction."""
        if _debug: IOCB._debug("abort(%d) %r", self.ioID, err)

        if self.ioController:                   # pass to controller
            self.ioController.abort_io(self, err)
        elif self.ioState < COMPLETED:
            self.ioState = ABORTED              # just fill in the data
            self.ioError = err
            self.trigger()


    def set_timeout(self, delay, err=TimeoutError):
        """Called to set a transaction timer."""
        if _debug: IOCB._debug("set_timeout(%d) %r err=%r", self.ioID, delay, err)

        if self.ioTimeout:
            self.ioTimeout.suspend_task()       # if one has already been created, cancel it
        else:
            self.ioTimeout = FunctionTask(self.Abort, err)

        # (re)schedule it
        self.ioTimeout.install_task(_time() + delay)


    def __repr__(self):
        xid = id(self)
        if (xid < 0): xid += (1 << 32)

        sname = self.__module__ + '.' + self.__class__.__name__
        desc = "(%d)" % (self.ioID)

        return '<' + sname + desc + ' instance at 0x%08x' % (xid,) + '>'

#
#   IOChainMixIn
#

@bacpypes_debugging
class IOChainMixIn(DebugContents):

    _debugContents = ( 'ioChain++', )

    def __init__(self, iocb):
        if _debug: IOChainMixIn._debug("__init__ %r", iocb)

        self.ioChain = iocb                     # save a refence back to the iocb
        self.add_callback(self.chain_callback)  # set the callback to follow the chain
        if not self.ioChain:                    # if we're not chained, there's no notification to do
            return

        iocb.ioController = self                # this object becomes its controller
        iocb.ioState = ACTIVE                   # consider the parent active

        try:
            if _debug: IOChainMixIn._debug("    - encoding")

            self.encode()                       # let the derived class set the args and kwargs

            if _debug: IOChainMixIn._debug("    - encode complete")
        except:
            err = sys.exc_info()[1]             # extract the error and abort the request
            if _debug: IOChainMixIn._exception("    - encoding exception: %r", err)
            iocb.abort(err)


    def chain_callback(self, iocb):
        """Callback when this iocb completes."""
        if _debug: IOChainMixIn._debug("chain_callback %r", iocb)

        if not self.ioChain:                    # if we're not chained, there's no notification to do
            return

        iocb = self.ioChain                     # refer to the chained iocb

        try:
            if _debug: IOChainMixIn._debug("    - decoding")

            self.decode()                       # let the derived class transform the data

            if _debug: IOChainMixIn._debug("    - decode complete")
        except:
            err = sys.exc_info()[1]             # extract the error and abort
            if _debug: IOChainMixIn._exception("    - decoding exception: %r", err)

            iocb.ioState = ABORTED
            iocb.ioError = err

        self.ioChain = None                     # break the references
        iocb.ioController = None
        iocb.trigger()                          # notify the client


    def abort_io(self, iocb, err):
        """Forward the abort downstream."""
        if _debug: IOChainMixIn._debug("abort_io %r %r", iocb, err)

        # make sure we're being notified of an abort request from
        # the iocb we are chained from
        if iocb is not self.ioChain:
            raise RuntimeError("broken chain")

        # call my own Abort(), which may forward it to a controller or
        # be overridden by IOGroup
        self.abort(err)


    def encode(self):
        """Hook to transform the request, called when this IOCB is
        chained."""
        if _debug: IOChainMixIn._debug("encode")
        # by default do nothing, the arguments have already been supplied


    def decode(self):
        """Hook to transform the response, called when this IOCB is
        completed."""
        if _debug: IOChainMixIn._debug("decode")

        iocb = self.ioChain                     # refer to the chained iocb

        if self.ioState == COMPLETED:           # if this has completed successfully, pass it up
            if _debug: IOChainMixIn._debug("    - completed: %r", self.ioResponse)

            iocb.ioState = COMPLETED            # change the state and transform the content
            iocb.ioResponse = self.ioResponse

        elif self.ioState == ABORTED:           # if this aborted, pass that up too
            if _debug: IOChainMixIn._debug("    - aborted: %r", self.ioError)
            iocb.ioState = ABORTED
            iocb.ioError = self.ioError

        else:
            raise RuntimeError("invalid state: %d" % (self.ioState,))

#
#   IOChain
#

@bacpypes_debugging
class IOChain(IOCB, IOChainMixIn):

    def __init__(self, chain, *args, **kwargs):
        """Initialize a chained control block."""
        if _debug: IOChain._debug("__init__ %r %r %r", chain, args, kwargs)

        IOCB.__init__(self, *args, **kwargs)    # initialize IOCB part to pick up the ioID
        IOChainMixIn.__init__(self, chain)

#
#   IOGroup
#

@bacpypes_debugging
class IOGroup(IOCB, DebugContents):

    _debugContents = ('ioMembers',)

    def __init__(self):
        """Initialize a group."""
        if _debug: IOGroup._debug("__init__")
        IOCB.__init__(self)

        # start out being done.  When an IOCB is added to the
        # group that is not already completed, this state will
        # change to PENDING.
        self.ioMembers = []
        self.ioState = COMPLETED
        self.ioComplete.set()


    def add(self, iocb):
        """Add an IOCB to the group, you can also add other groups."""
        if _debug: IOGroup._debug("add %r", iocb)

        self.ioMembers.append(iocb)

        # assume all of our members have not completed yet
        self.ioState = PENDING
        self.ioComplete.clear()

        # when this completes, call back to the group.  If this
        # has already completed, it will trigger
        iocb.add_callback(self.group_callback)


    def group_callback(self, iocb):
        """Callback when a child iocb completes."""
        if _debug: IOGroup._debug("group_callback %r", iocb)

        for iocb in self.ioMembers:
            if not iocb.ioComplete.isSet():
                if _debug: IOGroup._debug("    - waiting for child: %r", iocb)
                break
        else:
            if _debug: IOGroup._debug("    - all children complete")
            self.ioState = COMPLETED
            self.trigger()


    def abort(self, err):
        """Called by a client to abort all of the member transactions.
        When the last pending member is aborted the group callback
        function will be called."""
        if _debug: IOGroup._debug("abort %r", err)

        self.ioState = ABORTED
        self.ioError = err

        for iocb in self.ioMembers:             # abort all the members
            iocb.abort(err)

        self.trigger()                          # notify the client

#
#   IOQueue
#

@bacpypes_debugging
class IOQueue:

    def __init__(self, name=None):
        if _debug: IOQueue._debug("__init__ %r", name)

        self.notempty = threading.Event()
        self.notempty.clear()

        self.queue = []


    def put(self, iocb):
        """Add an IOCB to a queue.  This is usually called by the function
        that filters requests and passes them out to the correct processing
        thread."""
        if _debug: IOQueue._debug("put %r", iocb)

        if iocb.ioState != PENDING:             # requests should be pending before being queued
            raise RuntimeError("invalid state transition")

        wasempty = not self.notempty.isSet()    # save that it might have been empty

        # add the request to the end of the list of iocb's at same priority
        priority = iocb.ioPriority
        item = (priority, iocb)
        self.queue.insert(bisect_left(self.queue, (priority+1,)), item)

        iocb.ioQueue = self                     # point the iocb back to this queue
        self.notempty.set()                     # set the event, queue is no longer empty
        return wasempty


    def get(self, block=1, delay=None):
        """Get a request from a queue, optionally block until a request
        is available."""
        if _debug: IOQueue._debug("get block=%r delay=%r", block, delay)

        # if the queue is empty and we do not block return None
        if not block and not self.notempty.isSet():
            return None

        if delay:                               # wait for something to be in the queue
            self.notempty.wait(delay)
            if not self.notempty.isSet():
                return None
        else:
            self.notempty.wait()

        priority, iocb = self.queue[0]          # extract the first element
        del self.queue[0]
        iocb.ioQueue = None

        qlen = len(self.queue)
        if not qlen:                            # if the queue is empty, clear the event
            self.notempty.clear()

        return iocb


    def remove(self, iocb):
        """Remove a control block from the queue, called if the request
        is canceled/aborted."""
        if _debug: IOQueue._debug("remove %r", iocb)

        # remove the request from the queue
        for i, item in enumerate(self.queue):
            if iocb is item[1]:
                if _debug: IOQueue._debug("    - found at %d", i)
                del self.queue[i]

                # if the queue is empty, clear the event
                qlen = len(self.queue)
                if not qlen:
                    self.notempty.clear()

                # record the new length
                # self.queuesize.Record( qlen, _time() )
                break
        else:
            if _debug: IOQueue._debug("    - not found")


    def abort(self, err):
        """Abort all of the control blocks in the queue."""
        if _debug: IOQueue._debug("abort %r", err)

        # send aborts to all of the members
        try:
            for iocb in self.queue:
                iocb.ioQueue = None
                iocb.abort(err)

            # flush the queue
            self.queue = []

            # the queue is now empty, clear the event
            self.notempty.clear()
        except ValueError:
            pass

#
#   IOController
#

@bacpypes_debugging
class IOController(object):

    def __init__(self, name=None):
        """Initialize a controller."""
        if _debug: IOController._debug("__init__ name=%r", name)

        self.name = name


    def abort(self, err):
        """Abort all requests, no default implementation."""
        pass


    def request_io(self, iocb):
        """Called by a client to start processing a request."""
        if _debug: IOController._debug("request_io %r", iocb)

        if not isinstance(iocb, IOCB):
            raise TypeError("IOCB expected")

        iocb.ioController = self                # bind the iocb to this controller
        try:
            err = None
            iocb.ioState = PENDING
            self.process_io(iocb)               # let derived class figure out how to process this
        except:
            err = sys.exc_info()[1]

        if err:
            self.abort_io(iocb, err)


    def process_io(self, iocb):
        """Figure out how to respond to this request.  This must be
        provided by the derived class."""
        raise NotImplementedError("IOController must implement process_io()")


    def active_io(self, iocb):
        """Called by a handler to notify the controller that a request is
        being processed."""
        if _debug: IOController._debug("active_io %r", iocb)

        # requests should be idle or pending before coming active
        if (iocb.ioState != IDLE) and (iocb.ioState != PENDING):
            raise RuntimeError("invalid state transition (currently %d)" % (iocb.ioState,))

        iocb.ioState = ACTIVE


    def complete_io(self, iocb, msg):
        """Called by a handler to return data to the client."""
        if _debug: IOController._debug("complete_io %r %r", iocb, msg)

        if iocb.ioState == COMPLETED:           # if it completed, leave it alone
            pass
        elif iocb.ioState == ABORTED:           # if it already aborted, leave it alone
            pass
        else:
            iocb.ioState = COMPLETED
            iocb.ioResponse = msg
            iocb.trigger()                      # notify the client


    def abort_io(self, iocb, err):
        """Called by a handler or a client to abort a transaction."""
        if _debug: IOController._debug("abort_io %r %r", iocb, err)

        if iocb.ioState == COMPLETED:           # if it completed, leave it alone
            pass
        elif iocb.ioState == ABORTED:           # if it already aborted, leave it alone
            pass
        else:
            iocb.ioState = ABORTED
            iocb.ioError = err
            iocb.trigger()                      # notify the client


#
#   IOQController
#

@bacpypes_debugging
class IOQController(IOController):

    wait_time = 0.0

    def __init__(self, name=None):
        """Initialize a queue controller."""
        if _debug: IOQController._debug("__init__ name=%r", name)
        IOController.__init__(self, name)

        self.state = CTRL_IDLE
        _statelog.debug("%s %s %s" % (_strftime(), self.name, "idle"))

        self.active_iocb = None

        # create an IOQueue for iocb's requested when not idle
        self.ioQueue = IOQueue(str(name) + " queue")


    def abort(self, err):
        """Abort all pending requests."""
        if _debug: IOQController._debug("abort %r", err)

        if (self.state == CTRL_IDLE):
            if _debug: IOQController._debug("    - idle")
            return

        while True:
            iocb = self.ioQueue.get()
            if not iocb:
                break
            if _debug: IOQController._debug("    - iocb: %r", iocb)

            iocb.ioState = ABORTED
            iocb.ioError = err
            iocb.trigger()                      # notify the client

        if (self.state != CTRL_IDLE):
            if _debug: IOQController._debug("    - busy after aborts")


    def request_io(self, iocb):
        """Called by a client to start processing a request."""
        if _debug: IOQController._debug("request_io %r", iocb)

        iocb.ioController = self

        if (self.state != CTRL_IDLE):           # if we're busy, queue it
            if _debug: IOQController._debug("    - busy, request queued")

            iocb.ioState = PENDING
            self.ioQueue.put(iocb)
            return

        try:
            err = None
            self.process_io(iocb)               # let derived class figure out how to process this
        except:
            err = sys.exc_info()[1]

        if err:
            self.abort_io(iocb, err)


    def process_io(self, iocb):
        """Figure out how to respond to this request.  This must be
        provided by the derived class."""
        raise NotImplementedError("IOController must implement process_io()")


    def active_io(self, iocb):
        """Called by a handler to notify the controller that a request is
        being processed."""
        if _debug: IOQController._debug("active_io %r", iocb)

        # base class work first, setting iocb state and timer data
        IOController.active_io(self, iocb)

        self.state = CTRL_ACTIVE
        self.active_iocb = iocb
        _statelog.debug("%s %s %s" % (_strftime(), self.name, "active"))
 

    def complete_io(self, iocb, msg):
        """Called by a handler to return data to the client."""
        if _debug: IOQController._debug("complete_io %r %r", iocb, msg)

        if iocb is not self.active_iocb:
            raise RuntimeError("not the current iocb")

        # normal completion
        IOController.complete_io(self, iocb, msg)
        self.active_iocb = None

        # check to see if we should wait a bit
        if self.wait_time:
            self.state = CTRL_WAITING
            _statelog.debug("%s %s %s" % (_strftime(), self.name, "waiting"))

            # schedule a call in the future
            task = FunctionTask(IOQController._wait_trigger, self)
            task.install_task(_time() + self.wait_time)

        else:
            self.state = CTRL_IDLE
            _statelog.debug("%s %s %s" % (_strftime(), self.name, "idle"))

            # look for more to do
            deferred(IOQController._trigger, self)


    def abort_io(self, iocb, err):
        """Called by a handler or a client to abort a transaction."""
        if _debug: IOQController._debug("abort_io %r %r", iocb, err)

        IOController.abort_io(self, iocb, err)

        if iocb is not self.active_iocb:
            if _debug: IOQController._debug("    - not current iocb")
            return

        self.active_iocb = None
        self.state = CTRL_IDLE
        _statelog.debug("%s %s %s" % (_strftime(), self.name, "idle"))

        # look for more to do
        deferred(IOQController._trigger, self)


    def _trigger(self):
        """Called to launch the next request in the queue."""
        if _debug: IOQController._debug("_trigger")

        # if we are busy, do nothing
        if self.state != CTRL_IDLE:
            if _debug: IOQController._debug("    - not idle")
            return

        # if there is nothing to do, return
        if not self.ioQueue.queue:
            if _debug: IOQController._debug("    - empty queue")
            return

        iocb = self.ioQueue.get()               # get the next iocb

        try:
            err = None
            self.process_io(iocb)               # let derived class figure out how to process this
        except:
            err = sys.exc_info()[1]

        if err:
            self.abort_io(iocb, err)

        if self.state == CTRL_IDLE:             # if we're idle, call again
            deferred(IOQController._trigger, self)


    def _wait_trigger(self):
        """Called to launch the next request in the queue."""
        if _debug: IOQController._debug("_wait_trigger")

        if (self.state != CTRL_WAITING):
            raise RuntimeError("not waiting")

        self.state = CTRL_IDLE
        _statelog.debug("%s %s %s" % (_strftime(), self.name, "idle"))

        IOQController._trigger(self)            # look for more to do

#
#   ClientController
#

@bacpypes_debugging
class ClientController(Client, IOQController):

    def __init__(self):
        if _debug: ClientController._debug("__init__")
        Client.__init__(self)
        IOController.__init__(self)


    def process_io(self, iocb):
        if _debug: ClientController._debug("process_io %r", iocb)

        self.active_io(iocb)                    # this is now an active request
        self.request(iocb.args[0])              # send the PDU downstream


    def confirmation(self, pdu):
        if _debug: ClientController._debug("confirmation %r %r", args, kwargs)

        if not self.active_iocb:
            ClientController._debug("no active request")
            return

        # look for exceptions
        if isinstance(pdu, Exception):
            self.abort_io(self.active_iocb, pdu)
        else:
            self.complete_io(self.active_iocb, pdu)

#
#   SieveQueue
#

@bacpypes_debugging
class SieveQueue(IOQController):

    def __init__(self, request_fn, address=None):
        if _debug: SieveQueue._debug("__init__ %r %r", request_fn, address)
        IOQController.__init__(self, str(address))

        self.request_fn = request_fn
        self.address = address


    def process_io(self, iocb):
        if _debug: SieveQueue._debug("process_io %r", iocb)

        self.active_io(iocb)                    # this is now an active request
        self.request_fn(iocb.args[0])           # send the request

#
#   SieveClientController
#

@bacpypes_debugging
class SieveClientController(Client, IOController):

    def __init__(self):
        if _debug: SieveClientController._debug("__init__")
        Client.__init__(self)
        IOController.__init__(self)

        self.queues = {}                        # queues for each address


    def process_io(self, iocb):
        if _debug: SieveClientController._debug("process_io %r", iocb)

        destination_address = iocb.args[0].pduDestination
        if _debug: SieveClientController._debug("    - destination_address: %r", destination_address)

        queue = self.queues.get(destination_address, None)
        if not queue:
            queue = SieveQueue(self.request, destination_address)
            self.queues[destination_address] = queue
        if _debug: SieveClientController._debug("    - queue: %r", queue)

        queue.request_io(iocb)


    def request(self, pdu):
        if _debug: SieveClientController._debug("request %r", pdu)

        # send it downstream
        super(SieveClientController, self).request(pdu)


    def confirmation(self, pdu):
        if _debug: SieveClientController._debug("confirmation %r", pdu)

        source_address = pdu.pduSource
        queue = self.queues.get(source_address, None)
        if _debug: SieveClientController._debug("    - source_address: %r", source_address)
        if _debug: SieveClientController._debug("    - queue: %r", queue)

        if not queue:
            SieveClientController._debug("no queue for %r" % (source_address,))
            return

        if not queue.active_iocb:
            SieveClientController._debug("no active request for %r" % (source_address,))
            return

        if isinstance(pdu, Exception):          # complete the request
            queue.abort_io(queue.active_iocb, pdu)
        else:
            queue.complete_io(queue.active_iocb, pdu)

        # if the queue is empty and idle, forget about the controller
        if not queue.ioQueue.queue and not queue.active_iocb:
            if _debug: SieveClientController._debug("    - queue is empty")
            del self.queues[source_address]

#
#   register_controller
#

@bacpypes_debugging
def register_controller(controller):
    if _debug: register_controller._debug("register_controller %r", controller)
    global local_controllers

    if not controller.name:                     # skip those that shall not be named
        return

    if controller.name in local_controllers:
        raise RuntimeError("already a local controller named %r" % (controller.name,))

    local_controllers[controller.name] = controller

#
#   abort
#

@bacpypes_debugging
def abort(err):
    """Abort everything, everywhere."""
    if _debug: abort._debug("abort %r", err)
    global local_controllers

    # tell all the local controllers to abort
    for controller in local_controllers.values():
        controller.abort(err)
