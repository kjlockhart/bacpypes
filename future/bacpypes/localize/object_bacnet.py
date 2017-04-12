#!/usr/bin/python
'''
object_bacnet - BACnet Object definitions with BACnet Property Naming

BACnet Clause 12 - Modeling Control Devices as a Collection of Objects

The data structures used in a device to store information are a local matter. In order to exchange that information with another
device using this protocol, there must be a "network-visible" representation of the information that is standardized. An object-
oriented approach has been adopted to provide this network-visible representation. This clause defines a set of standard
object types. These object types define an abstract data structure that provides a framework for building the application layer
services. The application layer services are designed, in part, to access and manipulate the properties of these standard object
types. Mapping the effect of these services to the real data structures used in the device is a local matter. The number of
instances of a particular object type that a device will support is also a local matter.

All objects are referenced by their Object_Identifier property. Each object within a single BACnet Device shall have a unique
value for the Object_Identifier property. When combined with the system-wide unique Object_Identifier of the BACnet
Device, this provides a mechanism for referencing every object in the control system network. No object shall have an
Object_Identifier with an instance number of 4194303. Object properties that contain BACnetObjectIdentifiers may use
4194303 to indicate that the property is not initialized.

Not all object types defined in this standard need to be supported in order to conform to the standard. In addition, some
properties of particular object types are optional. At the beginning of each standard object type specification that follows is a
summary of the properties of the object type. The summary includes the property identifier, the datatype of the property, and
one of the following : O, R, W
    where
        O indicates that the property is optional,
        R indicates that the property is required to be present and readable using BACnet services,
        W indicates that the property is required to be present, readable, and writable using BACnet services.

It is intended that the collection of object types and their properties defined in this standard be comprehensive, but
implementors are free to define additional nonstandard object types or additional nonstandard properties of standard object
types.

'''
#--- standard Python modules ---
import sys
from copy import copy as _copy
from collections import defaultdict

#--- 3rd party modules ---

#--- this application's modules ---
from .errors import ConfigurationError, ExecutionError, \
    InvalidParameterDatatype
from .debugging import bacpypes_debugging, ModuleLogger

from .primitivedata import Atomic, BitString, Boolean, CharacterString, Date, \
    Double, Integer, ObjectIdentifier, ObjectType, OctetString, Real, Time, \
    Unsigned
from .constructeddata import AnyAtomic, Array, ArrayOf, Choice, Element, \
    Sequence, SequenceOf
from .basetypes import AccessCredentialDisable, AccessCredentialDisableReason, \
    AccessEvent, AccessPassbackMode, AccessRule, AccessThreatLevel, \
    AccessUserType, AccessZoneOccupancyState, AccumulatorRecord, Action, \
    ActionList, AddressBinding, AssignedAccessRights, AuthenticationFactor, \
    AuthenticationFactorFormat, AuthenticationPolicy, AuthenticationStatus, \
    AuthorizationException, AuthorizationMode, BackupState, BinaryPV, \
    COVSubscription, CalendarEntry, ChannelValue, ClientCOV, \
    CredentialAuthenticationFactor, DailySchedule, DateRange, DateTime, \
    Destination, DeviceObjectPropertyReference, DeviceObjectReference, \
    DeviceStatus, DoorAlarmState, DoorSecuredStatus, DoorStatus, DoorValue, \
    EngineeringUnits, EventNotificationSubscription, EventParameter, \
    EventState, EventTransitionBits, EventType, FaultParameter, FaultType, \
    FileAccessMethod, LifeSafetyMode, LifeSafetyOperation, LifeSafetyState, \
    LightingCommand, LightingInProgress, LightingTransition, LimitEnable, \
    LockStatus, LogMultipleRecord, LogRecord, LogStatus, LoggingType, \
    Maintenance, NetworkSecurityPolicy, NodeType, NotifyType, \
    ObjectPropertyReference, ObjectTypesSupported, OptionalCharacterString, \
    Polarity, PortPermission, Prescale, PriorityArray, ProcessIdSelection, \
    ProgramError, ProgramRequest, ProgramState, PropertyAccessResult, \
    PropertyIdentifier, Recipient, Reliability, RestartReason, Scale, \
    SecurityKeySet, SecurityLevel, Segmentation, ServicesSupported, \
    SetpointReference, ShedLevel, ShedState, SilencedState, SpecialEvent, \
    StatusFlags, TimeStamp, VTClass, VTSession, WriteStatus
from .apdu import EventNotificationParameters, ReadAccessSpecification, \
    ReadAccessResult

#------------------------------------------------------------------------------

# some debugging
_debug = 0
_log = ModuleLogger(globals())

#
#   PropertyError
#

class PropertyError(AttributeError):
    pass

# a dictionary of object types and classes
registered_object_types = {}

#
#   register_object_type
#

@bacpypes_debugging
def register_object_type(cls=None, vendor_id=0):
    if _debug: register_object_type._debug("register_object_type %s vendor_id=%s", repr(cls), vendor_id)

    # if cls isn't given, return a decorator
    if not cls:
        def _register(xcls):
            if _debug: register_object_type._debug("_register %s (vendor_id=%s)", repr(cls), vendor_id)
            return register_object_type(xcls, vendor_id)
        if _debug: register_object_type._debug("    - returning decorator")

        return _register

    # make sure it's an Object derived class
    if not issubclass(cls, Object):
        raise RuntimeError("Object derived class required")

    # build a property dictionary by going through the class and all its parents
    _properties = {}
    for c in cls.__mro__:
        for prop in getattr(c, 'properties', []):
            if prop.identifier not in _properties:
                _properties[prop.identifier] = prop

    # if the object type hasn't been provided, make an immutable one
    if 'objectType' not in _properties:
        _properties['objectType'] = ReadableProperty('objectType', ObjectType, cls.objectType, mutable=False)

    # store this in the class
    cls._properties = _properties

    # now save this in all our types
    registered_object_types[(cls.objectType, vendor_id)] = cls

    # return the class as a decorator
    return cls

#
#   get_object_class
#

@bacpypes_debugging
def get_object_class(object_type, vendor_id=0):
    """Return the class associated with an object type."""
    if _debug: get_object_class._debug("get_object_class %r vendor_id=%r", object_type, vendor_id)

    # find the klass as given
    cls = registered_object_types.get((object_type, vendor_id))
    if _debug: get_object_class._debug("    - direct lookup: %s", repr(cls))

    # if the class isn't found and the vendor id is non-zero, try the standard class for the type
    if (not cls) and vendor_id:
        cls = registered_object_types.get((object_type, 0))
        if _debug: get_object_class._debug("    - default lookup: %s", repr(cls))

    return cls

#
#   get_datatype
#

@bacpypes_debugging
def get_datatype(object_type, propid, vendor_id=0):
    """Return the datatype for the property of an object."""
    if _debug: get_datatype._debug("get_datatype %r %r vendor_id=%r", object_type, propid, vendor_id)

    # get the related class
    cls = get_object_class(object_type, vendor_id)
    if not cls:
        return None

    # get the property
    prop = cls._properties.get(propid)
    if not prop:
        return None

    # return the datatype
    return prop.datatype

#
#   Property
#

@bacpypes_debugging
class Property:

    def __init__(self, identifier, datatype, default=None, optional=True, mutable=True):
        if _debug:
            Property._debug("__init__ %s %s default=%r optional=%r mutable=%r",
                identifier, datatype, default, optional, mutable
                )

        # keep the arguments
        self.identifier = identifier
        self.datatype = datatype
        self.optional = optional
        self.mutable = mutable
        self.default = default

    def ReadProperty(self, obj, arrayIndex=None):
        if _debug:
            Property._debug("ReadProperty(%s) %s arrayIndex=%r",
                self.identifier, obj, arrayIndex
                )

        # get the value
        value = obj._values[self.identifier]

        # access an array
        if arrayIndex is not None:
            if not issubclass(self.datatype, Array):
                raise ExecutionError(errorClass='property', errorCode='propertyIsNotAnArray')

            if value is not None:
                try:
                    # dive in, the water's fine
                    value = value[arrayIndex]
                except IndexError:
                    raise ExecutionError(errorClass='property', errorCode='invalidArrayIndex')

        # all set
        return value

    def WriteProperty(self, obj, value, arrayIndex=None, priority=None, direct=False):
        if _debug:
            Property._debug("WriteProperty(%s) %s %r arrayIndex=%r priority=%r direct=%r",
                self.identifier, obj, value, arrayIndex, priority, direct
                )

        if direct:
            if _debug: Property._debug("    - direct write")
        else:
            # see if it must be provided
            if not self.optional and value is None:
                raise ValueError("%s value required" % (self.identifier,))

            # see if it can be changed
            if not self.mutable:
                raise ExecutionError(errorClass='property', errorCode='writeAccessDenied')

            # if it's atomic, make sure it's valid
            if issubclass(self.datatype, Atomic):
                if _debug: Property._debug("    - property is atomic, checking value")
                if not self.datatype.is_valid(value):
                    raise InvalidParameterDatatype("%s must be of type %s" % (
                            self.identifier, self.datatype.__name__,
                            ))

            elif not isinstance(value, self.datatype):
                if _debug: Property._debug("    - property is not atomic and wrong type")
                raise InvalidParameterDatatype("%s must be of type %s" % (
                        self.identifier, self.datatype.__name__,
                        ))

        # local check if the property is monitored
        is_monitored = self.identifier in obj._property_monitors

        if arrayIndex is not None:
            if not issubclass(self.datatype, Array):
                raise ExecutionError(errorClass='property', errorCode='propertyIsNotAnArray')

            # check the array
            arry = obj._values[self.identifier]
            if arry is None:
                raise RuntimeError("%s uninitialized array" % (self.identifier,))

            if is_monitored:
                old_value = _copy(arry)

            # seems to be OK, let the array object take over
            if _debug: Property._debug("    - forwarding to array")
            try:
                arry[arrayIndex] = value
            except IndexError:
                raise ExecutionError(errorClass='property', errorCode='invalidArrayIndex')

            # check for monitors, call each one with the old and new value
            if is_monitored:
                for fn in obj._property_monitors[self.identifier]:
                    if _debug: Property._debug("    - monitor: %r", fn)
                    fn(old_value, arry)

        else:
            if is_monitored:
                old_value = obj._values.get(self.identifier, None)

            # seems to be OK
            obj._values[self.identifier] = value

            # check for monitors, call each one with the old and new value
            if is_monitored:
                for fn in obj._property_monitors[self.identifier]:
                    if _debug: Property._debug("    - monitor: %r", fn)
                    fn(old_value, value)

#
#   StandardProperty
#

@bacpypes_debugging
class StandardProperty(Property):

    def __init__(self, identifier, datatype, default=None, optional=True, mutable=True):
        if _debug:
            StandardProperty._debug("__init__ %s %s default=%r optional=%r mutable=%r",
                identifier, datatype, default, optional, mutable
                )

        # use one of the subclasses
        if not isinstance(self, (OptionalProperty, ReadableProperty, WritableProperty)):
            raise ConfigurationError(self.__class__.__name__ + " must derive from OptionalProperty, ReadableProperty, or WritableProperty")

        # validate the identifier to be one of the standard property enumerations
        if identifier not in PropertyIdentifier.enumerations:
            raise ConfigurationError("unknown standard property identifier: %s" % (identifier,))

        # continue with the initialization
        Property.__init__(self, identifier, datatype, default, optional, mutable)

#
#   OptionalProperty
#

@bacpypes_debugging
class OptionalProperty(StandardProperty):

    """The property is required to be present and readable using BACnet services."""

    def __init__(self, identifier, datatype, default=None, optional=True, mutable=False):
        if _debug:
            OptionalProperty._debug("__init__ %s %s default=%r optional=%r mutable=%r",
                identifier, datatype, default, optional, mutable
                )

        # continue with the initialization
        StandardProperty.__init__(self, identifier, datatype, default, optional, mutable)

#
#   ReadableProperty
#

@bacpypes_debugging
class ReadableProperty(StandardProperty):

    """The property is required to be present and readable using BACnet services."""

    def __init__(self, identifier, datatype, default=None, optional=False, mutable=False):
        if _debug:
            ReadableProperty._debug("__init__ %s %s default=%r optional=%r mutable=%r",
                identifier, datatype, default, optional, mutable
                )

        # continue with the initialization
        StandardProperty.__init__(self, identifier, datatype, default, optional, mutable)

#
#   WritableProperty
#

@bacpypes_debugging
class WritableProperty(StandardProperty):

    """The property is required to be present, readable, and writable using BACnet services."""

    def __init__(self, identifier, datatype, default=None, optional=False, mutable=True):
        if _debug:
            WritableProperty._debug("__init__ %s %s default=%r optional=%r mutable=%r",
                identifier, datatype, default, optional, mutable
                )

        # continue with the initialization
        StandardProperty.__init__(self, identifier, datatype, default, optional, mutable)

#
#   ObjectIdentifierProperty
#

@bacpypes_debugging
class ObjectIdentifierProperty(ReadableProperty):

    def WriteProperty(self, obj, value, arrayIndex=None, priority=None, direct=False):
        if _debug: ObjectIdentifierProperty._debug("WriteProperty %r %r arrayIndex=%r priority=%r", obj, value, arrayIndex, priority)

        # make it easy to default
        if value is None:
            pass
        elif isinstance(value, int):
            value = (obj.objectType, value)
        elif isinstance(value, tuple) and len(value) == 2:
            if value[0] != obj.objectType:
                raise ValueError("%s required" % (obj.objectType,))
        else:
            raise TypeError("Object_Identifier")

        return Property.WriteProperty( self, obj, value, arrayIndex, priority, direct )

#
#   Object
#

@bacpypes_debugging
class Object:

    _debug_contents = ('_app',)

    properties = \
        [ ObjectIdentifierProperty('Object_Identifier', ObjectIdentifier, optional=False)
        , ReadableProperty('Object_Name', CharacterString, optional=False)
        , ReadableProperty('Description', CharacterString)
        , ReadableProperty('Property_List', ArrayOf(PropertyIdentifier))
        , OptionalProperty('Profile_Name', CharacterString)
        ]
    _properties = {}

    def __init__(self, **kwargs):
        """Create an object, with default property values as needed."""
        if _debug: Object._debug("__init__(%s) %r", self.__class__.__name__, kwargs)

        # map the python names into property names and make sure they
        # are appropriate for this object
        initargs = {}
        for key, value in kwargs.items():
            if key not in self._properties:
                raise PropertyError(key)
            initargs[key] = value

        # object is detached from an application until it is added
        self._app = None

        # start with a clean dict of values
        self._values = {}

        # empty list of property monitors
        self._property_monitors = defaultdict(list)

        # start with a clean array of property identifiers
        if 'Property_List' in initargs:
            propertyList = None
        else:
            propertyList = ArrayOf(PropertyIdentifier)()
            initargs['Property_List'] = propertyList

        # initialize the object
        for propid, prop in self._properties.items():
            if propid in initargs:
                if _debug: Object._debug("    - setting %s from initargs", propid)

                # defer to the property object for error checking
                prop.WriteProperty(self, initargs[propid], direct=True)

                # add it to the property list if we are building one
                if propertyList is not None:
                    propertyList.append(propid)

            elif prop.default is not None:
                if _debug: Object._debug("    - setting %s from default", propid)

                # default values bypass property interface
                self._values[propid] = prop.default

                # add it to the property list if we are building one
                if propertyList is not None:
                    propertyList.append(propid)

            else:
                if not prop.optional:
                    if _debug: Object._debug("    - %s value required", propid)

                self._values[propid] = None

        if _debug: Object._debug("    - done __init__")


    def _attr_to_property(self, attr):
        """Common routine to translate a python attribute name to a property name and
        return the appropriate property."""
        prop = self._properties.get(attr)
        if not prop:
            raise PropertyError(attr)
        return prop


    def __getattr__(self, attr):
        if _debug: Object._debug("__getattr__ %r", attr)

        # do not redirect private attrs or functions
        if attr.startswith('_') or attr[0].isupper() or (attr == 'debug_contents'):
            return object.__getattribute__(self, attr)

        # defer to the property to get the value
        prop = self._attr_to_property(attr)
        if _debug: Object._debug("    - deferring to %r", prop)

        # defer to the property to get the value
        return prop.ReadProperty(self)

    def __setattr__(self, attr, value):
        if _debug: Object._debug("__setattr__ %r %r", attr, value)

        if attr.startswith('_') or attr[0].isupper() or (attr == 'debug_contents'):
            return object.__setattr__(self, attr, value)

        # defer to the property to normalize the value
        prop = self._attr_to_property(attr)
        if _debug: Object._debug("    - deferring to %r", prop)

        return prop.WriteProperty(self, value, direct=True)

    def add_property(self, prop):
        """Add a property to an object.  The property is an instance of
        a Property or one of its derived classes.  Adding a property
        disconnects it from the collection of properties common to all of the
        objects of its class."""
        if _debug: Object._debug("add_property %r", prop)

        # make a copy of the properties dictionary
        self._properties = _copy(self._properties)

        # save the property reference and default value (usually None)
        self._properties[prop.identifier] = prop
        self._values[prop.identifier] = prop.default

        # tell the object it has a new property
        if 'propertyList' in self._values:
            property_list = self.propertyList
            if prop.identifier not in property_list:
                if _debug: Object._debug("    - adding to property list")
                property_list.append(prop.identifier)

    def delete_property(self, prop):
        """Delete a property from an object.  The property is an instance of
        a Property or one of its derived classes, but only the property
        is relavent.  Deleting a property disconnects it from the collection of
        properties common to all of the objects of its class."""
        if _debug: Object._debug("delete_property %r", value)

        # make a copy of the properties dictionary
        self._properties = _copy(self._properties)

        # delete the property from the dictionary and values
        del self._properties[prop.identifier]
        if prop.identifier in self._values:
            del self._values[prop.identifier]

        # remove the property identifier from its list of know properties
        if 'propertyList' in self._values:
            property_list = self.propertyList
            if prop.identifier in property_list:
                if _debug: Object._debug("    - removing from property list")
                property_list.remove(prop.identifier)

    def ReadProperty(self, propid, arrayIndex=None):
        if _debug: Object._debug("ReadProperty %r arrayIndex=%r", propid, arrayIndex)

        # get the property
        prop = self._properties.get(propid)
        if not prop:
            raise PropertyError(propid)

        # defer to the property to get the value
        return prop.ReadProperty(self, arrayIndex)

    def WriteProperty(self, propid, value, arrayIndex=None, priority=None, direct=False):
        if _debug: Object._debug("WriteProperty %r %r arrayIndex=%r priority=%r", propid, value, arrayIndex, priority)

        # get the property
        prop = self._properties.get(propid)
        if not prop:
            raise PropertyError(propid)

        # defer to the property to set the value
        return prop.WriteProperty(self, value, arrayIndex, priority, direct)

    def get_datatype(self, propid):
        """Return the datatype for the property of an object."""
        if _debug: Object._debug("get_datatype %r", propid)

        # get the property
        prop = self._properties.get(propid)
        if not prop:
            raise PropertyError(propid)

        # return the datatype
        return prop.datatype

    def _dict_contents(self, use_dict=None, as_class=dict):
        """Return the contents of an object as a dict."""
        if _debug: Object._debug("dict_contents use_dict=%r as_class=%r", use_dict, as_class)

        # make/extend the dictionary of content
        if use_dict is None:
            use_dict = as_class()

        klasses = list(self.__class__.__mro__)
        klasses.reverse()

        # build a list of property identifiers "bottom up"
        property_names = []
        properties_seen = set()
        for c in klasses:
            for prop in getattr(c, 'properties', []):
                if prop.identifier not in properties_seen:
                    property_names.append(prop.identifier)
                    properties_seen.add(prop.identifier)

        # extract the values
        for property_name in property_names:
            # get the value
            property_value = self._properties.get(property_name).ReadProperty(self)
            if property_value is None:
                continue

            # if the value has a way to convert it to a dict, use it
            if hasattr(property_value, "dict_contents"):
                property_value = property_value.dict_contents(as_class=as_class)

            # save the value
            use_dict.__setitem__(property_name, property_value)

        # return what we built/updated
        return use_dict

    def debug_contents(self, indent=1, file=sys.stdout, _ids=None):
        """Print out interesting things about the object."""
        klasses = list(self.__class__.__mro__)
        klasses.reverse()

        # print special attributes "bottom up"
        previous_attrs = ()
        for c in klasses:
            attrs = getattr(c, '_debug_contents', ())

            # if we have seen this list already, move to the next class
            if attrs is previous_attrs:
                continue

            for attr in attrs:
                file.write("%s%s = %s\n" % ("    " * indent, attr, getattr(self, attr)))
            previous_attrs = attrs

        # build a list of property identifiers "bottom up"
        property_names = []
        properties_seen = set()
        for c in klasses:
            for prop in getattr(c, 'properties', []):
                if prop.identifier not in properties_seen:
                    property_names.append(prop.identifier)
                    properties_seen.add(prop.identifier)

        # print out the values
        for property_name in property_names:
            property_value = self._values.get(property_name, None)

            # printing out property values that are None is tedious
            if property_value is None:
                continue

            if hasattr(property_value, "debug_contents"):
                file.write("%s%s\n" % ("    " * indent, property_name))
                property_value.debug_contents(indent+1, file, _ids)
            else:
                file.write("%s%s = %r\n" % ("    " * indent, property_name, property_value))


#------------------------------------------------------------------------------

@register_object_type
class AccessCredentialObject(Object):
    objectType = 'accessCredential'
    type= 'AC'
    properties = \
        [ WritableProperty('globalIdentifier', Unsigned)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('credentialStatus', BinaryPV)
        , ReadableProperty('reasonForDisable', SequenceOf(AccessCredentialDisableReason))
        , ReadableProperty('authenticationFactors', ArrayOf(CredentialAuthenticationFactor))
        , ReadableProperty('activationTime', DateTime)
        , ReadableProperty('expiryTime', DateTime)
        , ReadableProperty('credentialDisable', AccessCredentialDisable)
        , OptionalProperty('daysRemaining', Integer)
        , OptionalProperty('usesRemaining', Integer)
        , OptionalProperty('absenteeLimit', Unsigned)
        , OptionalProperty('belongsTo', DeviceObjectReference)
        , ReadableProperty('assignedAccessRights', ArrayOf(AssignedAccessRights))
        , OptionalProperty('lastAccessPoint', DeviceObjectReference)
        , OptionalProperty('lastAccessEvent', AccessEvent)
        , OptionalProperty('lastUseTime', DateTime)
        , OptionalProperty('traceFlag', Boolean)
        , OptionalProperty('threatAuthority', AccessThreatLevel)
        , OptionalProperty('extendedTimeEnable', Boolean)
        , OptionalProperty('authorizationExemptions', SequenceOf(AuthorizationException))
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
#       , OptionalProperty('masterExemption', Boolean)
#       , OptionalProperty('passbackExemption', Boolean)
#       , OptionalProperty('occupancyExemption', Boolean)
        ]

@register_object_type
class AccessDoorObject(Object):
    objectType = 'accessDoor'
    type= 'AD'
    properties = \
        [ WritableProperty('Present_Value', DoorValue)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('Priority_Array', PriorityArray)
        , ReadableProperty('Relinquish_Default', DoorValue)
        , OptionalProperty('doorStatus', DoorStatus)
        , OptionalProperty('lockStatus', LockStatus)
        , OptionalProperty('securedStatus', DoorSecuredStatus)
        , OptionalProperty('doorMembers', ArrayOf(DeviceObjectReference))
        , ReadableProperty('doorPulseTime', Unsigned)
        , ReadableProperty('doorExtendedPulseTime', Unsigned)
        , OptionalProperty('doorUnlockDelayTime', Unsigned)
        , ReadableProperty('doorOpenTooLongTime', Unsigned)
        , OptionalProperty('doorAlarmState', DoorAlarmState)
        , OptionalProperty('maskedAlarmValues', SequenceOf(DoorAlarmState))
        , OptionalProperty('maintenanceRequired', Maintenance)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('alarmValues', SequenceOf(DoorAlarmState))
        , OptionalProperty('faultValues', SequenceOf(DoorAlarmState))
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        ]

@register_object_type
class AccessPointObject(Object):
    objectType = 'accessPoint'
    type= 'AP'
    properties = \
        [ ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('authenticationStatus', AuthenticationStatus)
        , ReadableProperty('activeAuthenticationPolicy', Unsigned)
        , ReadableProperty('numberOfAuthenticationPolicies', Unsigned)
        , OptionalProperty('authenticationPolicyList', ArrayOf(AuthenticationPolicy))
        , OptionalProperty('authenticationPolicyNames', ArrayOf(CharacterString))
        , ReadableProperty('authorizationMode', AuthorizationMode)
        , OptionalProperty('verificationTime', Unsigned)
        , OptionalProperty('lockout', Boolean)
        , OptionalProperty('lockoutRelinquishTime', Unsigned)
        , OptionalProperty('failedAttempts', Unsigned)
        , OptionalProperty('failedAttemptEvents', SequenceOf(AccessEvent))
        , OptionalProperty('maxFailedAttempts', Unsigned)
        , OptionalProperty('failedAttemptsTime', Unsigned)
        , OptionalProperty('threatLevel', AccessThreatLevel)
        , OptionalProperty('occupancyUpperLimitEnforced', Boolean)
        , OptionalProperty('occupancyLowerLimitEnforced', Boolean)
        , OptionalProperty('occupancyCountAdjust', Boolean)
        , OptionalProperty('accompanimentTime', Unsigned)
        , ReadableProperty('accessEvent', AccessEvent)
        , ReadableProperty('accessEventTag', Unsigned)
        , ReadableProperty('accessEventTime', TimeStamp)
        , ReadableProperty('accessEventCredential', DeviceObjectReference)
        , OptionalProperty('accessEventAuthenticationFactor', AuthenticationFactor)
        , ReadableProperty('accessDoors', ArrayOf(DeviceObjectReference))
        , ReadableProperty('priorityForWriting', Unsigned)
        , OptionalProperty('musterPoint', Boolean)
        , OptionalProperty('zoneTo', DeviceObjectReference)
        , OptionalProperty('zoneFrom', DeviceObjectReference)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('transactionNotificationClass', Unsigned)
        , OptionalProperty('accessAlarmEvents', SequenceOf(AccessEvent))
        , OptionalProperty('accessTransactionEvents', SequenceOf(AccessEvent))
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class AccessRightsObject(Object):
    objectType = 'accessRights'
    type= 'AR'
    properties = \
        [ WritableProperty('globalIdentifier', Unsigned)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('Enable', Boolean)
        , ReadableProperty('negativeAccessRules', ArrayOf(AccessRule))
        , ReadableProperty('positiveAccessRules', ArrayOf(AccessRule))
        , OptionalProperty('accompaniment', DeviceObjectReference)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class AccessUserObject(Object):
    objectType = 'accessUser'
    type= 'AU'
    properties = \
        [ WritableProperty('globalIdentifier', Unsigned)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('userType', AccessUserType)
        , OptionalProperty('userName', CharacterString)
        , OptionalProperty('userExternalIdentifier', CharacterString)
        , OptionalProperty('userInformationReference', CharacterString)
        , OptionalProperty('members', SequenceOf(DeviceObjectReference))
        , OptionalProperty('memberOf', SequenceOf(DeviceObjectReference))
        , ReadableProperty('credentials', SequenceOf(DeviceObjectReference))
       ]

@register_object_type
class AccessZoneObject(Object):
    objectType = 'accessZone'
    type= 'AZ'
    properties = \
        [ WritableProperty('globalIdentifier', Unsigned)
        , ReadableProperty('occupancyState', AccessZoneOccupancyState)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , OptionalProperty('occupancyCount', Unsigned)
        , OptionalProperty('occupancyCountEnable', Boolean)
        , OptionalProperty('adjustValue', Integer)
        , OptionalProperty('occupancyUpperLimit', Unsigned)
        , OptionalProperty('occupancyLowerLimit', Unsigned)
        , OptionalProperty('credentialsInZone', SequenceOf(DeviceObjectReference) )
        , OptionalProperty('lastCredentialAdded', DeviceObjectReference)
        , OptionalProperty('lastCredentialAddedTime', DateTime)
        , OptionalProperty('lastCredentialRemoved', DeviceObjectReference)
        , OptionalProperty('lastCredentialRemovedTime', DateTime)
        , OptionalProperty('passbackMode', AccessPassbackMode)
        , OptionalProperty('passbackTimeout', Unsigned)
        , ReadableProperty('entryPoints', SequenceOf(DeviceObjectReference))
        , ReadableProperty('exitPoints', SequenceOf(DeviceObjectReference))
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('alarmValues', SequenceOf(AccessZoneOccupancyState))
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class AccumulatorObject(Object):
    objectType = 'accumulator'
    type= 'ACC'
    properties = \
        [ ReadableProperty('Present_Value', Unsigned)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('scale', Scale)
        , ReadableProperty('Units', EngineeringUnits)
        , OptionalProperty('prescale', Prescale)
        , ReadableProperty('Max_Pres_Value', Unsigned)
        , OptionalProperty('valueChangeTime', DateTime)
        , OptionalProperty('valueBeforeChange', Unsigned)
        , OptionalProperty('valueSet', Unsigned)
        , OptionalProperty('loggingRecord', AccumulatorRecord)
        , OptionalProperty('loggingObject', ObjectIdentifier)
        , OptionalProperty('pulseRate', Unsigned)
        , OptionalProperty('highLimit', Unsigned)
        , OptionalProperty('lowLimit', Unsigned)
        , OptionalProperty('limitMonitoringInterval', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('limitEnable', LimitEnable)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class AlertEnrollmentObject(Object):
    objectType = 'alertEnrollment'
    properties = \
        [ ReadableProperty('Present_Value', ObjectIdentifier)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('eventDetectionEnable', Boolean)
        , ReadableProperty('notificationClass', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        ]

@register_object_type
class AnalogInputObject(Object):
    objectType = 'analogInput'
    type= 'AI'
    properties = \
        [ ReadableProperty('Present_Value', Real)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Update_Interval', Unsigned)
        , ReadableProperty('Units', EngineeringUnits)
        , OptionalProperty('Min_Pres_Value', Real)
        , OptionalProperty('Max_Pres_Value', Real)
        , OptionalProperty('Resolution', Real)
        , OptionalProperty('covIncrement', Real)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('highLimit', Real)
        , OptionalProperty('lowLimit', Real)
        , OptionalProperty('deadband', Real)
        , OptionalProperty('limitEnable', LimitEnable)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class AnalogOutputObject(Object):
    objectType = 'analogOutput'
    properties = \
        [ WritableProperty('Present_Value', Real)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('Units',  EngineeringUnits)
        , OptionalProperty('Min_Pres_Value', Real)
        , OptionalProperty('Max_Pres_Value', Real)
        , OptionalProperty('Resolution', Real)
        , ReadableProperty('Priority_Array', PriorityArray)
        , ReadableProperty('Relinquish_Default', Real)
        , OptionalProperty('covIncrement', Real)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('highLimit', Real)
        , OptionalProperty('lowLimit', Real)
        , OptionalProperty('deadband', Real)
        , OptionalProperty('limitEnable', LimitEnable)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions',  EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class AnalogValueObject(Object):
    objectType = 'analogValue'
    properties = \
        [ ReadableProperty('Present_Value', Real)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('Units', EngineeringUnits)
        , OptionalProperty('Min_Pres_Value', Real)
        , OptionalProperty('Max_Pres_Value', Real)
        , OptionalProperty('Resolution', Real)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Real)
        , OptionalProperty('covIncrement', Real)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass',  Unsigned)
        , OptionalProperty('highLimit', Real)
        , OptionalProperty('lowLimit', Real)
        , OptionalProperty('deadband', Real)
        , OptionalProperty('limitEnable', LimitEnable)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class AveragingObject(Object):
    objectType = 'averaging'
    properties = \
        [ ReadableProperty('minimumValue', Real)
        , OptionalProperty('minimumValueTimestamp', DateTime)
        , ReadableProperty('averageValue', Real)
        , OptionalProperty('varianceValue', Real)
        , ReadableProperty('maximumValue', Real)
        , OptionalProperty('maximumValueTimestamp', DateTime)
        , WritableProperty('attemptedSamples', Unsigned)
        , ReadableProperty('validSamples', Unsigned)
        , ReadableProperty('objectPropertyReference', DeviceObjectPropertyReference)
        , WritableProperty('windowInterval', Unsigned)
        , WritableProperty('windowSamples', Unsigned)
        ]

@register_object_type
class BinaryInputObject(Object):
    objectType = 'binaryInput'
    properties = \
        [ ReadableProperty('Present_Value', BinaryPV)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('polarity', Polarity)
        , OptionalProperty('inactiveText', CharacterString)
        , OptionalProperty('activeText', CharacterString)
        , OptionalProperty('changeOfStateTime', DateTime)
        , OptionalProperty('changeOfStateCount', Unsigned)
        , OptionalProperty('timeOfStateCountReset', DateTime)
        , OptionalProperty('elapsedActiveTime', Unsigned)
        , OptionalProperty('timeOfActiveTimeReset', DateTime)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('alarmValue', BinaryPV)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class BinaryOutputObject(Object):
    objectType = 'binaryOutput'
    properties = \
        [ WritableProperty('Present_Value', BinaryPV)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('polarity', Polarity)
        , OptionalProperty('inactiveText', CharacterString)
        , OptionalProperty('activeText', CharacterString)
        , OptionalProperty('changeOfStateTime', DateTime)
        , OptionalProperty('changeOfStateCount', Unsigned)
        , OptionalProperty('timeOfStateCountReset', DateTime)
        , OptionalProperty('elapsedActiveTime', Unsigned)
        , OptionalProperty('timeOfActiveTimeReset', DateTime)
        , OptionalProperty('minimumOffTime', Unsigned)
        , OptionalProperty('minimumOnTime', Unsigned)
        , ReadableProperty('Priority_Array', PriorityArray)
        , ReadableProperty('Relinquish_Default', BinaryPV)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('feedbackValue', BinaryPV)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class BinaryValueObject(Object):
    objectType = 'binaryValue'
    properties = \
        [ WritableProperty('Present_Value', BinaryPV)
        , ReadableProperty('Status_Flags',StatusFlags)
        , ReadableProperty('Event_State',EventState)
        , OptionalProperty('Reliability',Reliability)
        , ReadableProperty('Out_Of_Service',Boolean)
        , OptionalProperty('inactiveText',CharacterString)
        , OptionalProperty('activeText',CharacterString)
        , OptionalProperty('changeOfStateTime',DateTime)
        , OptionalProperty('changeOfStateCount',Unsigned)
        , OptionalProperty('timeOfStateCountReset',DateTime)
        , OptionalProperty('elapsedActiveTime',Unsigned)
        , OptionalProperty('timeOfActiveTimeReset',DateTime)
        , OptionalProperty('minimumOffTime',Unsigned)
        , OptionalProperty('minimumOnTime',Unsigned)
        , OptionalProperty('Priority_Array',PriorityArray)
        , OptionalProperty('Relinquish_Default',BinaryPV)
        , OptionalProperty('timeDelay',Unsigned)
        , OptionalProperty('notificationClass',Unsigned)
        , OptionalProperty('alarmValue',BinaryPV)
        , OptionalProperty('eventEnable',EventTransitionBits)
        , OptionalProperty('ackedTransitions',EventTransitionBits)
        , OptionalProperty('notifyType',NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class BitStringValueObject(Object):
    objectType = 'bitstringValue'
    properties = \
        [ ReadableProperty('Present_Value', BitString)
        , OptionalProperty('bitText', ArrayOf(CharacterString))
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', BitString)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('alarmValues', ArrayOf(BitString))
        , OptionalProperty('bitMask', BitString)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class CalendarObject(Object):
    objectType = 'calendar'
    properties = \
        [ ReadableProperty('Present_Value', Boolean)
        , ReadableProperty('dateList', SequenceOf(CalendarEntry))
        ]

@register_object_type
class ChannelObject(Object):
    objectType = 'channel'
    properties = \
        [ WritableProperty('Present_Value', ChannelValue)
        , ReadableProperty('lastPriority', Unsigned)
        , ReadableProperty('writeStatus', WriteStatus)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , WritableProperty('listOfObjectPropertyReferences', ArrayOf(DeviceObjectPropertyReference))
        , OptionalProperty('executionDelay', ArrayOf(Unsigned))
        , OptionalProperty('allowGroupDelayInhibit', Boolean)
        , WritableProperty('channelNumber', Unsigned)
        , WritableProperty('controlGroups', ArrayOf(Unsigned))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class CharacterStringValueObject(Object):
    objectType = 'characterstringValue'
    properties = \
        [ ReadableProperty('Present_Value', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', CharacterString)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('alarmValues', ArrayOf(OptionalCharacterString))
        , OptionalProperty('faultValues', ArrayOf(OptionalCharacterString))
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class CommandObject(Object):
    objectType = 'command'
    properties = \
        [ WritableProperty('Present_Value', Unsigned)
        , ReadableProperty('inProcess', Boolean)
        , ReadableProperty('allWritesSuccessful', Boolean)
        , ReadableProperty('action', ArrayOf(ActionList))
        , OptionalProperty('actionText', ArrayOf(CharacterString))
        ]

@register_object_type
class CredentialDataInputObject(Object):
    objectType = 'credentialDataInput'
    properties = \
        [ ReadableProperty('Present_Value', AuthenticationFactor)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('supportedFormats', ArrayOf(AuthenticationFactorFormat))
        , OptionalProperty('supportedFormatClasses', ArrayOf(Unsigned))
        , ReadableProperty('updateTime', TimeStamp)
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class DatePatternValueObject(Object):
    objectType = 'datePatternValue'
    properties = \
        [ ReadableProperty('Present_Value', Date)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Date)
        ]

@register_object_type
class DateValueObject(Object):
    objectType = 'dateValue'
    properties = \
        [ ReadableProperty('Present_Value', Date)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Date)
        ]

@register_object_type
class DateTimePatternValueObject(Object):
    objectType = 'datetimePatternValue'
    properties = \
        [ ReadableProperty('Present_Value', DateTime)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', DateTime)
        , OptionalProperty('isUtc', Boolean)
        ]

@register_object_type
class DateTimeValueObject(Object):
    objectType = 'datetimeValue'
    properties = \
        [ ReadableProperty('Present_Value', DateTime)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', DateTime)
        , OptionalProperty('isUtc', Boolean)
        ]

@register_object_type
class DeviceObject(Object):
    objectType = 'device'
    properties = \
        [ ReadableProperty('systemStatus', DeviceStatus)
        , ReadableProperty('vendorName', CharacterString)
        , ReadableProperty('vendorIdentifier', Unsigned)
        , ReadableProperty('modelName', CharacterString)
        , ReadableProperty('firmwareRevision', CharacterString)
        , ReadableProperty('applicationSoftwareVersion', CharacterString)
        , OptionalProperty('location', CharacterString)
        , ReadableProperty('protocolVersion', Unsigned)
        , ReadableProperty('protocolRevision', Unsigned)
        , ReadableProperty('protocolServicesSupported', ServicesSupported)
        , ReadableProperty('protocolObjectTypesSupported', ObjectTypesSupported)
        , ReadableProperty('objectList', ArrayOf(ObjectIdentifier))
        , OptionalProperty('structuredObjectList', ArrayOf(ObjectIdentifier))
        , ReadableProperty('maxApduLengthAccepted', Unsigned)
        , ReadableProperty('segmentationSupported', Segmentation)
        , OptionalProperty('vtClassesSupported', SequenceOf(VTClass))
        , OptionalProperty('activeVtSessions', SequenceOf(VTSession))
        , OptionalProperty('localTime', Time)
        , OptionalProperty('localDate', Date)
        , OptionalProperty('utcOffset', Integer)
        , OptionalProperty('daylightSavingsStatus', Boolean)
        , OptionalProperty('apduSegmentTimeout', Unsigned)
        , ReadableProperty('apduTimeout', Unsigned)
        , ReadableProperty('numberOfApduRetries', Unsigned)
        , OptionalProperty('timeSynchronizationRecipients', SequenceOf(Recipient))
        , OptionalProperty('maxMaster', Unsigned)
        , OptionalProperty('maxInfoFrames', Unsigned)
        , ReadableProperty('deviceAddressBinding', SequenceOf(AddressBinding))
        , ReadableProperty('databaseRevision', Unsigned)
        , OptionalProperty('configurationFiles', ArrayOf(ObjectIdentifier))
        , OptionalProperty('lastRestoreTime', TimeStamp)
        , OptionalProperty('backupFailureTimeout', Unsigned)
        , OptionalProperty('backupPreparationTime', Unsigned)
        , OptionalProperty('restorePreparationTime', Unsigned)
        , OptionalProperty('restoreCompletionTime', Unsigned)
        , OptionalProperty('backupAndRestoreState', BackupState)
        , OptionalProperty('activeCovSubscriptions', SequenceOf(COVSubscription))
        , OptionalProperty('maxSegmentsAccepted', Unsigned)
        , OptionalProperty('slaveProxyEnable', ArrayOf(Boolean))
        , OptionalProperty('autoSlaveDiscovery', ArrayOf(Boolean))
        , OptionalProperty('slaveAddressBinding', SequenceOf(AddressBinding))
        , OptionalProperty('manualSlaveAddressBinding', SequenceOf(AddressBinding))
        , OptionalProperty('lastRestartReason', RestartReason)
        , OptionalProperty('timeOfDeviceRestart', TimeStamp)
        , OptionalProperty('restartNotificationRecipients', SequenceOf(Recipient))
        , OptionalProperty('utcTimeSynchronizationRecipients', SequenceOf(Recipient))
        , OptionalProperty('timeSynchronizationInterval', Unsigned)
        , OptionalProperty('alignIntervals', Boolean)
        , OptionalProperty('intervalOffset', Unsigned)
        , OptionalProperty('serialNumber', CharacterString)
        ]

@register_object_type
class EventEnrollmentObject(Object):
    objectType = 'eventEnrollment'
    properties = \
        [ ReadableProperty('eventType', EventType)
        , ReadableProperty('notifyType', NotifyType)
        , ReadableProperty('eventParameters', EventParameter)
        , ReadableProperty('objectPropertyReference', DeviceObjectPropertyReference)
        , ReadableProperty('Event_State', EventState)
        , ReadableProperty('eventEnable', EventTransitionBits)
        , ReadableProperty('ackedTransitions', EventTransitionBits)
        , ReadableProperty('notificationClass', Unsigned)
        , ReadableProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Reliability', Reliability)
        , OptionalProperty('faultType', FaultType)
        , OptionalProperty('faultParameters', FaultParameter)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

#-----

class EventLogRecordLogDatum(Choice):
    choiceElements = \
        [ Element('logStatus', LogStatus, 0)
        , Element('notification', EventNotificationParameters, 1)
        , Element('timeChange', Real, 2)
        ]

class EventLogRecord(Sequence):
    sequenceElements = \
        [ Element('timestamp', DateTime, 0)
        , Element('logDatum', EventLogRecordLogDatum, 1)
        ]

@register_object_type
class EventLogObject(Object):
    objectType = 'eventLog'
    properties = \
        [ ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , WritableProperty('Enable', Boolean)
        , OptionalProperty('Start_Time', DateTime)
        , OptionalProperty('Stop_Time', DateTime)
        , ReadableProperty('Stop_When_Full', Boolean)
        , ReadableProperty('Buffer_Size', Unsigned)
        , ReadableProperty('Log_Buffer', SequenceOf(EventLogRecord))
        , WritableProperty('Record_Count', Unsigned)
        , ReadableProperty('Total_Record_Count', Unsigned)
        , OptionalProperty('Notification_Threshold', Unsigned)
        , OptionalProperty('Records_Since_Notification', Unsigned)
        , OptionalProperty('lastNotifyRecord', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        ]

#-----

@register_object_type
class FileObject(Object):
    objectType = 'file'
    properties = \
        [ ReadableProperty('fileType', CharacterString)
        , ReadableProperty('fileSize', Unsigned)
        , ReadableProperty('modificationDate', DateTime)
        , WritableProperty('archive', Boolean)
        , ReadableProperty('readOnly', Boolean)
        , ReadableProperty('fileAccessMethod', FileAccessMethod)
        , OptionalProperty('Record_Count', Unsigned)
        ]

#-----

@register_object_type
class GlobalGroupObject(Object):
    objectType = 'globalGroup'
    properties = \
        [ ReadableProperty('groupMembers', ArrayOf(DeviceObjectPropertyReference))
        , OptionalProperty('groupMemberNames', ArrayOf(CharacterString))
        , ReadableProperty('Present_Value', ArrayOf(PropertyAccessResult))
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , ReadableProperty('memberStatusFlags', StatusFlags)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , OptionalProperty('updateInterval', Unsigned)
        , OptionalProperty('requestedUpdateInterval', Unsigned)
        , OptionalProperty('covResubscriptionInterval', Unsigned)
        , OptionalProperty('clientCovIncrement', ClientCOV)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('covuPeriod', Unsigned)
        , OptionalProperty('covuRecipients', SequenceOf(Recipient))
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class GroupObject(Object):
    objectType = 'group'
    properties = \
        [ ReadableProperty('listOfGroupMembers', SequenceOf(ReadAccessSpecification))
        , ReadableProperty('Present_Value', SequenceOf(ReadAccessResult))
        ]

@register_object_type
class IntegerValueObject(Object):
    objectType = 'integerValue'
    properties = \
        [ ReadableProperty('Present_Value', Integer)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , ReadableProperty('Units', EngineeringUnits)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Integer)
        , OptionalProperty('covIncrement', Unsigned)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('highLimit', Integer)
        , OptionalProperty('lowLimit', Integer)
        , OptionalProperty('deadband', Unsigned)
        , OptionalProperty('limitEnable', LimitEnable)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        , OptionalProperty('Min_Pres_Value', Integer)
        , OptionalProperty('Max_Pres_Value', Integer)
        , OptionalProperty('Resolution', Integer)
        ]

@register_object_type
class LargeAnalogValueObject(Object):
    objectType = 'largeAnalogValue'
    properties = \
        [ ReadableProperty('Present_Value', Double)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , ReadableProperty('Units', EngineeringUnits)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Integer)
        , OptionalProperty('covIncrement', Unsigned)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('highLimit', Double)
        , OptionalProperty('lowLimit', Double)
        , OptionalProperty('deadband', Double)
        , OptionalProperty('limitEnable', LimitEnable)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        , OptionalProperty('Min_Pres_Value', Double)
        , OptionalProperty('Max_Pres_Value', Double)
        , OptionalProperty('Resolution', Double)
        ]

@register_object_type
class LifeSafetyPointObject(Object):
    objectType = 'lifeSafetyPoint'
    properties = \
        [ ReadableProperty('Present_Value', LifeSafetyState)
        , ReadableProperty('trackingValue', LifeSafetyState)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , WritableProperty('mode', LifeSafetyMode)
        , ReadableProperty('acceptedModes', SequenceOf(LifeSafetyMode))
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('lifeSafetyAlarmValues', SequenceOf(LifeSafetyState))
        , OptionalProperty('alarmValues', SequenceOf(LifeSafetyState))
        , OptionalProperty('faultValues', SequenceOf(LifeSafetyState))
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        , ReadableProperty('silenced', SilencedState)
        , ReadableProperty('operationExpected', LifeSafetyOperation)
        , OptionalProperty('maintenanceRequired', Maintenance)
        , OptionalProperty('setting', Unsigned)
        , OptionalProperty('directReading', Real)
        , OptionalProperty('Units', EngineeringUnits)
        , OptionalProperty('memberOf', SequenceOf(DeviceObjectReference))
        ]

@register_object_type
class LifeSafetyZoneObject(Object):
    objectType = 'lifeSafetyZone'
    properties = \
        [ ReadableProperty('Present_Value', LifeSafetyState)
        , ReadableProperty('trackingValue', LifeSafetyState)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , WritableProperty('mode', LifeSafetyMode)
        , ReadableProperty('acceptedModes', SequenceOf(LifeSafetyMode))
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('lifeSafetyAlarmValues', SequenceOf(LifeSafetyState))
        , OptionalProperty('alarmValues', SequenceOf(LifeSafetyState))
        , OptionalProperty('faultValues', SequenceOf(LifeSafetyState))
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        , ReadableProperty('silenced', SilencedState)
        , ReadableProperty('operationExpected', LifeSafetyOperation)
        , OptionalProperty('maintenanceRequired', Boolean)
        , ReadableProperty('zoneMembers', SequenceOf(DeviceObjectReference))
        , OptionalProperty('memberOf', SequenceOf(DeviceObjectReference))
        ]

@register_object_type
class LightingOutputObject(Object):
    objectType = 'lightingOutput'
    properties = \
        [ WritableProperty('Present_Value', Real)
        , ReadableProperty('trackingValue', Real)
        , WritableProperty('lightingCommand', LightingCommand)
        , ReadableProperty('inProgress', LightingInProgress)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('blinkWarnEnable', Boolean)
        , ReadableProperty('egressTime', Unsigned)
        , ReadableProperty('egressActive', Boolean)
        , ReadableProperty('defaultFadeTime', Unsigned)
        , ReadableProperty('defaultRampRate', Real)
        , ReadableProperty('defaultStepIncrement', Real)
        , OptionalProperty('transition', LightingTransition)
        , OptionalProperty('feedbackValue', Real)
        , ReadableProperty('Priority_Array', PriorityArray)
        , ReadableProperty('Relinquish_Default', Real)
        , OptionalProperty('power', Real)
        , OptionalProperty('instantaneousPower', Real)
        , OptionalProperty('minActualValue', Real)
        , OptionalProperty('maxActualValue', Real)
        , ReadableProperty('lightingCommandDefaultPriority', Unsigned)
        , OptionalProperty('covIncrement', Real)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class LoadControlObject(Object):
    objectType = 'loadControl'
    properties = \
        [ ReadableProperty('Present_Value', ShedState)
        , OptionalProperty('stateDescription', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , WritableProperty('requestedShedLevel', ShedLevel)
        , WritableProperty('Start_Time', DateTime)
        , WritableProperty('shedDuration', Unsigned)
        , WritableProperty('dutyWindow', Unsigned)
        , WritableProperty('Enable', Boolean)
        , OptionalProperty('fullDutyBaseline', Real)
        , ReadableProperty('expectedShedLevel', ShedLevel)
        , ReadableProperty('actualShedLevel', ShedLevel)
        , WritableProperty('shedLevels', ArrayOf(Unsigned))
        , ReadableProperty('shedLevelDescriptions', ArrayOf(CharacterString))
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class LoopObject(Object):
    objectType = 'loop'
    properties = \
        [ ReadableProperty('Present_Value', Real)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('updateInterval', Unsigned)
        , ReadableProperty('outputUnits', EngineeringUnits)
        , ReadableProperty('manipulatedVariableReference', ObjectPropertyReference)
        , ReadableProperty('controlledVariableReference', ObjectPropertyReference)
        , ReadableProperty('controlledVariableValue', Real)
        , ReadableProperty('controlledVariableUnits', EngineeringUnits)
        , ReadableProperty('setpointReference', SetpointReference)
        , ReadableProperty('setpoint', Real)
        , ReadableProperty('action', Action)
        , OptionalProperty('proportionalConstant', Real)
        , OptionalProperty('proportionalConstantUnits', EngineeringUnits)
        , OptionalProperty('integralConstant', Real)
        , OptionalProperty('integralConstantUnits', EngineeringUnits)
        , OptionalProperty('derivativeConstant', Real)
        , OptionalProperty('derivativeConstantUnits', EngineeringUnits)
        , OptionalProperty('bias', Real)
        , OptionalProperty('maximumOutput', Real)
        , OptionalProperty('minimumOutput', Real)
        , ReadableProperty('priorityForWriting', Unsigned)
        , OptionalProperty('covIncrement', Real)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('errorLimit', Real)
        , OptionalProperty('deadband', Real)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class MultiStateInputObject(Object):
    objectType = 'multiStateInput'
    properties = \
        [ ReadableProperty('Present_Value', Unsigned)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('numberOfStates', Unsigned)
        , OptionalProperty('stateText', ArrayOf(CharacterString))
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('alarmValues', SequenceOf(Unsigned))
        , OptionalProperty('faultValues', SequenceOf(Unsigned))
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class MultiStateOutputObject(Object):
    objectType = 'multiStateOutput'
    properties = \
        [ WritableProperty('Present_Value', Unsigned)
        , OptionalProperty('Device_Type', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('numberOfStates', Unsigned)
        , OptionalProperty('stateText', ArrayOf(CharacterString))
        , ReadableProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Unsigned)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('feedbackValue', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class MultiStateValueObject(Object):
    objectType = 'multiStateValue'
    properties = \
        [ ReadableProperty('Present_Value', Unsigned)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('numberOfStates', Unsigned)
        , OptionalProperty('stateText', ArrayOf(CharacterString))
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Unsigned)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('alarmValues', SequenceOf(Unsigned))
        , OptionalProperty('faultValues', SequenceOf(Unsigned))
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class NetworkSecurityObject(Object):
    objectType = 'networkSecurity'
    properties = \
        [ WritableProperty('baseDeviceSecurityPolicy', SecurityLevel)
        , WritableProperty('networkAccessSecurityPolicies', ArrayOf(NetworkSecurityPolicy))
        , WritableProperty('securityTimeWindow', Unsigned)
        , WritableProperty('packetReorderTime', Unsigned)
        , ReadableProperty('distributionKeyRevision', Unsigned)
        , ReadableProperty('keySets', ArrayOf(SecurityKeySet))
        , WritableProperty('lastKeyServer', AddressBinding)
        , WritableProperty('securityPDUTimeout', Unsigned)
        , ReadableProperty('updateKeySetTimeout', Unsigned)
        , ReadableProperty('supportedSecurityAlgorithms', SequenceOf(Unsigned))
        , WritableProperty('doNotHide', Boolean)
        ]

@register_object_type
class NotificationClassObject(Object):
    objectType = 'notificationClass'
    properties = \
        [ ReadableProperty('notificationClass', Unsigned)
        , ReadableProperty('priority', ArrayOf(Unsigned))
        , ReadableProperty('ackRequired', EventTransitionBits)
        , ReadableProperty('recipientList', SequenceOf(Destination))
        ]

@register_object_type
class NotificationForwarderObject(Object):
    objectType = 'notificationForwarder'
    properties = \
        [ ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('recipientList', SequenceOf(Destination))
        , WritableProperty('subscribedRecipients', SequenceOf(EventNotificationSubscription))
        , ReadableProperty('processIdentifierFilter', ProcessIdSelection)
        , OptionalProperty('portFilter', ArrayOf(PortPermission))
        , ReadableProperty('localForwardingOnly', Boolean)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class OctetStringValueObject(Object):
    objectType = 'octetstringValue'
    properties = \
        [ ReadableProperty('Present_Value', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', OctetString)
        ]

@register_object_type
class PositiveIntegerValueObject(Object):
    objectType = 'positiveIntegerValue'
    properties = \
        [ ReadableProperty('Present_Value', Unsigned)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , ReadableProperty('Units', EngineeringUnits)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Unsigned)
        , OptionalProperty('covIncrement', Unsigned)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('highLimit', Unsigned)
        , OptionalProperty('lowLimit', Unsigned)
        , OptionalProperty('deadband', Unsigned)
        , OptionalProperty('limitEnable', LimitEnable)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        , OptionalProperty('Min_Pres_Value', Unsigned)
        , OptionalProperty('Max_Pres_Value', Unsigned)
        , OptionalProperty('Resolution', Unsigned)
        ]

@register_object_type
class ProgramObject(Object):
    objectType = 'program'
    properties = \
        [ ReadableProperty('programState', ProgramState)
        , WritableProperty('programChange', ProgramRequest)
        , OptionalProperty('reasonForHalt', ProgramError)
        , OptionalProperty('descriptionOfHalt', CharacterString)
        , OptionalProperty('programLocation', CharacterString)
        , OptionalProperty('instanceOf', CharacterString)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class PulseConverterObject(Object):
    objectType = 'pulseConverter'
    properties = \
        [ ReadableProperty('Present_Value', Real)
        , OptionalProperty('inputReference', ObjectPropertyReference)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , ReadableProperty('Units', EngineeringUnits)
        , ReadableProperty('scaleFactor', Real)
        , WritableProperty('adjustValue', Real)
        , ReadableProperty('count', Unsigned)
        , ReadableProperty('updateTime', DateTime)
        , ReadableProperty('countChangeTime', DateTime)
        , ReadableProperty('countBeforeChange', Unsigned)
        , OptionalProperty('covIncrement', Real)
        , OptionalProperty('covPeriod', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('timeDelay', Unsigned)
        , OptionalProperty('highLimit', Real)
        , OptionalProperty('lowLimit', Real)
        , OptionalProperty('deadband', Real)
        , OptionalProperty('limitEnable', LimitEnable)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('timeDelayNormal', Unsigned)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class ScheduleObject(Object):
    objectType = 'schedule'
    properties = \
        [ ReadableProperty('Present_Value', AnyAtomic)
        , ReadableProperty('effectivePeriod', DateRange)
        , OptionalProperty('weeklySchedule', ArrayOf(DailySchedule))
        , OptionalProperty('exceptionSchedule', ArrayOf(SpecialEvent))
        , ReadableProperty('scheduleDefault', AnyAtomic)
        , ReadableProperty('listOfObjectPropertyReferences', SequenceOf(DeviceObjectPropertyReference))
        , ReadableProperty('priorityForWriting', Unsigned)
        , ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Reliability', Reliability)
        , ReadableProperty('Out_Of_Service', Boolean)
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class StructuredViewObject(Object):
    objectType = 'structuredView'
    properties = \
        [ ReadableProperty('nodeType', NodeType)
        , OptionalProperty('nodeSubtype', CharacterString)
        , ReadableProperty('subordinateList', ArrayOf(DeviceObjectReference))
        , OptionalProperty('subordinateAnnotations', ArrayOf(CharacterString))
        ]

@register_object_type
class TimePatternValueObject(Object):
    objectType = 'timePatternValue'
    properties = \
        [ ReadableProperty('Present_Value', Time)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Time)
        ]

@register_object_type
class TimeValueObject(Object):
    objectType = 'timeValue'
    properties = \
        [ ReadableProperty('Present_Value', Time)
        , ReadableProperty('Status_Flags', StatusFlags)
        , OptionalProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , OptionalProperty('Out_Of_Service', Boolean)
        , OptionalProperty('Priority_Array', PriorityArray)
        , OptionalProperty('Relinquish_Default', Time)
        ]

@register_object_type
class TrendLogObject(Object):
    objectType = 'trendLog'
    type= 'TL'
    properties = \
        [ ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , WritableProperty('Log_Enable', Boolean)
        , OptionalProperty('Start_Time', DateTime)
        , OptionalProperty('Stop_Time', DateTime)
        , OptionalProperty('Log_DeviceObjectProperty', DeviceObjectPropertyReference)
        , OptionalProperty('Log_Interval', Unsigned)
        , OptionalProperty('COV_Resubscription_Interval', Unsigned)
        , OptionalProperty('Client_COV_Increment', ClientCOV)
        , ReadableProperty('Stop_When_Full', Boolean)
        , ReadableProperty('Buffer_Size', Unsigned)
        , ReadableProperty('Log_Buffer', SequenceOf(LogRecord))
        , WritableProperty('Record_Count', Unsigned)
        , ReadableProperty('Total_Record_Count', Unsigned)
        , ReadableProperty('loggingType', LoggingType)
        , OptionalProperty('alignIntervals', Boolean)
        , OptionalProperty('intervalOffset', Unsigned)
        , OptionalProperty('trigger', Boolean)
        , OptionalProperty('Notification_Threshold', Unsigned)
        , OptionalProperty('Records_Since_Notification', Unsigned)
        , OptionalProperty('Last_Notify_Record', Unsigned)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Notification_Class', Unsigned)
        , OptionalProperty('Event_Enable', EventTransitionBits)
        , OptionalProperty('Acked_Transitions', EventTransitionBits)
        , OptionalProperty('Notify_Type', NotifyType)
        , OptionalProperty('Event_Time_Stamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('reliabilityEvaluationInhibit', Boolean)
        ]

@register_object_type
class TrendLogMultipleObject(Object):
    objectType = 'trendLogMultiple'
    type= 'TLM'
    properties = \
        [ ReadableProperty('Status_Flags', StatusFlags)
        , ReadableProperty('Event_State', EventState)
        , OptionalProperty('Reliability', Reliability)
        , WritableProperty('Log_Enable', Boolean)
        , OptionalProperty('Start_Time', DateTime)
        , OptionalProperty('Stop_Time', DateTime)
        , ReadableProperty('Log_DeviceObjectProperty', ArrayOf(DeviceObjectPropertyReference))
        , ReadableProperty('loggingType', LoggingType)
        , ReadableProperty('Log_Interval', Unsigned)
        , OptionalProperty('alignIntervals', Boolean)
        , OptionalProperty('intervalOffset', Unsigned)
        , OptionalProperty('trigger', Boolean)
        , ReadableProperty('Stop_When_Full', Boolean)
        , ReadableProperty('Buffer_Size', Unsigned)
        , ReadableProperty('Log_Buffer', SequenceOf(LogMultipleRecord))
        , WritableProperty('Record_Count', Unsigned)
        , ReadableProperty('Total_Record_Count', Unsigned)
        , OptionalProperty('Notification_Threshold', Unsigned)
        , OptionalProperty('Records_Since_Notification', Unsigned)
        , OptionalProperty('lastNotifyRecord', Unsigned)
        , OptionalProperty('notificationClass', Unsigned)
        , OptionalProperty('eventEnable', EventTransitionBits)
        , OptionalProperty('ackedTransitions', EventTransitionBits)
        , OptionalProperty('notifyType', NotifyType)
        , OptionalProperty('eventTimeStamps', ArrayOf(TimeStamp))
        , OptionalProperty('eventMessageTexts', ArrayOf(CharacterString))
        , OptionalProperty('eventMessageTextsConfig', ArrayOf(CharacterString))
        , OptionalProperty('eventDetectionEnable', Boolean)
        , OptionalProperty('eventAlgorithmInhibitRef', ObjectPropertyReference)
        , OptionalProperty('eventAlgorithmInhibit', Boolean)
        , OptionalProperty('ReliabilityEvaluationInhibit', Boolean)
        ]
