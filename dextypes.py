# Utility class for working with DEX features
#


import copy

# get the ghidra api
from __main__ import ghidra, currentProgram, getState, getMonitor

import ghidra_utils


class dex_string(object):
    def __init__(self, dex_hdr, str_idx):
        SIZE_OF_STRING_ELEMENTS = 4

        self.dex_hdr = dex_hdr

        str_idx = ghidra_utils.enforce_value(str_idx)

        str_id_addr = dex_hdr.str_ids.add(str_idx*SIZE_OF_STRING_ELEMENTS)
        str_id = ghidra_utils.dictify(str_id_addr, program=dex_hdr.program)

        string_data_addr = dex_hdr.address.add(str_id["stringDataOffset"])
        string_data = ghidra_utils.dictify(
            string_data_addr, program=dex_hdr.program)

        self.ea = string_data_addr
        self.address = string_data_addr
        self.content = string_data["data"]

    def __str__(self):
        return self.content

    def __repr__(self):
        return self.__str__()

    def __getitem__(self, i):
        return self.content.__getitem__(i)

    def __contains__(self, thing):
        return thing in self.content


class dex_proto(object):
    def __init__(self, dex_hdr, proto_idx):
        SIZE_OF_PROTO_ELEMENTS = 12

        self.dex_hdr = dex_hdr

        proto_idx = ghidra_utils.enforce_value(proto_idx)

        proto_address = dex_hdr.proto.add(proto_idx * SIZE_OF_PROTO_ELEMENTS)
        self.ea = proto_address
        self.address = self.ea

        proto_dict = ghidra_utils.dictify(
            proto_address, program=dex_hdr.program)

        # These should be DWords, but only seem to work as words...
        shorty_str_idx = proto_dict["shortyIndex"]
        return_type_idx = proto_dict["returnTypeIndex"]
        parameters_off = proto_dict["parametersOffset"]

        self.shorty = dex_hdr.get_string(shorty_str_idx)
        self.parameters = list(dex_hdr.get_types_from_list(parameters_off))
        self.return_type = dex_hdr.get_type(return_type_idx)

    def __str__(self):
        params = ','.join(self.parameters)
        return "({params}){return_type}".format(return_type=self.return_type, params=params)

    def __repr__(self):
        return self.__str__()


SIZE_OF_METHOD_ELEMENTS = 0x08


class dex_method(object):
    def __init__(self, dex_hdr, method_idx):
        self.dex_hdr = dex_hdr

        method_idx = ghidra_utils.enforce_value(method_idx)

        method_address = dex_hdr.methods.add(
            method_idx * SIZE_OF_METHOD_ELEMENTS)
        self.address = method_address
        self.ea = self.address

        method_dict = ghidra_utils.dictify(
            method_address, program=dex_hdr.program)

        method_class_type_idx = method_dict["classIndex"]
        self.clazz = dex_hdr.get_type(method_class_type_idx)

        method_prototype_idx = method_dict["protoIndex"]
        self.prototype = dex_hdr.get_proto(method_prototype_idx)
        self.shorty = self.prototype.shorty

        method_name_idx = method_dict["nameIndex"]
        self.name = str(dex_hdr.get_string(method_name_idx))

    @property
    def method_prototype(self):
        return self.prototype

    def __str__(self):
        return "{}.{}{}".format(self.clazz, self.name, self.prototype)

    def __repr__(self):
        return self.__str__()


class dex_field(object):

    clazz = None
    type = None
    name = None

    def __init__(self, dex_hdr, field_idx):
        SIZE_OF_FIELD_ELEMENTS = 8

        self.dex_hdr = dex_hdr

        field_idx = ghidra_utils.enforce_value(field_idx)

        field_address = dex_hdr.fields.add(field_idx*SIZE_OF_FIELD_ELEMENTS)
        self.address = field_address
        self.ea = self.address

        field_dict = ghidra_utils.dictify(
            field_address, program=dex_hdr.program)

        field_class_type_idx = field_dict["classIndex"]
        self.clazz = dex_hdr.get_type(field_class_type_idx)

        field_type_idx = field_dict["typeIndex"]
        self.type = dex_hdr.get_type(field_type_idx)

        field_name_str_idx = field_dict["nameIndex"]
        self.name = dex_hdr.get_string(field_name_str_idx)

    def __str__(self):
        return "{type} {clazz}{name}".format(type=self.type, clazz=self.clazz, name=self.name)

    def __repr__(self):
        return self.__str__()


class dex_classdef(object):
    ACC_INTERFACE = 0x200
    ACC_FINAL = 0x10
    super_class = None
    super_class_cached = False
    all_super_classes = None
    interfaces = None
    all_interfaces = None

    classdata = None

    def __init__(self, dex_hdr, idx=None, address=None):
        if idx is None and address is None:
            raise Exception("Need either index or address for a classdef")

        SIZE_OF_CLASSDEF_ELEMENTS = 0x20
        self.dex_hdr = dex_hdr

        if address is None:
            # determine the address from the index
            idx = ghidra_utils.enforce_value(idx)
            address = dex_hdr.classdefs.add(
                idx * SIZE_OF_CLASSDEF_ELEMENTS)

        self.address = address
        self.ea = self.address

        classdef_dict = ghidra_utils.dictify(
            self.address, program=dex_hdr.program)

        class_idx = classdef_dict["classIndex"]
        self.name = dex_hdr.get_type(class_idx)

        super_class_idx = classdef_dict["superClassIndex"]
        self.super_class_type = dex_hdr.get_type(super_class_idx)

        self.interface_types = []
        interface_address = classdef_dict["interfacesOffset"]
        if interface_address != 0:
            interface_dict = ghidra_utils.dictify(
                interface_address, program=dex_hdr.program)
            num_interfaces = interface_dict["size"]

            for idx in range(0, num_interfaces):
                self.interface_types.append(dex_hdr.get_type(
                    interface_dict["item_"+str(idx)]["typeIndex"]))

        self.access_flags = classdef_dict["accessFlags"]

        if self.is_interface():

            if self.super_class_type != "Ljava/lang/Object;":
                raise Exception("hey, found an interface with non-object super {} @ {} in {}, has {}".format(
                    self.name, self.address, self.dex_hdr.program, self.super_class_type))

        classdata_address = classdef_dict["classDataOffset"]
        # possible if it's a "marker interface"
        if 0 != ghidra_utils.enforce_raw_address(classdata_address):
            self.classdata = dex_classdata(dex_hdr, classdata_address)

    def __str__(self):
        output = self.name
        if self.super_class_type != "Ljava/lang/Object;":
            output += " extends {}".format(self.super_class_type)
        if self.interface_types:
            output += " implements " + ",".join(self.interface_types)

        return output

    def __repr__(self):
        return self.__str__()

    # could expose other details like public, abstract, etc
    def is_interface(self):
        return (self.access_flags & dex_classdef.ACC_INTERFACE) != 0

    def is_final(self):
        return (self.access_flags & dex_classdef.ACC_FINAL) != 0

    def get_super_class(self, headers=None):
        """ Return the superclass definition, or None if it's java/lang/Object (or can't be found) """
        if not self.super_class_cached:
            self.super_class_cached = True

            if "Ljava/lang/Object;" == self.super_class_type:
                return None

            # try finding in our current header first
            super_class = self.dex_hdr.get_classdef(self.super_class_type)
            if super_class is None:
                # classdef defined in another header somewhere
                if headers is None:
                    headers = get_all_dex_headers()
                for header in headers.values():
                    if str(header) == str(self.dex_hdr):
                        # skip, we've already checked this
                        continue

                    super_class = header.get_classdef(self.super_class_type)
                    if super_class is not None:
                        # found it!
                        break

            if super_class is not None:
                self.super_class = super_class
            else:
                print("Warning: classdef not found for {}".format(
                    self.super_class_type))

        return self.super_class

    def get_all_super_classes(self, headers=None):
        """ return a list of super classes, up to (but not including) the java.lang.object root.
            If there's no super apart from that (or an error finding it), return the empty list """
        if self.all_super_classes is None:
            super_class = self.get_super_class(headers=headers)
            ret_list = []
            if super_class is not None:
                ret_list.append(super_class)
                ret_list.extend(
                    super_class.get_all_super_classes(headers=headers))

            self.all_super_classes = ret_list

        return self.all_super_classes

    def get_interfaces(self,  headers=None):
        """ Return a list of immediate interface class definitions. """
        # Note: looks like some interfaces may not necessarily be present? I'm guessing proguarded out? Don't appear to be present in any of the headers. Skip any Nones
        if self.interfaces is None:
            ret_list = list()
            for iface_type in self.interface_types:
                cd = self.dex_hdr.get_classdef(iface_type)
                if cd is None:
                    # check the other headers
                    if headers is None:
                        headers = get_all_dex_headers()
                    for header in headers.values():
                        if str(header) == str(self.dex_hdr):
                            # skip, we've already checked this
                            continue

                        cd = header.get_classdef(iface_type)
                        if cd is not None:
                            # found it!
                            break

                if cd is not None:
                    ret_list.append(cd)
                else:
                    print(
                        "Warning classdef not found for interface {}".format(iface_type))
            self.interfaces = ret_list

        return self.interfaces

    def get_all_interfaces(self, headers=None):
        """ Return a list of interface class definitions, including any interfaces the immediate interfaces have, up the chain"""
        if self.all_interfaces is None:
            iface_list = self.get_interfaces(headers=headers)
            new_list = []
            for iface in iface_list:
                new_list.extend(iface.get_all_interfaces(headers=headers))

            # and make sure we include the original list
            self.all_interfaces = iface_list + new_list

        return self.all_interfaces

    def get_all_interface_types(self, headers=None):
        """ Return a list of interface class types, including any interfaces the immediate interfaces have, up the chain. Note: this WILL include interface types we can't find definitions for, like Runnable"""
        # don't need to cache this, interfaces are cached all the way up, so it should be pretty fast
        # start from the interface types
        iface_type_list = copy.copy(self.interface_types)

        # this will only include interfaces where we can get the classdef
        iface_list = self.get_interfaces(headers=headers)
        while iface_list:
            # grab the next iface classdef
            iface = iface_list.pop()
            # grab the interface types from that
            iface_type_list.extend(iface.interface_types)
            # add any higher interfaces to the iface list to grab
            iface_list.extend(iface.get_interfaces(headers=headers))

        return iface_type_list

    def get_implementors(self, headers=None):
        """ Get all the implementing classes for this interface """
        if not self.is_interface():
            # not an interface, can't be implemented
            return []

        return get_classdef_with_interface(self.name, headers=headers)

    def get_children(self, headers=None):
        """ Get all the subclasses for this class """
        # TODO bail if final
        return get_subclasses_of_class(self.name, headers=headers)

    def get_method(self, method_name, prototype):
        if self.classdata is not None:
            return self.classdata.get_method(method_name, prototype)

        return None

    def get_methods(self):
        if self.classdata is not None:
            return self.classdata.get_methods()

        return []


def decode_uleb128_bytes_to_int(byte_array):
    """
    Read in a byte array as uleb128 varint
    """
    ret = 0
    i = 0
    while i < len(byte_array):
        ret = ret | (((byte_array[i] % 256) & 0x7f) << 7*i)
        i += 1
    return ret


class dex_classdata(object):
    instance_fields = None
    static_fields = None
    virtual_methods = None
    direct_methods = None

    def __init__(self, dex_hdr, address):

        self.instance_fields = []
        self.static_fields = []
        self.virtual_methods = []
        self.direct_methods = []

        self.address = address
        self.ea = self.address
        self.dex_hdr = dex_hdr

        data_iterator = dex_hdr.program.getListing().getData(
            ghidra_utils.get_address(self.address), True)

        # note: this only grabs the numbers for each list of entries (because the actual entries are treated as seperate data items by ghidra
        classdata_dict = ghidra_utils.dictify(
            data_iterator.next(), program=dex_hdr.program)

        prev_idx = 0
        for idx in range(0, decode_uleb128_bytes_to_int(classdata_dict["static_fields"])):
            encoded_field = encoded_dex_field(
                dex_hdr, data_iterator.next().getAddress(), prev_idx)
            prev_idx = encoded_field.field_idx
            self.static_fields.append(encoded_field.field)

        prev_idx = 0
        for idx in range(0, decode_uleb128_bytes_to_int(classdata_dict["instance_fields"])):
            encoded_field = encoded_dex_field(
                dex_hdr, data_iterator.next().getAddress(), prev_idx)
            prev_idx = encoded_field.field_idx
            self.instance_fields.append(encoded_field.field)

        prev_idx = 0
        for idx in range(0, decode_uleb128_bytes_to_int(classdata_dict["direct_methods"])):
            encoded_method = encoded_dex_method(
                dex_hdr, data_iterator.next().getAddress(), prev_idx)
            prev_idx = encoded_method.method_idx
            self.direct_methods.append(encoded_method.method)

        prev_idx = 0
        for idx in range(0, decode_uleb128_bytes_to_int(classdata_dict["virtual_methods"])):
            encoded_method = encoded_dex_method(
                dex_hdr, data_iterator.next().getAddress(), prev_idx)
            prev_idx = encoded_method.method_idx
            self.virtual_methods.append(encoded_method.method)

    def get_method(self, method_name, prototype):
        """ Find the matching dex method in this class data, or return none """
        for method in self.get_methods():
            if method.name == method_name:
                if prototype == str(method.prototype):
                    return method

        return None

    def get_methods(self):
        for method in self.virtual_methods + self.direct_methods:
            yield method


class encoded_dex_field(object):

    field = None
    field_idx = None
    access_flags = None

    def __init__(self, dex_hdr, address, previous_idx=0):
        """ Need previous idx, because the field indices are recorded as differences from the previous one """
        self.address = address
        self.ea = self.address
        self.dex_hdr = dex_hdr

        encoded_data = ghidra_utils.dictify(
            self.address, program=dex_hdr.program)

        self.field_idx = decode_uleb128_bytes_to_int(
            encoded_data["field_idx_diff"]) + previous_idx
        self.field = dex_field(dex_hdr, self.field_idx)
        self.access_flags = decode_uleb128_bytes_to_int(
            encoded_data["accessFlags"])


class encoded_dex_method(object):
    method = None
    method_idx = None
    access_flags = None
    code_item_offset = None

    def __init__(self, dex_hdr, address, previous_idx=0):
        """ Need previous idx, because the method indices are recorded as differences from the previous one """
        self.address = address
        self.ea = self.address
        self.dex_hdr = dex_hdr

        encoded_data = ghidra_utils.dictify(
            self.address, program=dex_hdr.program)
        self.method_idx = decode_uleb128_bytes_to_int(
            encoded_data["method_idx_diff"]) + previous_idx
        self.method = dex_method(dex_hdr, self.method_idx)
        self.access_flags = decode_uleb128_bytes_to_int(
            encoded_data["access_flags"])
        self.code_item_offset = decode_uleb128_bytes_to_int(
            encoded_data["code_off"])


class dex_header(object):

    base = None
    str_ids = None
    types = None
    proto = None
    fields = None
    method_dict = None
    classdef_dict = None

    def __init__(self, program=None):
        """ Create a header object, based on the dex component """

        if program is None:
            program = currentProgram
        self.program = program

        header_addr = ghidra_utils.get_address(0, program=self.program)

        header_dict = ghidra_utils.dictify(header_addr, program=self.program)

        self.ea = header_addr
        self.address = header_addr

        self.num_strings = header_dict["stringIdsSize"]
        self.str_ids = self.address.add(header_dict["stringIdsOffset"])
        self.types = self.address.add(header_dict["typeIdsOffset"])
        self.proto = self.address.add(header_dict["protoIdsOffset"])
        self.num_fields = header_dict["fieldIdsSize"]
        self.fields = self.address.add(header_dict["fieldIdsOffset"])
        self.num_methods = header_dict["methodIdsSize"]
        self.methods = self.address.add(header_dict["methodIdsOffset"])
        self.num_classdefs = header_dict["classDefsIdsSize"]
        self.classdefs = self.address.add(header_dict["classDefsIdsOffset"])
        self.data = self.address.add(header_dict["dataOffset"])

        self.string_cache = None

    def get_string(self, string_idx):
        return dex_string(self, string_idx)

    def get_strings(self):
        ''' Return an iterator over the strings in this dex file '''
        for string_index in xrange(self.num_strings):
            yield self.get_string(string_index)

    @property
    def strings(self):
        if self.string_cache is None or len(self.string_cache) != self.num_strings:
            self.string_cache = list(self.get_strings())
        return self.string_cache

    def get_type(self, type_index):
        '''Get a type by the type index'''
        SIZE_OF_TYPE_ELEMENTS = 4

        type_index = ghidra_utils.enforce_value(type_index)

        type_addr = self.types.add(type_index*SIZE_OF_TYPE_ELEMENTS)
        type_str_idx = ghidra_utils.dictify(type_addr, program=self.program)[
            "descriptorIndex"]

        return str(self.get_string(type_str_idx))

    def get_types_from_list(self, typelist_offset):
        if typelist_offset != 0:
            type_list_addr = self.address.add(typelist_offset)
            type_list_dict = ghidra_utils.dictify(
                type_list_addr, program=self.program)

            num_types = type_list_dict["size"]
            for i in xrange(num_types):
                type_index = type_list_dict["item_"+str(i)]["typeIndex"]
                yield self.get_type(type_index)

    def get_proto(self, proto_index):
        return dex_proto(self, proto_index)

    def get_method(self, method_index):
        '''Get a method by the method index'''
        method_index = ghidra_utils.enforce_value(method_index)

        if method_index >= self.num_methods or method_index < 0:
            raise IndexError("Attempted to get method {} of {}".format(
                method_index, self.num_methods))
        return dex_method(self, method_index)

    def get_methods(self):
        for method_index in xrange(self.num_methods):
            yield dex_method(self, method_index)

    def get_method_dict(self):
        """ Grab all the methods and store them by class, name, and proto """
        if self.method_dict is None:
            method_dict = {}

            for idx in xrange(0, self.num_methods):
                m = self.get_method(idx)
                if m.clazz not in method_dict:
                    method_dict[m.clazz] = {}

                if m.name not in method_dict[m.clazz]:
                    method_dict[m.clazz][m.name] = {}

                # Note: store by string repr of prototype, not prototype object
                method_dict[m.clazz][m.name][str(m.prototype)] = m

                # TODO - chuck in a combined one for faster searching exact matches?

            self.method_dict = method_dict

        return self.method_dict

    def get_methods_by_class(self, clazz):
        """ Use the sorting of the method indices to find all the dex methods for a given class

            Methods are sorted first by class type id. Types are sorted by string id. Strings are sorted by string contents as UTF-16 code points (so alphabetical should be close enough till we start hitting unicode chars in class names)

            We'll use a binary search to start narrowing things down
        """
        range_start = 0
        range_end = self.num_methods
        split_idx = 0
        test_method = None

        clazz = ghidra_utils.SymbolDescriptor(clazz).to_java()

        while(range_end >= range_start):
            split_idx = range_start + ((range_end-range_start)/2)
            test_method = self.get_method(split_idx)

            if test_method.clazz == clazz:
                # found the class!
                break

            elif test_method.clazz < clazz:
                # this is too early
                range_start = split_idx+1
            else:
                # this is too late
                if range_end == split_idx:
                    break
                range_end = split_idx

        if test_method.clazz == clazz:
            # we found our class. now walk backwards and forwards from here to find all of them
            clazz_start = split_idx
            while clazz_start > 0:
                test_idx = clazz_start - 1
                test_method = self.get_method(test_idx)
                if test_method.clazz == clazz:
                    clazz_start = test_idx
                else:
                    # found first non-clazz method before - we're done
                    break

            clazz_end = split_idx
            while clazz_end < (self.num_methods-1):
                test_idx = clazz_end + 1
                test_method = self.get_method(test_idx)
                if test_method.clazz == clazz:
                    clazz_end = test_idx
                else:
                    # found first non-clazz method after - we're done
                    break

            # now give back the methods in order
            for method_idx in xrange(clazz_start, clazz_end+1):
                yield self.get_method(method_idx)

    def get_method_by_details(self, clazz, method_name, prototype):
        for method in self.get_methods_by_class(clazz):
            if method.name == method_name:
                if prototype == str(method.prototype):
                    return method

        return None

    def get_fields(self):
        """ Returns an iterator for the fields in this DEX """
        for field_index in xrange(self.num_fields):
            yield dex_field(self, field_index)

    def get_classdef_dict(self):
        if self.classdef_dict is None:
            self.classdef_dict = dict()

            for idx in xrange(0, self.num_classdefs):
                cd = dex_classdef(self, idx)
                self.classdef_dict[cd.name] = cd

        return self.classdef_dict

    def get_classdef(self, class_name):
        """ Return the classdef for a specific class (in either java or ghidra format)

            Note: if the class is not present, this will return None
        """
        clazz = ghidra_utils.get_class_symbol(class_name, self.program)
        classdef = None

        if clazz is not None:
            symlist = list(self.program.getSymbolTable().getChildren(clazz))

            for sym in symlist:
                if sym.getName() == "__classdef__":
                    classdef = dex_classdef(
                        dex_hdr=self, address=sym.getAddress())
                    break

        return classdef

    def get_classdef_with_interface(self, interface_clazz):
        """ Return any classdefs we know that implement the given interface at any level """
        if isinstance(interface_clazz, dex_classdef):
            interface_clazz = interface_clazz.name

        implementors = []

        classdefs = self.get_classdef_dict()
        for cd in classdefs.values():
            if interface_clazz in cd.get_all_interface_types():
                implementors.append(cd)

        return implementors

    def get_subclasses_of_class(self, super_clazz):
        """ Return any classdefs we know are a child of the given class at any level """
        if isinstance(super_clazz, dex_classdef):
            super_clazz = super_clazz.name

        children = []

        classdefs = self.get_classdef_dict()
        for cd in classdefs.values():
            if super_clazz in [super_class.name for super_class in cd.get_all_super_class_types()]:
                children.append(cd)

        return children


def get_dex_method_for_function(function):
    program = function.program

    header = get_all_dex_headers()[str(program)]

    # boo, can only get the method id offset from the comment
    method_id_offset = ghidra_utils.get_address(
        function.getComment().split("Method ID Offset: ")[1].strip(), program=program)
    idx = method_id_offset.subtract(header.methods)/SIZE_OF_METHOD_ELEMENTS

    return header.get_method(idx)


def get_dex_method_at_address(address=None, program=None, header=None):
    if program is None:
        program = getState().getCurrentProgram()

    address = ghidra_utils.get_address(address=address, program=program)
    insn = ghidra_utils.get_instruction_at_address(
        address=address, program=program)

    if header is None:
        header = dex_header(program)  # TODO cache this?

    if insn is not None and "invoke" in insn.getMnemonicString():
        # this is the calling line - get the dex method ref at the start
        idx = insn.getOpObjects(0)[0].getValue()
        # note: getOperandReferences(0) gives reference to target fn
    elif header.methods.getOffset() <= address.getOffset() and address.getOffset() < (header.methods.getOffset() + (header.num_methods * SIZE_OF_METHOD_ELEMENTS)):
        # lies within the dex method range, this is the dex method line
        idx = (address.getOffset() - header.methods.getOffset()) / \
            SIZE_OF_METHOD_ELEMENTS
    else:
        raise Exception(
            "Didn't find invoke or dex method ref at {} in {}. Perhaps you want get_dex_method_for_function()".format(address, program))

    return header.get_method(idx)


CACHED_HEADERS = None


def get_all_dex_headers(monitor=None, sameDirectory=True):
    global CACHED_HEADERS
    if CACHED_HEADERS is None:

        if monitor is None:
            monitor = getMonitor()

        CACHED_HEADERS = dict()
        for program in ghidra_utils.get_all_dex_programs(sameDirectory=sameDirectory):
            CACHED_HEADERS[str(program)] = dex_header(program)

    return CACHED_HEADERS


def get_classdef(class_name, headers=None):
    if headers is None:
        headers = get_all_dex_headers()

    java_class_name = ghidra_utils.SymbolDescriptor(class_name).to_java()

    for header in headers.values():
        cd = header.get_classdef(java_class_name)
        if cd is not None:
            return cd

    return None


def get_classdef_with_interface(interface_clazz, headers=None):
    """ Return any classdefs we know that implement the given interface at any level """
    if headers is None:
        headers = get_all_dex_headers()

    implementors = []

    for header in headers.values():
        implementors.extend(
            header.get_classdef_with_interface(interface_clazz))

    return implementors


def get_subclasses_of_class(super_clazz, headers=None):
    """ Return any classdefs we know are a child of the given class at any level, across all the headers """

    if headers is None:
        headers = get_all_dex_headers()

    children = []

    for header in headers.values():
        children.extend(header.get_subclasses_of_class(super_clazz))

    return children
