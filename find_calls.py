# Utility class for finding dex calls throughout a multi-dex environment
#
#
#@category Dalvik

import copy

import dextypes
import ghidra_utils
import dalvik_trace


def class_name_to_java_style(name):
    """ change foo.bar.flam to Lfoo/bar/flam; """
    if name is not None:
        if not (name.startswith("L") and name.endswith(";")):
            name = "L" + name + ";"

        name = name.replace(".", "/")

    return name


def java_name_to_ghidra_style(name):
    """ Lfoo/bar/flam; to foo::bar::flam """
    if name is not None:
        if name.startswith("L") and name.endswith(";"):
            name = name[1:-1]

        name = name.replace("/", "::")

    return name


def find_dex_methods(headers=None, clazz=None, method_name=None, proto=None, dex_method=None):
    """ Find all dex method descriptors that match the requirements

        Treats a None as "*". Proto is full length prototype string

        Speed up by retaining headers and passing in manually

        Usages:
            all: Find all dex method declarations for a particular method
            clazz and method_name only: find all declarations for a polymorphic method
            clazz only: Find all method declarations against given class
            method_name and proto only: find all declarations that might be an interface

        Yields out dex methods as they're found
    """

    if headers is None:
        headers = dextypes.get_all_dex_headers()

    if dex_method is not None:
        clazz = dex_method.clazz
        method_name = dex_method.name
        proto = str(dex_method.method_prototype)

    for header in headers.values():
        methods = None
        if clazz is not None:
            classdef = header.get_classdef(clazz)
            if classdef is not None:
                methods = classdef.get_methods()
            else:
                methods = header.get_methods_by_class(
                    clazz)  # TODO is this faster anyway?
        else:
            # no class definition limiter - going to need to walk all the dex methods :/
            methods = header.get_methods()

        for method in methods:
            if method_name is None or (method_name == method.name):
                if proto is None or (proto == str(method.prototype)):
                    yield method


def class_has_method(clazz, method_name, proto, headers=None):
    """ Return true if a class has the given method defined (in any of the dexs) 

        TODO check for different method defns in different dexes?
    """

    if headers is None:
        headers = dextypes.get_all_dex_headers().values()

    for header in headers:
        classdef = header.get_classdef(clazz)

        if classdef is not None:
            if classdef.get_method(method_name, proto) is not None:
                return True
        else:
            # TODO is this faster than classdef anyway?
            if header.get_method_by_details(clazz, method_name, proto) is not None:
                return True

    return False


def find_potential_invoke_interface_classes(headers=None, clazz=None, method_name=None, proto=None, dex_method=None):
    """ Find higher level interfaces that might also be used for an invoke_interface call.

        Returns list of matching interface class names, empty list if there are none
    """
    if dex_method is not None:
        clazz = dex_method.clazz
        method_name = dex_method.name
        proto = str(dex_method.method_prototype)

    if clazz is None or method_name is None or proto is None:
        raise Exception(
            "Need all of class, method and proto to find invoke_interface_classes")

    classdef = dextypes.get_classdef(clazz, headers)

    # note: this won't pick up java library interfaces like runnable
    interfaces = classdef.get_all_interfaces()

    for interface in interfaces:
        if class_has_method(interface.name, method_name, proto):
            yield interface


def find_potential_invoke_virtual_classes(headers=None, clazz=None, method_name=None, proto=None, dex_method=None):
    """ Find higher level parent classes that might also be used for an invoke_virtual call.

        Returns list of matching super class names, empty list if there are none

        Note: this assumes that dalvik handles virtuals by requesting the lowest level class where the method is defined (so A { B() }; C extends A {}; c=new C(); c.B() <--- gets invoked as invoke_virtual A.B for object c)
    """
    if dex_method is not None:
        clazz = dex_method.clazz
        method_name = dex_method.name
        proto = str(dex_method.method_prototype)

    if clazz is None or method_name is None or proto is None:
        raise Exception(
            "Need all of class, method and proto to find invoke_virtual_classes")

    classdef = dextypes.get_classdef(clazz, headers)

    supers = classdef.get_all_super_classes()

    for super in supers:
        if class_has_method(super.name, method_name, proto):
            yield super


def find_potential_invoke_super_classes(headers=None, clazz=None, method_name=None, proto=None, dex_method=None):
    """ Find children that might have called this with invoke_super

        Returns list of matching child class names, empty list if there are none
    """
    if dex_method is not None:
        clazz = dex_method.clazz
        method_name = dex_method.name
        proto = str(dex_method.method_prototype)

    if clazz is None or method_name is None or proto is None:
        raise Exception(
            "Need all of class, method and proto to find invoke_super_classes")

    classdef = dextypes.get_classdef(clazz, headers)

    if not classdef.is_final():
        children = dextypes.get_subclasses_of_class(classdef, headers=headers)
        print("Found children {}".format(children))
        return children
    else:
        return []


def find_callers(dex_method=None, function=None, headers=None, include_interface=True, include_virtual=True, include_super=False):
    """ Find all the possible callers to a method. Returns list of tuples of (address,program) of callers
        include super is off by default, because it needs to walk every classdef to see if it might be a child of this one
    """
    if headers is None:
        headers = dextypes.get_all_dex_headers()

    if function is not None:
        dex_method = dextypes.get_dex_method_for_function(function)

    clazz = dex_method.clazz
    method_name = dex_method.name
    proto = str(dex_method.method_prototype)

    # first - direct calls
    # find the matching method references
    method_instances = find_dex_methods(
        headers=headers, clazz=clazz, method_name=method_name, proto=proto)
    for mi in method_instances:
        refmgr = mi.dex_hdr.program.getReferenceManager()
        for ref in refmgr.getReferencesTo(ghidra_utils.get_address(mi.address)):
            address = ref.getFromAddress()
            insn = ghidra_utils.get_instruction_at_address(
                address=address, program=mi.dex_hdr.program)
            yield (address, mi.dex_hdr.program, insn)

    if include_interface:
        for classdef in find_potential_invoke_interface_classes(headers=headers, clazz=clazz, method_name=method_name, proto=proto):
            method_instances = find_dex_methods(
                headers=headers, clazz=classdef.name, method_name=method_name, proto=proto)

            for mi in method_instances:
                refmgr = mi.dex_hdr.program.getReferenceManager()
                for ref in refmgr.getReferencesTo(ghidra_utils.get_address(mi.address)):
                    address = ref.getFromAddress()
                    insn = ghidra_utils.get_instruction_at_address(
                        address=address, program=mi.dex_hdr.program)
                    # make sure it's an invoke_interface - should always be, but let's check
                    assert insn.getMnemonicString().startswith("invoke_interface"), "Interface wasn't called with invoke interface? {} in {} for {}".format(
                        address, mi.dex_hdr.program, mi)
                    yield(address, mi.dex_hdr.program, insn)

    if include_virtual:
        for classdef in find_potential_invoke_virtual_classes(headers=headers, clazz=clazz, method_name=method_name, proto=proto):
            method_instances = find_dex_methods(
                headers=headers, clazz=classdef.name, method_name=method_name, proto=proto)

            for mi in method_instances:
                refmgr = mi.dex_hdr.program.getReferenceManager()
                for ref in refmgr.getReferencesTo(ghidra_utils.get_address(mi.address)):
                    address = ref.getFromAddress()
                    insn = ghidra_utils.get_instruction_at_address(
                        address=address, program=mi.dex_hdr.program)
                    # make sure it's an invoke_virtual
                    if insn.getMnemonicString().startswith("invoke_virtual"):
                        yield (address, mi.dex_hdr.program, insn)

    if include_super:
        for classdef in find_potential_invoke_super_classes(headers=headers, clazz=clazz, method_name=method_name, proto=proto):
            method_instances = find_dex_methods(
                headers=headers, clazz=classdef.name, method_name=method_name, proto=proto)

            for mi in method_instances:
                refmgr = mi.dex_hdr.program.getReferenceManager()
                for ref in refmgr.getReferencesTo(ghidra_utils.get_address(mi.address)):
                    address = ref.getFromAddress()
                    insn = ghidra_utils.get_instruction_at_address(
                        address=address, program=mi.dex_hdr.program)
                    # make sure it's an invoke_super
                    if insn.getMnemonicString().startswith("invoke_super"):
                        yield (address, mi.dex_hdr.program, insn)


def trace_callers(dex_method=None, function=None, headers=None, include_interface=True, include_virtual=True, include_super=False, previously_seen=None, depth=5):
    """ Produce a list of traces of callers of this function, and their callers, and so on and so on
    """
    # todo include a previously traced cache, to help with diamond calls - e.g., A->B, A->C, B->D, C->D - don't want to have to check A twice

    if depth is not None:
        if depth <= 0:
            # reached the max depth, time to come back up
            return []

        depth = depth-1

    # use for avoiding getting caught in loops
    if previously_seen is None:
        previously_seen = []

    if function is not None:
        dex_method = dextypes.get_dex_method_for_function(function)

    previously_seen.append(str(dex_method))

    callers = find_callers(dex_method=dex_method, headers=headers, include_interface=include_interface,
                           include_virtual=include_virtual, include_super=include_super)

    traces = []

    for call_tuple in callers:
        call_function = ghidra_utils.get_function_at_address(
            call_tuple[0], program=call_tuple[1])
        dm = dextypes.get_dex_method_for_function(call_function)

        if str(dm) not in previously_seen:
            traces.append((call_tuple, trace_callers(dex_method=dm, headers=headers, include_interface=include_interface,
                                                     include_virtual=include_virtual, include_super=include_super, previously_seen=copy.copy(previously_seen), depth=depth)))
        else:
            # display a recursion indicator
            traces.append((call_tuple, "RECURSION"))

    return traces


def display_trace(trace_result, stack=""):

    for entry in trace_result:
        call_tuple = entry[0]
        call_function = ghidra_utils.get_function_at_address(
            call_tuple[0], program=call_tuple[1])
        dm = dextypes.get_dex_method_for_function(call_function)

        new_stack = "{}:{}\t{}\n".format(
            call_tuple[0], call_tuple[1].getName(), dm) + stack

        next_level_list = entry[1]

        if isinstance(next_level_list, list):
            if next_level_list:
                # more to display - recurse
                display_trace(next_level_list, new_stack)
            else:
                # reached the end of the trace - print it
                print(new_stack)
        else:
            # something like recursion label - just display that on top of the stack
            print(next_level_list + "\n" + new_stack)


TRACE_CACHE = dict()


def check_invoke_args(address, program, args_list):
    """ Handles simple int, string, bool args (e.g., where direct values in play, not call results or multi values, or string builds, etc. straight assignments only atm. doesn't check 'this'. None in the list treated as * """

    function = ghidra_utils.get_function_at_address(
        address=address, program=program)

    trace_id = str(function)

    if trace_id not in TRACE_CACHE:
        TRACE_CACHE[trace_id] = dalvik_trace.FunctionTrace(function)

    ftrace = TRACE_CACHE[trace_id]
    try:
        call = ftrace.find_call_at_address(address)
    except Exception as e:
        print("Failed to trace {}: {}".format(function, e))
        return False

    if call is None:
        raise Exception("Couldn't get call from : {}".format(
            ghidra_utils.get_instruction_at_address(address=address, program=program)))

    for idx, arg in enumerate(args_list):
        if arg is None:
            continue

        if isinstance(arg, bool):
            # turn into an int
            arg = 1 if arg else 0

        try:
            resolved_arg = call.params_list[idx].value.resolve()
            if resolved_arg != arg:
                return False

        except Exception as e:
            print("Failed : {}".format(ghidra_utils.get_instruction_at_address(
                address=address, program=program)))
            raise

    return True


def find_calls(headers=None, clazz=None, method_name=None, proto=None, dex_method=None, args=None, quiet=False):
    """ Find all the calls to a given function. 

        Treats a None as "*". Proto is full length prototype string

        Speed up by retaining headers and passing in manually

        Usages:
            all: Find all usages for a particular method
            clazz and method_name only: find all calls for a polymorphic method
            clazz only: Find all calls against given class
            method_name and proto only: find all interactions that might be an interface

        Returns dict of the methods, with their calling locations

        Requires xref_invoke_to_dex_method_id analysis to be run to have reference to the method id location.
    """

    if dex_method is not None:
        clazz = dex_method.clazz
        method_name = dex_method.name
        proto = str(dex_method.method_prototype)

    # find the matching method references
    method_instances = find_dex_methods(
        headers=headers, clazz=clazz, method_name=method_name, proto=proto, dex_method=dex_method)

    ret_dict = {}
    output = ""

    for mi in method_instances:
        ret_dict[mi] = []
        directly_called = False

        output += "Method {} @ {}: {}\n".format(
            mi, mi.dex_hdr.program.getName(), hex(int(mi.address.getOffset())))

        class_def = dextypes.get_classdef(mi.clazz)
        if class_def is None:
            print("Warning: {} couldn't find class def for {}".format(mi, mi.clazz))

        refmgr = mi.dex_hdr.program.getReferenceManager()
        for ref in ghidra_utils.iterate(refmgr.getReferencesTo(ghidra_utils.get_address(mi.address))):
            directly_called = True
            call_address = ref.getFromAddress()

            if args is not None:
                if not check_invoke_args(call_address.getOffset(), mi.dex_hdr.program, args):
                    # didn't match
                    continue

            ret_dict[mi].append(call_address.getOffset())
            call_func = ghidra_utils.get_function_at_address(
                call_address, mi.dex_hdr.program)

            output += "\tCalled by {} ( {} : {} )\n".format(
                call_func, call_func.getProgram().getName(), call_func.getEntryPoint())
            insn = ghidra_utils.get_instruction_at_address(
                address=call_address.getOffset(), program=mi.dex_hdr.program)
            output += "\t\t{}: {}\n".format(call_address, insn)

        if not directly_called:
            output += "\tNot directly called\n"
        elif len(ret_dict[mi]) < 1:
            output += "\tNot called with desired args\n"

    if not quiet:
        print(output)

    return ret_dict


def find_interface_calls(headers=None, clazz=None, method_name=None, proto=None, dex_method=None, args=None, quiet=False):
    """ Find all calls to a given interface.
        clazz is interface class (so, not the implementing class - IFoo, not FooImpl). Need all of clazz, method_name and proto 

        Speed up by retaining headers and passing in manually

        Proto is full length prototype string

        Returns list of call locations 

        Requires xref_invoke_to_dex_method_id analysis to be run to have reference to the method id location.
    """
    if dex_method is not None:
        clazz = dex_method.clazz
        method_name = dex_method.name
        proto = str(dex_method.method_prototype)

    # TODO - would be nice to have a way to go from a concrete class to find the higher interface class?
    if clazz is None or method_name is None or proto is None:
        raise Exception(
            "Need all of clazz, method_name and proto to find interface calls")

    method_instances = find_dex_methods(
        headers=headers, clazz=clazz, method_name=method_name, proto=proto)

    """if len(method_instances) < 1:
        raise Exception("Didn't find method reference for {} {} {}".format(clazz, method_name, proto))
    """

    # require invoke-interface
    interface_call_list = []
    directly_called = False

    output = ""

    #print("Method {}".format(method_instances[0]))
    for mi in method_instances:
        refmgr = mi.dex_hdr.program.getReferenceManager()
        for ref in ghidra_utils.iterate(refmgr.getReferencesTo(ghidra_utils.get_address(mi.address))):
            directly_called = True
            call_address = ref.getFromAddress()

            if args is not None:
                if not check_invoke_args(call_address.getOffset(), mi.dex_hdr.program, args):
                    # didn't match
                    continue

            insn = ghidra_utils.get_instruction_at_address(
                address=call_address.getOffset(), program=mi.dex_hdr.program)

            if insn.getMnemonicString().startswith("invoke_interface"):
                interface_call_list.append(call_address.getOffset())
                call_func = ghidra_utils.get_function_at_address(
                    call_address, mi.dex_hdr.program)
                output += "\tCalled by {} ( {} : {} )\n".format(
                    call_func, call_func.getProgram().getName(), call_func.getEntryPoint())

                output += "\t\t{}: {}\n".format(call_address, insn)

    if not directly_called:
        output += "\tNot directly called\n"
    elif len(interface_call_list) < 1:
        output += "\tNot called with desired args\n"

    if not quiet:
        print(output)

    return interface_call_list


def find_impls(clazz=None, method_name=None, proto=None, dex_method=None, quiet=False):
    """ Find all the implementations of a given function. 

        Treats a None as "*". Proto is full length prototype string

        Speed up by retaining headers and passing in manually

        Usages:
            all: Find all impls for a particular method
            clazz and method_name only: find all impls for a polymorphic method
            clazz only: Find all method implementations for a given class
            method_name and proto only: find all impls that might be an interface

        Returns dict of the methods and their implementation locations
    """
    # TODO use the alphabetical nature of class/function ordering to speed up
    if dex_method is not None:
        clazz = dex_method.clazz
        method_name = dex_method.name
        proto = str(dex_method.method_prototype)

    impls = dict()

    output = ""

    for program in ghidra_utils.get_all_dex_programs():
        for function in ghidra_utils.iterate(program.getFunctionManager().getFunctions(True)):
            # easy check - do the names match, if specified
            if method_name is None or (function.getName() == method_name):
                # check the class, if specified
                if clazz is None or (function.getParentNamespace().getName(True) == java_name_to_ghidra_style(clazz)):
                    # now, check the protoype, if specified
                    method = dextypes.get_dex_method_for_function(function)

                    if proto is None or (str(method.prototype) == proto):
                        # match!
                        if method not in impls:
                            impls[method] = list()
                        impls[method].append(function)

                        output += "\tImplemented at {} ({} @ {} )\n".format(function.getName(
                            True), function.getProgram().getName(), function.getEntryPoint())

                        break

    if not quiet:
        print(output)

    return impls


def find_interface_impls(method_name=None, proto=None, dex_method=None, quiet=False):
    """ Find methods which _may_ implement a given interface (by method name and prototype) 

        Proto is full length prototype string

        Returns list of ghidra.Functions which may implement the interface
    """

    if (method_name is None or proto is None) and (dex_method is None):
        raise Exception(
            "Need method_name and proto, or dex_method to find interface calls")

    if dex_method is not None:
        method_name = dex_method.name
        proto = str(dex_method.prototype)

    if not quiet:
        print("Interface {}{}".format(method_name, proto))
    return find_impls(clazz=None, method_name=method_name, proto=proto, quiet=quiet)
