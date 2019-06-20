# Find AIDL definitions for IPC calls using binder
#
# Search through DEX headers to find classes that
# inherit from IInterface and Binder, then locate
# the big switch statements that perform the dispatch
# and extract the AIDL definition information.
#
#
#@category Dalvik

import dextypes

class AIDL(object):
    def __init__(self, stub, binder, interface):
        self.stub = stub
        self.binder = binder
        self.interface = interface
    def __str__(self):
        return 'Interface: {}\n\tStub: {}\n\tBinder: {}'.format(self.interface, self.stub, self.binder)

def main():
    dex_headers = dextypes.get_all_dex_headers(monitor)
    found_aidls = list()

    interface_to_binder= dict()
    for program, dex in dex_headers.iteritems():
        monitor.setMessage("Searching classes in {}".format(program))
        monitor.initialize(dex.num_classdefs)
        for clazz, classdef in dex.get_classdef_dict().iteritems():
            monitor.incrementProgress(1)
            interface = None
            binder = None

            if classdef.super_class_type == 'Landroid/os/Binder;':
                interfaces = classdef.get_all_interface_types(dex_headers)
                if len(interfaces) > 1 and interfaces[0] != 'Landroid/os/IInterface;':
                    interface = interfaces[0]
                    binder = clazz
                    interface_to_binder[interface] = binder

    # Now we need to find the stubs
    for program, dex in dex_headers.iteritems():
        monitor.setMessage("Searching for stubs in {}".format(program))
        monitor.initialize(dex.num_classdefs)
        for clazz, classdef in dex.get_classdef_dict().iteritems():
            for interface in classdef.get_all_interface_types(dex_headers):
                # We don't want to match ourselves...
                if interface in interface_to_binder and clazz != interface_to_binder[interface]:
                    # got one!

                    aidl = AIDL(stub=clazz, binder=interface_to_binder[interface], interface=interface)
                    found_aidls.append(aidl)

    for aidl in found_aidls:
        print(aidl)

if __name__ == '__main__':
    main()
