"""  """

import copy

import ghidra_utils

from __main__ import * 

def get_block_address(block):
    return block.getFirstStartAddress().getOffset()
    
def get_destinations(block, monitor):
    return [ref.getDestinationBlock() for ref in ghidra_utils.iterate(block.getDestinations(monitor)) if not ref.getFlowType().isCall()]
    
def find_loops(address=None, program=None, monitor=None):
    """ Walk the function to find any loop edges

        Observation - loops can only have one entry (but multiple exits [break], and multiple returns [continue]. Therefore, can rely on all elements inside a loop having passed through the entry.
    
        Therefore, define a loop edge as an edge where the path from function entrypoint to the source of the edge contains the destination of the edge.
    
        Move down destination blocks from entrypoint (skipping calls), marking as visited
        Record path for each block
        For each destination edge on each block, check if dest is already in path
            If it is, it's a loop edge!
        If a destination block is already visited, don't revisit (but the destination edge will be checked)
    """
    if monitor is None:
        monitor = getMonitor()

    function = ghidra_utils.get_function_at_address(address=address, program=program)
    
    entry_block = ghidra_utils.get_basic_block_at_address(address=function.getEntryPoint(), program=program)
    
    visited_list = []
    to_visit_list = [(entry_block, [])]
    
    loops = list()
    
    while len(to_visit_list) > 0:
        visit_block, path = to_visit_list.pop()
        visit_addr = get_block_address(visit_block)
        visited_list.append(visit_addr)
        print("checking {} {}".format(visit_block.getName(), [hex(int(addr)) for addr in path]))
        
        # add this block to path
        path.append(visit_addr)
        print([hex(int(addr)) for addr in path])
        
        # get each edge from this block
        edges = get_destinations(visit_block, monitor)
        
        for edge_dest in edges:
            edge_dest_addr = get_block_address(edge_dest)
            if edge_dest_addr in path:
                # loop detected! - edge dest is the loop head, visit is the loop tail
                loops.append((edge_dest_addr, visit_addr))
                # by implication, already visited, so don't readd
            else:
                # no loop - add it if we haven't already visited
                if edge_dest_addr not in visited_list and edge_dest_addr not in [get_block_address(block) for block, ignore in to_visit_list]:
                    add = (edge_dest, copy.copy(path))
                    print("Adding {} {}".format(add[0].getName(), [hex(int(addr)) for addr in add[1]]))
                    to_visit_list.append((edge_dest, copy.copy(path)))
                 
    print(["{}<-{}".format(hex(int(loop[0])),hex(int(loop[1]))) for loop in loops])
    return loops

    