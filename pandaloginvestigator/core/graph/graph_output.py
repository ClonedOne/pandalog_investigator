from pandaloginvestigator.core.io import results_reader
import networkx as nx
from os import path

color_db = 'blue'
color_created = 'red'
color_written = 'yellow'
color_unknown = 'green'


def generate_graph(dir_results_path):
    """
    Reads the corrupted processes result file.
    Generates a .graphml file containing the structure of the directed graph of corrupted processes.
    Nodes will be colored differently based on their origin.

    :param dir_results_path: path to the global result folder
    :return:
    """
    graph = nx.DiGraph()
    corrupted_dict = results_reader.read_result_corrupted(dir_results_path)

    for filename in corrupted_dict:

        if len(corrupted_dict[filename]) == 0:
            continue

        for corrupted_process in corrupted_dict[filename]:
            process = str(corrupted_process[0][0]) + ',' + str(corrupted_process[0][1])
            corrupted_process_origin = corrupted_process[1]
            parent = str(corrupted_process[2][0]) + ',' + str(corrupted_process[2][1])

            if corrupted_process_origin == 'database':
                c = color_db
            elif corrupted_process_origin == 'created':
                c = color_created
            elif corrupted_process_origin == 'mem_written':
                c = color_written
            else:
                c = color_unknown

            graph.add_node(process, origin=corrupted_process_origin, color=c)
            graph.add_edge(parent, process)

    nx.write_graphml(graph, path.join(dir_results_path, 'corrupted_processes_graph.graphml'))

