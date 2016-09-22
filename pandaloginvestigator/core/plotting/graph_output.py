from pandaloginvestigator.core.utils import results_reader
import networkx as nx
import matplotlib.pyplot as plt


color_db = 'blue'
color_created = 'red'
color_wirtten = 'yellow'
color_unknown = 'green'


def generate_graph(dir_results_path):
    graph = nx.DiGraph()
    corrupted_dict = results_reader.read_result_corrupted(dir_results_path)
    for filename in corrupted_dict:
        if len(corrupted_dict[filename]) == 0:
            continue
        for malware in corrupted_dict[filename]:
            print(malware)
            process = str(malware[0][0]) + ',' + str(malware[0][1])
            malware_origin = malware[1]
            parent = str(malware[2][0]) + ',' + str(malware[2][1])
            if malware_origin == 'database':
                c = color_db
            elif malware_origin == 'created':
                c = color_created
            elif malware_origin == 'mem_written':
                c = color_wirtten
            else:
                c = color_unknown
            graph.add_node(process, origin=malware_origin, color=c)
            graph.add_edge(parent, process)
    nx.draw(graph)
    plt.show()
    nx.write_graphml(graph, dir_results_path + '/graph.graphml')

