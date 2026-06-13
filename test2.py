import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

def main():

    x = input("Please enter the node number x：")
    try:

        x = int(x)
    except ValueError:

        print("Please enter the node number x：")
        return


    neighbors = []
    file_name=input("Please enter the filename:")
    # pattern : name_nodeCount_edgeCount_maxDegree
    MAX_DEGREE=(file_name.split('_')[3])
    NUM_VERTEX=(file_name.split('_')[1])
    filename = f"./data/neighbor_files_"+file_name+f"/neighbor_{x}.txt"
    try:
        with open(filename, 'r') as file:
            for line in file:
                neighbors.append(int(line.strip()))
    except FileNotFoundError:

        print(f"The file {filename} does not exist.")
        return

    print("The count of the neighbors of the node is: ", len(neighbors))

    command = ["./bin/gcf_4cycle", "--idx", str(x), "--role", str(1),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX, "--profile"]
    querier_process = subprocess.Popen(command)
    print(file_name)

    command = ["./bin/gcf_4cycle", "--idx", str(x), "--role", str(0),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX, "--profile"]
    server_process = subprocess.Popen(command)

    batch_size = 32
    vertices = [i for i in range(0, int(NUM_VERTEX)) if i != x]
    remaining_vertices = vertices
    with ThreadPoolExecutor(max_workers=batch_size) as executor:
        while remaining_vertices:
            current_batch = remaining_vertices[:batch_size]
            future_to_command = {executor.submit(subprocess.Popen, ["./bin/gcf_4cycle", "--neighbor", str(vertex), "--role", str(2),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]): vertex for vertex in current_batch}

            for future in as_completed(future_to_command):
                vertex = future_to_command[future]
                try:
                    process = future.result()
                    return_code = process.wait()
                    if return_code != 0:
                        print(f'process error: vertex {vertex} exited with {return_code}')
                except Exception as exc:
                    print(f'process error for vertex {vertex}: {exc}')

            remaining_vertices = remaining_vertices[batch_size:]

    querier_return_code = querier_process.wait()
    if querier_return_code != 0:
        print(f'process error: querier exited with {querier_return_code}')

    server_return_code = server_process.wait()
    if server_return_code != 0:
        print(f'process error: server exited with {server_return_code}')

if __name__ == "__main__":
    main()
    
