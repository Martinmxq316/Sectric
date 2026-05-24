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

    processes = []

    command = ["./bin/gcf_psi", "--idx", str(x), "--role", str(1),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]
    process = subprocess.Popen(command)
    processes.append(process)
    print(file_name)

    batch_size = 50
    with ThreadPoolExecutor(max_workers=batch_size) as executor:
        future_to_command = {executor.submit(subprocess.Popen, ["./bin/gcf_psi", "--neighbor", str(neighbor), "--role", str(2),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]): neighbor for neighbor in neighbors[:batch_size]}

        for future in as_completed(future_to_command):
            try:
                process = future.result()
                process.wait()
            except Exception as exc:
                print(f'process error: {exc}')

        remaining_neighbors = neighbors[batch_size:]
        while remaining_neighbors:
            future_to_command = {executor.submit(subprocess.Popen, ["./bin/gcf_psi", "--neighbor", str(neighbor), "--role", str(2),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]): neighbor for neighbor in remaining_neighbors[:batch_size]}

            for future in as_completed(future_to_command):
                try:
                    process = future.result()
                    process.wait()
                except Exception as exc:
                    print(f'process error: {exc}')

            remaining_neighbors = remaining_neighbors[batch_size:]


    command = ["./bin/gcf_psi", "--idx", str(x), "--role", str(0),"--name",file_name,"--num_d",MAX_DEGREE,"--num_v",NUM_VERTEX]
    process = subprocess.Popen(command)
    processes.append(process)


    for process in processes[:-1]:
        process.wait()

    processes[-1].wait()

if __name__ == "__main__":
    main()
