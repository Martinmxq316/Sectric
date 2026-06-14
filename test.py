import argparse
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed


def parse_args():
    parser = argparse.ArgumentParser(description="Run triangle PSI counting roles.")
    parser.add_argument("--idx", type=int, help="Query vertex index.")
    parser.add_argument("--name", help="Dataset name, e.g. test_6_1_4.")
    parser.add_argument("--batch-size", type=int, default=50, help="Concurrent role-2 preprocessing batch size.")
    parser.add_argument("--profile", action="store_true", help="Enable gcf_psi aggregate profiling for roles 0 and 1.")
    parser.add_argument(
        "--profile-candidate-detail",
        action="store_true",
        help="Enable gcf_psi profiling with detail rows for roles 0 and 1.",
    )
    return parser.parse_args()


def read_required_inputs(args):
    if args.idx is None:
        x = input("Please enter the node number x:")
        try:
            args.idx = int(x)
        except ValueError:
            print("Please enter the node number x:")
            return False

    if args.name is None:
        args.name = input("Please enter the filename:")

    return True


def run_role2_batch(neighbors, batch_size, base_role2_command):
    batch_size = max(1, batch_size)
    remaining_neighbors = list(neighbors)
    while remaining_neighbors:
        current_batch = remaining_neighbors[:batch_size]
        with ThreadPoolExecutor(max_workers=batch_size) as executor:
            future_to_neighbor = {
                executor.submit(subprocess.Popen, base_role2_command + ["--neighbor", str(neighbor)]): neighbor
                for neighbor in current_batch
            }

            for future in as_completed(future_to_neighbor):
                neighbor = future_to_neighbor[future]
                try:
                    process = future.result()
                    return_code = process.wait()
                    if return_code != 0:
                        print(f"role 2 process for neighbor {neighbor} exited with code {return_code}")
                except Exception as exc:
                    print(f"role 2 process for neighbor {neighbor} error: {exc}")

        remaining_neighbors = remaining_neighbors[batch_size:]


def main():
    args = parse_args()
    if not read_required_inputs(args):
        return

    file_name = args.name
    # pattern: name_nodeCount_edgeCount_maxDegree
    try:
        max_degree = file_name.split("_")[3]
        num_vertex = file_name.split("_")[1]
    except IndexError:
        print("Dataset name should match pattern name_nodeCount_edgeCount_maxDegree.")
        return

    neighbors = []
    filename = f"./data/neighbor_files_{file_name}/neighbor_{args.idx}.txt"
    try:
        with open(filename, "r") as file:
            for line in file:
                neighbors.append(int(line.strip()))
    except FileNotFoundError:
        print(f"The file {filename} does not exist.")
        return

    print("The count of the neighbors of the node is: ", len(neighbors))

    profile_flags = []
    if args.profile_candidate_detail:
        profile_flags.append("--profile-candidate-detail")
    elif args.profile:
        profile_flags.append("--profile")

    common_args = [
        "--name",
        file_name,
        "--num_d",
        max_degree,
        "--num_v",
        num_vertex,
    ]

    processes = []

    querier_command = [
        "./bin/gcf_psi",
        "--idx",
        str(args.idx),
        "--role",
        "1",
    ] + common_args + profile_flags
    querier_process = subprocess.Popen(querier_command)
    processes.append(querier_process)
    print(file_name)

    role2_command = [
        "./bin/gcf_psi",
        "--role",
        "2",
    ] + common_args
    run_role2_batch(neighbors, args.batch_size, role2_command)

    server_command = [
        "./bin/gcf_psi",
        "--idx",
        str(args.idx),
        "--role",
        "0",
    ] + common_args + profile_flags
    server_process = subprocess.Popen(server_command)
    processes.append(server_process)

    for process in processes[:-1]:
        process.wait()

    processes[-1].wait()


if __name__ == "__main__":
    main()
