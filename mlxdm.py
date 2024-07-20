import pylxd
import argparse
import subprocess

def get_vm_profiles():
    # Connect to the local LXD server
    client = pylxd.Client()

    # Get the list of all instances (containers/VMs)
    instances = client.instances.all()

    vm_profiles = {}
    active_gpu_profiles = set()
    gpu_profiles_list = []

    for instance in instances:
        # Get the name of the instance (VM)
        vm_name = instance.name

        # Get the running state of the instance
        state = instance.state().status

        # Get the list of profiles associated with the instance
        profiles = instance.profiles

        # Store the profiles and state in the dictionary with the VM name as the key
        vm_profiles[vm_name] = (state, profiles)

        # Collect GPU profiles for running VMs and add them to active_gpu_profiles
        if state == "Running":
            for profile in profiles:
                if profile.startswith("gpu-"):
                    active_gpu_profiles.add(profile)
                    gpu_profiles_list.append(profile)

    return vm_profiles, active_gpu_profiles, gpu_profiles_list

def get_all_profiles():
    # Connect to the local LXD server
    client = pylxd.Client()

    # Get the list of all profiles
    profiles = client.profiles.all()
    
    # Extract profile names
    profile_names = [profile.name for profile in profiles]
    return profile_names

def print_vm_profiles(vm_profiles):
    # Print the header
    print(f"{'NAME':<20} {'STATE':<10} {'PROFILES':<30}")
    print("=" * 60)
    
    # Print each VM's state and profiles
    for vm_name, (state, profiles) in vm_profiles.items():
        profiles_str = ", ".join(profiles)
        print(f"{vm_name:<20} {state:<10} {profiles_str:<30}")

def print_gpu_profiles(vm_profiles):
    # Print the header
    print(f"{'NAME':<20} {'STATE':<10} {'GPU PROFILES':<30}")
    print("=" * 60)
    
    # Print each VM's state and GPU profiles
    for vm_name, (state, profiles) in vm_profiles.items():
        gpu_profiles = [profile for profile in profiles if profile.startswith("gpu")]
        if gpu_profiles:
            gpu_profiles_str = ", ".join(gpu_profiles)
            print(f"{vm_name:<20} {state:<10} {gpu_profiles_str:<30}")

def stop_instance(instance_name):
    # Connect to the local LXD server
    client = pylxd.Client()

    try:
        # Get the instance by name
        instance = client.instances.get(instance_name)

        # Stop the instance
        instance.stop(wait=True)
        print(f"Instance '{instance_name}' has been stopped.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to stop instance '{instance_name}': {e}")

def gpu_status():
    try:
        # Run the shell command to get NVIDIA GPU information
        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        # Count the number of lines in the output
        total_gpus = len(result.stdout.strip().split('\n'))

        # Get VM profiles and count active GPU profiles
        _, active_gpu_profiles, gpu_profiles_list = get_vm_profiles()

        # Calculate available GPUs
        available_gpus = total_gpus - len(active_gpu_profiles)

        # Print the GPU status in a column format
        print(f"{'TOTAL':<10} {'ACTIVE':<10} {'PROFILES':<30} {'AVAILABLE':<10}")
        print("=" * 60)
        print(f"{total_gpus:<10} {len(active_gpu_profiles):<10} {', '.join(gpu_profiles_list):<30} {available_gpus:<10}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute command: {e}")

def gpu_list():
    # Get total number of GPUs
    try:
        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))

        # Get all profiles
        all_profiles = get_all_profiles()
        
        # Filter profiles starting with "gpu-"
        gpu_profiles = [profile for profile in all_profiles if profile.startswith("gpu-")]

        # Print the GPU list in a column format
        print(f"{'TOTAL':<10} {'PROFILES':<30}")
        print("=" * 40)
        print(f"{total_gpus:<10} {', '.join(gpu_profiles):<30}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute command: {e}")

def start_instance(instance_name):
    # Connect to the local LXD server
    client = pylxd.Client()

    try:
        # Get the instance by name
        instance = client.instances.get(instance_name)

        # Check if the instance is already running
        if instance.state().status == "Running":
            print(f"Instance '{instance_name}' is already running.")
            return

        # Get the profiles associated with the instance
        _, active_gpu_profiles, _ = get_vm_profiles()
        instance_profiles = instance.profiles

        # Count the number of "gpu-" profiles associated with the instance
        gpu_profiles_for_instance = [profile for profile in instance_profiles if profile.startswith("gpu-")]

        # Count the total available GPUs
        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))
        available_gpus = total_gpus - len(active_gpu_profiles)

        # Check if the number of GPU profiles exceeds the available GPUs
        if len(gpu_profiles_for_instance) > available_gpus:
            print(f"Error: Not enough available GPUs. Instance '{instance_name}' has {len(gpu_profiles_for_instance)} GPU profiles, but only {available_gpus} GPUs are available.")
            return

        # Check if the profiles are already associated with running VMs
        conflicting_profiles = [profile for profile in gpu_profiles_for_instance if profile in active_gpu_profiles]
        if conflicting_profiles:
            print(f"Error: The following GPU profiles are already in use by running VMs: {', '.join(conflicting_profiles)}")
            return

        # Start the instance
        instance.start(wait=True)
        print(f"Instance '{instance_name}' has been started.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to start instance '{instance_name}': {e}")

def main():
    parser = argparse.ArgumentParser(description="Manage LXD instances and GPU status.")
    subparsers = parser.add_subparsers(dest="command")

    # Subparser for the "show" command
    show_parser = subparsers.add_parser("show", help="Show information")
    show_subparsers = show_parser.add_subparsers(dest="show_command")
    show_profile_parser = show_subparsers.add_parser("profile", help="Show profiles of all instances")
    show_gpu_parser = show_subparsers.add_parser("gpu", help="Show GPU profiles of instances")

    # Subparser for the "stop" command
    stop_parser = subparsers.add_parser("stop", help="Stop a specific instance")
    stop_parser.add_argument("instance_name", help="Name of the instance to stop")

    # Subparser for the "start" command
    start_parser = subparsers.add_parser("start", help="Start a specific instance")
    start_parser.add_argument("instance_name", help="Name of the instance to start")

    # Subparser for the "gpu" command
    gpu_parser = subparsers.add_parser("gpu", help="GPU information")
    gpu_subparsers = gpu_parser.add_subparsers(dest="gpu_command")
    gpu_status_parser = gpu_subparsers.add_parser("status", help="Show GPU status")
    gpu_list_parser = gpu_subparsers.add_parser("list", help="List GPU profiles")

    args = parser.parse_args()

    if args.command == "show":
        vm_profiles, _, _ = get_vm_profiles()
        if args.show_command == "profile":
            print_vm_profiles(vm_profiles)
        elif args.show_command == "gpu":
            print_gpu_profiles(vm_profiles)
        else:
            show_parser.print_help()
    elif args.command == "stop":
        stop_instance(args.instance_name)
    elif args.command == "start":
        start_instance(args.instance_name)
    elif args.command == "gpu":
        if args.gpu_command == "status":
            gpu_status()
        elif args.gpu_command == "list":
            gpu_list()
        else:
            gpu_parser.print_help()
    else:
        parser.print_help()

if __name__ == "__main__":
    main()
