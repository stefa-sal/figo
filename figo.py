import argparse
import pylxd
import subprocess

# Helper function to get VM profiles
def get_vm_profiles(client):
    vm_profiles = {}
    running_vms = {}
    stopped_vms = []

    # Iterate through all instances and categorize them based on their status
    for instance in client.instances.all():
        vm_profiles[instance.name] = instance.profiles
        if instance.status == "Running":
            running_vms[instance.name] = instance.profiles
        else:
            stopped_vms.append(instance.name)

    return vm_profiles, running_vms, stopped_vms

# Function to get all profiles
def get_all_profiles(client):
    profiles = client.profiles.all()
    return [profile.name for profile in profiles]

# Function to print VM profiles
def print_vm_profiles(vm_profiles, client):
    print("{:<20} {:<10} {:<30}".format("INSTANCE", "STATE", "PROFILES"))
    for name, profiles in vm_profiles.items():
        instance = client.instances.get(name)
        state = instance.status
        profiles_str = ", ".join(profiles)
        print("{:<20} {:<10} {:<30}".format(name, state, profiles_str))

# Function to print GPU profiles
def print_gpu_profiles(vm_profiles, client):
    print("{:<20} {:<10} {:<30}".format("INSTANCE", "STATE", "PROFILES"))
    for name, profiles in vm_profiles.items():
        instance = client.instances.get(name)
        state = instance.status
        gpu_profiles = [profile for profile in profiles if profile.startswith("gpu")]
        profiles_str = ", ".join(gpu_profiles)
        print("{:<20} {:<10} {:<30}".format(name, state, profiles_str))

# Function to stop a specific instance
def stop_instance(instance_name, client):
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Running":
            print(f"Error: Instance '{instance_name}' is not running.")
            return
        instance.stop(wait=True)
        print(f"Instance '{instance_name}' stopped.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to stop instance '{instance_name}': {e}")

# Function to start a specific instance
def start_instance(instance_name, client):
    instance = client.instances.get(instance_name)

    if instance.status != "Stopped":
        print(f"Error: Instance '{instance_name}' is not stopped.")
        return

    # Get the profiles associated with the instance
    instance_profiles = instance.profiles
    gpu_profiles_for_instance = [
        profile for profile in instance_profiles if profile.startswith("gpu-")
    ]

    # Get the total number of GPUs available
    result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
    total_gpus = len(result.stdout.strip().split('\n'))

    # Get the active GPU profiles from running instances
    running_instances = [i for i in client.instances.all() if i.status == "Running"]
    active_gpu_profiles = [
        profile for my_instance in running_instances for profile in my_instance.profiles 
        if profile.startswith("gpu-")
    ]

    available_gpus = total_gpus - len(active_gpu_profiles)
    if len(gpu_profiles_for_instance) > available_gpus:
        print(f"Error: Not enough available GPUs to start instance '{instance_name}'.")
        return

    # Replace conflicting GPU profiles
    conflict = False
    for gpu_profile in gpu_profiles_for_instance:
        for my_instance in running_instances:
            if gpu_profile in my_instance.profiles:
                conflict = True
                print(f"GPU profile '{gpu_profile}' is already in use by instance {my_instance.name}.")
                instance_profiles.remove(gpu_profile)
                new_profile = [
                    p for p in client.profiles.all() if p.name.startswith("gpu-")
                    and p.name not in active_gpu_profiles and p.name not in instance_profiles
                ][0].name
                instance_profiles.append(new_profile)
                print(f"Replaced GPU profile '{gpu_profile}' with '{new_profile}' "
                      f"for instance '{instance_name}'")
                break

    if conflict:
        instance.profiles = instance_profiles
        try:
            instance.save(wait=True)
        except pylxd.exceptions.LXDAPIException as e:
            print(f"Failed to update profiles for instance '{instance_name}': {e}")
            return

    try:   
        instance.start(wait=True)
        print(f"Instance '{instance_name}' started.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to start instance '{instance_name}': {e}")

# Function to add a GPU profile to an instance
def add_gpu_profile(instance_name, client):
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Stopped":
            print(f"Error: Instance '{instance_name}' is running or in error state.")
            return

        # Get the profiles associated with the instance
        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]

        # Get the total number of GPUs available
        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))

        if len(gpu_profiles_for_instance) >= total_gpus:
            print(f"Error: Instance '{instance_name}' already has the maximum number of GPU profiles.")
            return

        all_profiles = get_all_profiles(client)
        available_gpu_profiles = [
            profile for profile in all_profiles if profile.startswith("gpu-") 
            and profile not in instance_profiles
        ]

        if not available_gpu_profiles:
            print(f"Error: No available GPU profiles to add to instance '{instance_name}'.")
            return

        # Add the new GPU profile to the instance
        new_profile = available_gpu_profiles[0]
        instance_profiles.append(new_profile)
        instance.profiles = instance_profiles
        instance.save(wait=True)

        print(f"Added GPU profile '{new_profile}' to instance '{instance_name}'.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to add GPU profile to instance '{instance_name}': {e}")

# Function to remove a GPU profile from an instance
def remove_gpu_profile(instance_name, client):
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Stopped":
            print(f"Error: Instance '{instance_name}' is running or in error state.")
            return

        # Get the profiles associated with the instance
        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]

        if not gpu_profiles_for_instance:
            print(f"Error: Instance '{instance_name}' has no GPU profiles to remove.")
            return

        # Remove the GPU profile from the instance
        profile_to_remove = gpu_profiles_for_instance[0]
        instance_profiles.remove(profile_to_remove)
        instance.profiles = instance_profiles
        instance.save(wait=True)

        print(f"Removed GPU profile '{profile_to_remove}' from instance '{instance_name}'.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to remove GPU profile from instance '{instance_name}': {e}")

# Function to remove all GPU profiles from an instance
def remove_gpu_all_profiles(instance_name, client):
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Stopped":
            print(f"Error: Instance '{instance_name}' is running or in error state.")
            return

        # Get the profiles associated with the instance
        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]

        if not gpu_profiles_for_instance:
            print(f"Error: Instance '{instance_name}' has no GPU profiles to remove.")
            return

        # Remove all GPU profiles from the instance
        for gpu_profile in gpu_profiles_for_instance:
            instance_profiles.remove(gpu_profile)

        instance.profiles = instance_profiles
        instance.save(wait=True)

        print(f"Removed all GPU profiles from instance '{instance_name}'.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to remove GPU profiles from instance '{instance_name}': {e}")

# Function to show GPU status
def show_gpu_status(client):
    result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
    total_gpus = len(result.stdout.strip().split('\n'))

    running_instances = [i for i in client.instances.all() if i.status == "Running"]
    active_gpu_profiles = [
        profile for instance in running_instances for profile in instance.profiles 
        if profile.startswith("gpu-")
    ]

    available_gpus = total_gpus - len(active_gpu_profiles)

    gpu_profiles_str = ", ".join(active_gpu_profiles)
    print("{:<10} {:<10} {:<10} {:<40}".format("TOTAL", "AVAILABLE", "ACTIVE", "PROFILES"))
    print("{:<10} {:<10} {:<10} {:<40}".format(
        total_gpus, available_gpus, len(active_gpu_profiles), gpu_profiles_str))

# Function to list GPU profiles
def list_gpu_profiles(client):
    gpu_profiles = [
        profile.name for profile in client.profiles.all() if profile.name.startswith("gpu-")
    ]
    print("{:<10} {:<30}".format("TOTAL", "PROFILES"))
    print("{:<10} {:<30}".format(len(gpu_profiles), ", ".join(gpu_profiles)))

# Main function to parse command-line arguments and execute corresponding commands
def main():
    parser = argparse.ArgumentParser(description="Manage LXD instances and GPU profiles")
    subparsers = parser.add_subparsers(dest="command")

    # Add subparsers for the 'show' command
    show_parser = subparsers.add_parser("show", help="Show instance information")
    show_subparsers = show_parser.add_subparsers(dest="show_command")
    show_profile_parser = show_subparsers.add_parser("profile", help="Show instance profiles")
    show_gpu_parser = show_subparsers.add_parser("gpu", help="Show GPU profiles")

    # Add parser for the 'stop' command
    stop_parser = subparsers.add_parser("stop", help="Stop a specific instance")
    stop_parser.add_argument("instance_name", help="Name of the instance to stop")

    # Add parser for the 'start' command
    start_parser = subparsers.add_parser("start", help="Start a specific instance")
    start_parser.add_argument("instance_name", help="Name of the instance to start")

    # Add subparsers for the 'gpu' command
    gpu_parser = subparsers.add_parser("gpu", help="GPU information")
    gpu_subparsers = gpu_parser.add_subparsers(dest="gpu_command")
    gpu_status_parser = gpu_subparsers.add_parser("status", help="Show GPU status")
    gpu_list_parser = gpu_subparsers.add_parser("list", help="List GPU profiles")

    # Add parser for the 'add_gpu' command
    add_gpu_parser = subparsers.add_parser("add_gpu", help="Add a GPU profile to a specific instance")
    add_gpu_parser.add_argument("instance_name", help="Name of the instance to add a GPU profile to")

    # Add parser for the 'remove_gpu' command
    remove_gpu_parser = subparsers.add_parser("remove_gpu", 
                                              help="Remove a GPU profile from a specific instance")
    remove_gpu_parser.add_argument("instance_name", help="Name of the instance to remove a GPU profile from")

    # Add parser for the 'remove_gpu_all' command
    remove_gpu_all_parser = subparsers.add_parser("remove_gpu_all", 
                                                  help="Remove all GPU profiles from a specific instance")
    remove_gpu_all_parser.add_argument("instance_name", 
                                       help="Name of the instance to remove all GPU profiles from")

    args = parser.parse_args()
    client = pylxd.Client()

    if not args.command:
        parser.print_help()
    elif args.command == "show":
        if not args.show_command:
            show_parser.print_help()
        else:
            vm_profiles, _, _ = get_vm_profiles(client)
            if args.show_command == "profile":
                print_vm_profiles(vm_profiles, client)
            elif args.show_command == "gpu":
                print_gpu_profiles(vm_profiles, client)
    elif args.command == "stop":
        stop_instance(args.instance_name, client)
    elif args.command == "start":
        start_instance(args.instance_name, client)
    elif args.command == "gpu":
        if not args.gpu_command:
            gpu_parser.print_help()
        elif args.gpu_command == "status":
            show_gpu_status(client)
        elif args.gpu_command == "list":
            list_gpu_profiles(client)
    elif args.command == "add_gpu":
        add_gpu_profile(args.instance_name, client)
    elif args.command == "remove_gpu":
        remove_gpu_profile(args.instance_name, client)
    elif args.command == "remove_gpu_all":
        remove_gpu_all_profiles(args.instance_name, client)

if __name__ == "__main__":
    main()
