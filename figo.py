import argparse
import pylxd
import subprocess
import logging
import os
import yaml

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_vm_profiles(client):
    """Get VM profiles and categorize them based on their status."""
    vm_profiles = {}
    running_vms = {}
    stopped_vms = []

    for instance in client.instances.all():
        vm_profiles[instance.name] = instance.profiles
        if instance.status == "Running":
            running_vms[instance.name] = instance.profiles
        else:
            stopped_vms.append(instance.name)

    return vm_profiles, running_vms, stopped_vms

def get_all_profiles(client):
    """Get all available profiles."""
    return [profile.name for profile in client.profiles.all()]

def print_vm_profiles(vm_profiles, client):
    """Print VM profiles in a formatted table."""
    print("{:<20} {:<10} {:<30}".format("INSTANCE", "STATE", "PROFILES"))
    for name, profiles in vm_profiles.items():
        instance = client.instances.get(name)
        state = instance.status
        profiles_str = ", ".join(profiles)
        print("{:<20} {:<10} {:<30}".format(name, state, profiles_str))

def print_gpu_profiles(vm_profiles, client):
    """Print GPU profiles in a formatted table."""
    print("{:<20} {:<10} {:<30}".format("INSTANCE", "STATE", "PROFILES"))
    for name, profiles in vm_profiles.items():
        instance = client.instances.get(name)
        state = instance.status
        gpu_profiles = [profile for profile in profiles if profile.startswith("gpu")]
        profiles_str = ", ".join(gpu_profiles)
        print("{:<20} {:<10} {:<30}".format(name, state, profiles_str))

def stop_instance(instance_name, client):
    """Stop a specific instance."""
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Running":
            logger.error(f"Instance '{instance_name}' is not running.")
            return
        instance.stop(wait=True)
        logger.info(f"Instance '{instance_name}' stopped.")
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to stop instance '{instance_name}': {e}")

def start_instance(instance_name, client):
    """Start a specific instance."""
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Stopped":
            logger.error(f"Instance '{instance_name}' is not stopped.")
            return

        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]
        
        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))
        
        running_instances = [
            i for i in client.instances.all() if i.status == "Running"
        ]
        active_gpu_profiles = [
            profile for my_instance in running_instances for profile in my_instance.profiles
            if profile.startswith("gpu-")
        ]

        available_gpus = total_gpus - len(active_gpu_profiles)
        if len(gpu_profiles_for_instance) > available_gpus:
            logger.error(
                f"Not enough available GPUs to start instance '{instance_name}'."
            )
            return

        conflict = False
        for gpu_profile in gpu_profiles_for_instance:
            for my_instance in running_instances:
                if gpu_profile in my_instance.profiles:
                    conflict = True
                    logger.warning(
                        f"GPU profile '{gpu_profile}' is already in use by "
                        f"instance {my_instance.name}."
                    )
                    instance_profiles.remove(gpu_profile)
                    new_profile = [
                        p for p in client.profiles.all() 
                        if p.name.startswith("gpu-") and p.name not in active_gpu_profiles
                        and p.name not in instance_profiles
                    ][0].name
                    instance_profiles.append(new_profile)
                    logger.info(
                        f"Replaced GPU profile '{gpu_profile}' with '{new_profile}' "
                        f"for instance '{instance_name}'"
                    )
                    break

        if conflict:
            instance.profiles = instance_profiles
            instance.save(wait=True)

        instance.start(wait=True)
        logger.info(f"Instance '{instance_name}' started.")
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to start instance '{instance_name}': {e}")

def add_gpu_profile(instance_name, client):
    """Add a GPU profile to an instance."""
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Stopped":
            logger.error(f"Instance '{instance_name}' is running or in error state.")
            return

        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]

        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))

        if len(gpu_profiles_for_instance) >= total_gpus:
            logger.error(
                f"Instance '{instance_name}' already has the maximum number of GPU profiles."
            )
            return

        all_profiles = get_all_profiles(client)
        available_gpu_profiles = [
            profile for profile in all_profiles if profile.startswith("gpu-")
            and profile not in instance_profiles
        ]

        if not available_gpu_profiles:
            logger.error(
                f"No available GPU profiles to add to instance '{instance_name}'."
            )
            return

        new_profile = available_gpu_profiles[0]
        instance_profiles.append(new_profile)
        instance.profiles = instance_profiles
        instance.save(wait=True)

        logger.info(
            f"Added GPU profile '{new_profile}' to instance '{instance_name}'."
        )
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to add GPU profile to instance '{instance_name}': {e}")

def remove_gpu_profile(instance_name, client):
    """Remove a GPU profile from an instance."""
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Stopped":
            logger.error(f"Instance '{instance_name}' is running or in error state.")
            return

        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]

        if not gpu_profiles_for_instance:
            logger.error(f"Instance '{instance_name}' has no GPU profiles to remove.")
            return

        profile_to_remove = gpu_profiles_for_instance[0]
        instance_profiles.remove(profile_to_remove)
        instance.profiles = instance_profiles
        instance.save(wait=True)

        logger.info(
            f"Removed GPU profile '{profile_to_remove}' from instance '{instance_name}'."
        )
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(
            f"Failed to remove GPU profile from instance '{instance_name}': {e}"
        )

def remove_gpu_all_profiles(instance_name, client):
    """Remove all GPU profiles from an instance."""
    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Stopped":
            logger.error(f"Instance '{instance_name}' is running or in error state.")
            return

        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]

        if not gpu_profiles_for_instance:
            logger.error(f"Instance '{instance_name}' has no GPU profiles to remove.")
            return

        for gpu_profile in gpu_profiles_for_instance:
            instance_profiles.remove(gpu_profile)

        instance.profiles = instance_profiles
        instance.save(wait=True)

        logger.info(
            f"Removed all GPU profiles from instance '{instance_name}'."
        )
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(
            f"Failed to remove GPU profiles from instance '{instance_name}': {e}"
        )

def show_gpu_status(client):
    """Show the status of GPUs."""
    result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
    total_gpus = len(result.stdout.strip().split('\n'))

    running_instances = [
        i for i in client.instances.all() if i.status == "Running"
    ]
    active_gpu_profiles = [
        profile for instance in running_instances for profile in instance.profiles
        if profile.startswith("gpu-")
    ]

    available_gpus = total_gpus - len(active_gpu_profiles)

    gpu_profiles_str = ", ".join(active_gpu_profiles)
    print("{:<10} {:<10} {:<10} {:<40}".format("TOTAL", "AVAILABLE", "ACTIVE", "PROFILES"))
    print("{:<10} {:<10} {:<10} {:<40}".format(total_gpus, available_gpus, len(active_gpu_profiles), gpu_profiles_str))

def list_gpu_profiles(client):
    """List all GPU profiles."""
    gpu_profiles = [
        profile.name for profile in client.profiles.all() if profile.name.startswith("gpu-")
    ]
    print("{:<10} {:<30}".format("TOTAL", "PROFILES"))
    print("{:<10} {:<30}".format(len(gpu_profiles), ", ".join(gpu_profiles)))

def dump_profiles(client):
    """Dump all profiles into .yaml files."""
    profiles = client.profiles.all()
    directory = "./profiles"
    
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    for profile in profiles:
        profile_data = {
            'name': profile.name,
            'description': profile.description,
            'config': profile.config,
            'devices': profile.devices
        }
        file_name = os.path.join(directory, f"{profile.name}.yaml")
        with open(file_name, 'w') as file:
            yaml.dump(profile_data, file)
        print(f"Profile '{profile.name}' saved to '{file_name}'.")

def main():
    parser = argparse.ArgumentParser(description="Manage LXD instances and GPU profiles")
    subparsers = parser.add_subparsers(dest="command")

    show_parser = subparsers.add_parser("show", help="Show instance information")
    show_subparsers = show_parser.add_subparsers(dest="show_command")
    show_profile_parser = show_subparsers.add_parser("profile", help="Show instance profiles")
    show_gpu_parser = show_subparsers.add_parser("gpu", help="Show GPU profiles")

    stop_parser = subparsers.add_parser("stop", help="Stop a specific instance")
    stop_parser.add_argument("instance_name", help="Name of the instance to stop")

    start_parser = subparsers.add_parser("start", help="Start a specific instance")
    start_parser.add_argument("instance_name", help="Name of the instance to start")

    gpu_parser = subparsers.add_parser("gpu", help="GPU information")
    gpu_subparsers = gpu_parser.add_subparsers(dest="gpu_command")
    gpu_status_parser = gpu_subparsers.add_parser("status", help="Show GPU status")
    gpu_list_parser = gpu_subparsers.add_parser("list", help="List GPU profiles")

    add_gpu_parser = subparsers.add_parser("add_gpu", help="Add a GPU profile to a specific instance")
    add_gpu_parser.add_argument("instance_name", help="Name of the instance to add a GPU profile to")

    remove_gpu_parser = subparsers.add_parser("remove_gpu", help="Remove a GPU profile from a specific instance")
    remove_gpu_parser.add_argument("instance_name", help="Name of the instance to remove a GPU profile from")

    remove_gpu_all_parser = subparsers.add_parser("remove_gpu_all", help="Remove all GPU profiles from a specific instance")
    remove_gpu_all_parser.add_argument("instance_name", help="Name of the instance to remove all GPU profiles from")

    dump_profiles_parser = subparsers.add_parser("dump_profiles", help="Dump all profiles to .yaml files")

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
    elif args.command == "dump_profiles":
        dump_profiles(client)

if __name__ == "__main__":
    main()
