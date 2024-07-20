import pylxd
import argparse
import subprocess

def get_vm_profiles():
    client = pylxd.Client()
    instances = client.instances.all()
    vm_profiles = {}
    active_gpu_profiles = set()
    gpu_profiles_list = []

    for instance in instances:
        vm_name = instance.name
        state = instance.state().status
        profiles = instance.profiles
        vm_profiles[vm_name] = (state, profiles)

        if state == "Running":
            for profile in profiles:
                if profile.startswith("gpu-"):
                    active_gpu_profiles.add(profile)
                    gpu_profiles_list.append(profile)

    return vm_profiles, active_gpu_profiles, gpu_profiles_list

def get_all_profiles():
    client = pylxd.Client()
    profiles = client.profiles.all()
    profile_names = [profile.name for profile in profiles]
    return profile_names

def print_vm_profiles(vm_profiles):
    print(f"{'NAME':<20} {'STATE':<10} {'PROFILES':<30}")
    print("=" * 60)
    
    for vm_name, (state, profiles) in vm_profiles.items():
        profiles_str = ", ".join(profiles)
        print(f"{vm_name:<20} {state:<10} {profiles_str:<30}")

def print_gpu_profiles(vm_profiles):
    print(f"{'NAME':<20} {'STATE':<10} {'GPU PROFILES':<30}")
    print("=" * 60)
    
    for vm_name, (state, profiles) in vm_profiles.items():
        gpu_profiles = [profile for profile in profiles if profile.startswith("gpu")]
        if gpu_profiles:
            gpu_profiles_str = ", ".join(gpu_profiles)
            print(f"{vm_name:<20} {state:<10} {gpu_profiles_str:<30}")

def stop_instance(instance_name):
    client = pylxd.Client()

    try:
        instance = client.instances.get(instance_name)
        instance.stop(wait=True)
        print(f"Instance '{instance_name}' has been stopped.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to stop instance '{instance_name}': {e}")

def gpu_status():
    try:
        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))
        _, active_gpu_profiles, gpu_profiles_list = get_vm_profiles()
        available_gpus = total_gpus - len(active_gpu_profiles)

        profiles_column_width = max(len(", ".join(gpu_profiles_list)), len("PROFILES"))

        print(f"{'TOTAL':<10} {'ACTIVE':<10} {'PROFILES':<{profiles_column_width}} {'AVAILABLE':<10}")
        print("=" * (34 + profiles_column_width))
        print(f"{total_gpus:<10} {len(active_gpu_profiles):<10} "
              f"{', '.join(gpu_profiles_list):<{profiles_column_width}} {available_gpus:<10}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute command: {e}")

def gpu_list():
    try:
        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))
        all_profiles = get_all_profiles()
        gpu_profiles = [profile for profile in all_profiles if profile.startswith("gpu-")]

        profiles_column_width = max(len(", ".join(gpu_profiles)), len("PROFILES"))

        print(f"{'TOTAL':<10} {'PROFILES':<{profiles_column_width}}")
        print("=" * (16 + profiles_column_width))
        print(f"{total_gpus:<10} {', '.join(gpu_profiles):<{profiles_column_width}}")
    except subprocess.CalledProcessError as e:
        print(f"Failed to execute command: {e}")

def start_instance(instance_name):
    client = pylxd.Client()

    try:
        instance = client.instances.get(instance_name)
        if instance.state().status == "Running":
            print(f"Instance '{instance_name}' is already running.")
            return

        _, active_gpu_profiles, _ = get_vm_profiles()
        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]

        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))
        available_gpus = total_gpus - len(active_gpu_profiles)

        if len(gpu_profiles_for_instance) > available_gpus:
            print(f"Error: Not enough available GPUs. Instance '{instance_name}' has "
                  f"{len(gpu_profiles_for_instance)} GPU profiles, but only {available_gpus} GPUs are available.")
            return

        conflicting_profiles = [
            profile for profile in gpu_profiles_for_instance if profile in active_gpu_profiles
        ]
        all_profiles = get_all_profiles()
        available_gpu_profiles = [
            profile for profile in all_profiles if profile.startswith("gpu-") and 
            profile not in active_gpu_profiles
        ]

        for conflicting_profile in conflicting_profiles:
            if available_gpu_profiles:
                new_profile = available_gpu_profiles.pop(0)
                instance_profiles.remove(conflicting_profile)
                instance_profiles.append(new_profile)
                print(f"Replaced conflicting profile '{conflicting_profile}' with "
                      f"available profile '{new_profile}' for instance '{instance_name}'.")
            else:
                print(f"Error: No available GPU profiles to replace conflicting profile "
                      f"'{conflicting_profile}' for instance '{instance_name}'.")
                return

        # Set profiles to ensure changes take effect
        instance.profiles = instance_profiles
        instance.save(wait=True)

        instance.start(wait=True)
        print(f"Instance '{instance_name}' has been started.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to start instance '{instance_name}': {e}")

def main():
    parser = argparse.ArgumentParser(description="Manage LXD instances and GPU status.")
    subparsers = parser.add_subparsers(dest="command")

    show_parser = subparsers.add_parser("show", help="Show information")
    show_subparsers = show_parser.add_subparsers(dest="show_command")
    show_profile_parser = show_subparsers.add_parser("profile", help="Show profiles of all instances")
    show_gpu_parser = show_subparsers.add_parser("gpu", help="Show GPU profiles of instances")

    stop_parser = subparsers.add_parser("stop", help="Stop a specific instance")
    stop_parser.add_argument("instance_name", help="Name of the instance to stop")

    start_parser = subparsers.add_parser("start", help="Start a specific instance")
    start_parser.add_argument("instance_name", help="Name of the instance to start")

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

