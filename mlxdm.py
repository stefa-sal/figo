import pylxd

def get_vm_profiles():
    # Connect to the local LXD server
    client = pylxd.Client()

    # Get the list of all instances (containers/VMs)
    instances = client.instances.all()

    vm_profiles = {}

    for instance in instances:
        # Get the name of the instance (VM)
        vm_name = instance.name

        # Get the list of profiles associated with the instance
        profiles = instance.profiles

        # Store the profiles in the dictionary with the VM name as the key
        vm_profiles[vm_name] = profiles

    return vm_profiles

if __name__ == "__main__":
    vm_profiles = get_vm_profiles()
    
    # Print the profiles associated with each VM
    for vm_name, profiles in vm_profiles.items():
        print(f"VM Name: {vm_name}")
        print(f"Profiles: {', '.join(profiles)}")
        print()
