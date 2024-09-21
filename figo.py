# # PYTHON_ARGCOMPLETE_OK
#!/home/gpuserver/figo/venv/bin/python

import argparse
import argcomplete
import pylxd
import subprocess
import logging
import os
import ipaddress
import yaml
import re
import socket
import json 
import cryptography.hazmat.backends
import cryptography.hazmat.primitives.serialization
import cryptography.hazmat.primitives.asymmetric.rsa
import cryptography.x509
import cryptography.x509.oid
import datetime
from urllib.parse import urlparse

NET_PROFILE = "net-bridged-br-200-3"
NAME_SERVER_IP_ADDR = "160.80.1.8"
NAME_SERVER_IP_ADDR_2 = "8.8.8.8"
PROFILE_DIR = "./profiles"
USER_DIR = "./users"

# Directory that contains the remote node certificates
CERTIFICATE_DIR = "./certs"

# Base IP address to start the IP address generation for WireGuard VPN clients
BASE_IP = "10.202.1.15"

# WireGuard public key of the VPN server 
PublicKey = "rdM5suGD/hTHdStf/K1SVc4rviUcUQbKnARnw0AAwT8="

# Allowed IP addresses for the VPN server
AllowedIPs = "10.192.0.0/10"

# Endpoint of the VPN server
Endpoint = "gpunet-vpn.netgroup.uniroma2.it:13232"

FIGO_PREFIX="figo-"  

# NB: PROJECT_PREFIX cannot contain underscores
PROJECT_PREFIX = FIGO_PREFIX 

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("_")

#############################################
###### generic helper functions         #####
#############################################

def truncate(text, length):
    """Helper function to truncate text to a specific length with '*>' at the end if trimmed."""
    if len(text) > length:
        return f"{text[:length-2]}*>"
    return text

#############################################
###### figo instance command functions #####
#############################################

def get_incus_remotes():
    """Fetches the list of Incus remotes as a JSON object.
    
    Returns:    A dictionary of remote names and their information.
    Raises:     RuntimeError if the command fails to retrieve the JSON list
                ValueError if the JSON output cannot be parsed.
                
    """
    result = subprocess.run(['incus', 'remote', 'list', '--format', 'json'], capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to retrieve Incus remotes: {result.stderr}")

    try:
        remotes = json.loads(result.stdout)
        return remotes
    except json.JSONDecodeError:
        raise ValueError("Failed to parse JSON. The output may not be in the expected format.")

def get_projects(remote_node="local"): 
    """Fetches and returns the list of projects as a JSON object.
    
    Returns:    A list of projects as JSON objects if successful. Otherwise, returns None.
    """
    try:
        result = subprocess.run(['incus', 'project', 'list', f"{remote_node}:", '--format', 'json'], capture_output=True, text=True)
    except subprocess.CalledProcessError as e:
        #logger.error(f"Error: {e.stderr.strip()}")
        return None

    if result.returncode != 0:
        #logger.error(f"Failed to retrieve projects: {result.stderr}")
        return None

    try:
        projects = json.loads(result.stdout)
        return projects
    except json.JSONDecodeError:
        logger.error("Failed to parse JSON output.")
        return None

def run_incus_list(remote_node="local", project_name="default"):
    """Run the 'incus list -f json' command, optionally targeting a remote node and project
    
    Return the output as JSON if successful, otherwise return None.
    """
    try:
        # Prepare the command with an optional remote node and project name using the correct syntax
        command = ["incus", "list", "-f", "json", "--project", project_name]
        if remote_node:
            command = ["incus", "list", f"{remote_node}:", "-f", "json", "--project", project_name]
        
        # Run the command to get the list of instances in JSON format
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        
        # Parse the JSON output
        instances = json.loads(result.stdout)
        return instances
    except subprocess.CalledProcessError as e:
        # Print the exact error message from the command's stderr
        # logger.error(f"Error: {e.stderr.strip()}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Error: Failed to parse JSON output. {e}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error while running 'incus list -f json': {e}")
        return None

def get_and_print_instances(remote_node=None, project_name=None, full=False):
    """Get instances from the specified remote node and project and print their details.
    
    Returns:    False if fetching the instances failed, True otherwise.
    """

    RED = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"

    # Get the instances from 'incus list -f json'
    instances = run_incus_list(remote_node=remote_node, project_name=project_name)
    if instances is None:
        return  False # Exit if fetching the instances failed

    # Iterate through instances and print their details in columns
    for instance in instances:
        name = instance.get("name", "Unknown")
        instance_type = "vm" if instance.get("type") == "virtual-machine" else "cnt"
        state = instance.get("status", "err")[:3].lower()  # Shorten the status

        # Construct the context column as remote_name:project_name
        project_name = instance.get("project", "default")
        context = f"{remote_node}:{project_name}" if remote_node else f"local:{project_name}"

        if full:
            # Print all profiles
            profiles_str = ", ".join(instance.get("profiles", []))
            print("{:<14} {:<4} {:<5} {:<25} {:<30}".format(name, instance_type, state, truncate(context, 25), profiles_str))
        else:
            # Print only GPU profiles with color coding based on state
            gpu_profiles = [profile for profile in instance.get("profiles", []) if profile.startswith("gpu")]
            profiles_str = ", ".join(gpu_profiles)
            colored_profiles_str = f"{RED}{profiles_str}{RESET}" if state == "run" else f"{GREEN}{profiles_str}{RESET}"
            print("{:<14} {:<4} {:<5} {:<25} {:<30}".format(name, instance_type, state, truncate(context, 25), colored_profiles_str))
        
    return True

def print_profiles(remote_node=None, project_name=None, full=False):
    """Print profiles of all instances, either from the local or a remote Incus node.
    If full is False, prints only GPU profiles with color coding.
    """
    # Determine the header and profile type based on the 'full' flag
    if full:
        print("{:<14} {:<4} {:<5} {:<25} {:<30}".format("INSTANCE", "TYPE", "STATE", "CONTEXT", "PROFILES"))
    else:
        print("{:<14} {:<4} {:<5} {:<25} {:<30}".format("INSTANCE", "TYPE", "STATE", "CONTEXT", "GPU PROFILES"))

    # use a set to store the remote nodes that failed to retrieve the projects
    set_of_errored_remotes = set()
    if remote_node is None:
        #iterate over all remote nodes
        remotes = get_incus_remotes()
        for my_remote_node in remotes:
            # check to skip all the remote node of type images
            # Skipping remote node with protocol simplestreams
            if remotes[my_remote_node]["Protocol"] == "simplestreams":
                continue

            if project_name is None:
                # iterate over all projects
                projects = get_projects(remote_node=my_remote_node)
                if projects is None:
                    set_of_errored_remotes.add(my_remote_node)
                else: # projects is not None:
                    for project in projects:
                        my_project_name = project["name"]
                        result = get_and_print_instances(remote_node=my_remote_node, project_name=my_project_name, full=full)
                        if not result:
                            set_of_errored_remotes.add(my_remote_node)
            else:
                result = get_and_print_instances(remote_node=my_remote_node, project_name=project_name, full=full)
                if not result:
                    set_of_errored_remotes.add(my_remote_node)
    else:
        # Get instances from the specified remote node
        if project_name is None:
            # iterate over all projects
            projects = get_projects(remote_node=remote_node)
            if projects is None:
                set_of_errored_remotes.add(remote_node)
            else:  # projects is not None:
                for project in projects:
                    my_project_name = project["name"]
                    result = get_and_print_instances(remote_node=remote_node, project_name=my_project_name, full=full)
                    if not result:
                        set_of_errored_remotes.add(remote_node)
        else:
            # Get instances from the specified remote node and project
            result = get_and_print_instances(remote_node=remote_node, project_name=project_name, full=full)
            if not result:
                set_of_errored_remotes.add(remote_node)

    if set_of_errored_remotes:
        logger.error(f"Error: Failed to retrieve projects from remote(s): {', '.join(set_of_errored_remotes)}")

def get_remote_client(remote_node, project_name='default'):
    """Create a pylxd.Client instance for the specified remote node and project.
    
    Returns:  A pylxd.Client instance for the remote node if successful, None otherwise.
    """
    #TODO add the code to handle the case when the remote node is not reachable and return None

    if remote_node == "local":
        # Create a pylxd.Client instance for the local server
        try:
            return pylxd.Client(project=project_name)
        except pylxd.exceptions.ClientConnectionFailed as e:
            logger.error(f"Failed to connect to remote '{remote_node}' and project '{project_name}': Client connection failed.")
            return None
        
    else:
        address = get_remote_address(remote_node)
        cert_path = get_certificate_path(remote_node)

        # Create a pylxd.Client instance with SSL verification
        try:
            client_instance = pylxd.Client(endpoint=address, verify=cert_path, project=project_name)
            try:
                client_instance.instances.get("x") # Test if the project exist by fetching a non-existent instance
            except pylxd.exceptions.NotFound as e:
                if "Project not found" in str(e):
                    logger.error(f"Failed to connect to remote '{remote_node}' and project '{project_name}': Project not found.")
                    return None 
            except Exception as e:
                logger.error(f"Failed to connect to remote '{remote_node}' and project '{project_name}': {e}")
                return None
            return client_instance   
        except pylxd.exceptions.ClientConnectionFailed as e:
            logger.error(f"Failed to connect to remote '{remote_node}' and project '{project_name}': Client connection failed.")
            return None
        except Exception as e:
            logger.error(f"Failed to connect to remote '{remote_node}' and project '{project_name}': {e}")
            return None

def start_instance(instance_name, remote, project):
    """Start a specific instance on a given remote and within a specific project.
    
    Returns:    True if the instance was started successfully, False otherwise.
    """
    try:
        # Connect to the specified remote and project 
        remote_client = get_remote_client(remote, project_name=project)

        if not remote_client:
            return False
        
    except Exception as e:
        logger.error(f"Failed to connect to remote '{remote}' and project '{project}': An unexpected error occurred: {e})")
        return False
    
    try:
        instance = remote_client.instances.get(instance_name)

        if instance.status != "Stopped":
            logger.error(f"Instance '{instance_name}' in project '{project}' on remote '{remote}' is not stopped.")
            return False

        # Get GPU profiles associated with this instance
        instance_profiles = instance.profiles
        gpu_profiles_for_instance = [
            profile for profile in instance_profiles if profile.startswith("gpu-")
        ]
        
        # Check GPU availability
        result = subprocess.run('lspci | grep NVIDIA', capture_output=True, text=True, shell=True)
        total_gpus = len(result.stdout.strip().split('\n'))
        
        running_instances = [
            i for i in remote_client.instances.all() if i.status == "Running"
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
            return False

        # Resolve GPU conflicts
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
                        p for p in remote_client.profiles.all() 
                        if p.name.startswith("gpu-") and p.name not in active_gpu_profiles
                        and p.name not in instance_profiles
                    ][0].name
                    instance_profiles.append(new_profile)
                    logger.info(
                        f"Replaced GPU profile '{gpu_profile}' with '{new_profile}' "
                        f"for instance '{instance_name}'"
                    )
                    break

        # Update profiles if needed and start the instance
        if conflict:
            instance.profiles = instance_profiles
            instance.save(wait=True)

        instance.start(wait=True)
        logger.info(f"Instance '{instance_name}' started on '{remote}:{project}'.")
        return True

    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to start instance '{instance_name}' in project '{project}' on remote '{remote}': {e}")
        return False


def stop_instance(instance_name, remote, project):
    """Stop a specific instance."""

    try:
        # get the specified instance in project and remote  
        remote_client = get_remote_client(remote, project_name=project)
        instance = remote_client.instances.get(instance_name)

        if instance.status != "Running":
            logger.error(f"Instance '{instance_name}' in project '{project}' on remote '{remote}' is not running.")
            return

        instance.stop(wait=True)
        logger.info(f"Instance '{instance_name}' stopped.")
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to stop instance '{instance_name}' in project '{project}' on remote '{remote}': {e}")

def set_user_key(instance_name, remote, project, key_filename, client):
    """Set a public key in the /home/mpi/.ssh/authorized_keys of the specified instance."""
    try:
        # Read the public key from the file
        with open(key_filename, 'r') as key_file:
            public_key = key_file.read().strip()

        # get the specified instance in project and remote  
        remote_client = get_remote_client(remote, project_name=project)
        instance = remote_client.instances.get(instance_name)

        # Check if the instance is running
        if instance.status != "Running":
            logger.error(f"Error: Instance '{instance_name}' is not running.")
            return

        # Connect to the instance using LXD's exec
        def exec_command(command):
            try:
                exec_result = instance.execute(command)
                output, error = exec_result
                if error:
                    logger.error(f"Error executing command '{' '.join(command)}': {error}")
                return output
            except Exception as e:
                logger.error(f"Exception while executing command '{' '.join(command)}': {e}")
                return None

        # Create .ssh directory
        exec_command(['mkdir', '-p', '/home/mpi/.ssh'])

        # Create authorized_keys file
        exec_command(['touch', '/home/mpi/.ssh/authorized_keys'])

        # Set permissions
        exec_command(['chmod', '600', '/home/mpi/.ssh/authorized_keys'])
        exec_command(['chown', 'mpi:mpi', '/home/mpi/.ssh/authorized_keys'])

        # Add the public key
        exec_command(['sh', '-c', f'echo "{public_key}" >> /home/mpi/.ssh/authorized_keys'])

        logger.info(f"Public key from '{key_filename}' added to /home/mpi/.ssh/authorized_keys in instance '{instance_name}'.")
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to set user key for instance '{instance_name}': {e}")
    except FileNotFoundError:
        logger.error(f"File '{key_filename}' not found.")
    except Exception as e:
        logger.error(f"An error occurred: {e}")

def is_valid_ip(ip):
    """Check if the provided string is a valid IPv4 address."""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        octets = ip.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    return False

def set_ip(instance_name, remote, project, ip_address, gw_address, client):
    """Set a static IP address and gateway for a stopped instance."""
    if not is_valid_ip(ip_address):
        logger.error(f"Error: '{ip_address}' is not a valid IP address.")
        return
    
    if not is_valid_ip(gw_address):
        logger.error(f"Error: '{gw_address}' is not a valid IP address.")
        return

    try:
        # get the specified instance in project and remote  
        remote_client = get_remote_client(remote, project_name=project)
        instance = remote_client.instances.get(instance_name)

        if instance.status != "Stopped":
            logger.error(f"Error: Instance '{instance_name}' is not stopped.")
            return
        
        # Check if a profile starting with "net-" is associated with the instance
        net_profiles = [profile for profile in instance.profiles if profile.startswith("net-")]
        if not net_profiles:
            logger.info(f"Instance '{instance_name}' does not have a 'net-' profile associated. Adding '{NET_PROFILE}' profile.")
            # Add the NET_PROFILE profile to the instance
            instance.profiles.append(NET_PROFILE)
            instance.save(wait=True)

        network_config = f"""
version: 1
config:
  - type: physical
    name: enp5s0
    subnets:
      - type: static
        ipv4: true
        address: {ip_address}
        netmask: 255.255.255.0
        gateway: {gw_address}
        control: auto
  - type: nameserver
    address: {NAME_SERVER_IP_ADDR}
  - type: nameserver
    address: {NAME_SERVER_IP_ADDR_2}
"""

        instance.config['cloud-init.network-config'] = network_config
        instance.save(wait=True)
        logger.info(f"IP address '{ip_address}' and gateway '{gw_address}' assigned to instance '{instance_name}'.")
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to set IP address for instance '{instance_name}': {e}")

def get_all_profiles(client):
    """Get all available profiles."""
    return [profile.name for profile in client.profiles.all()]

def create_instance(instance_name, image, remote, project, instance_type):
    """Create a new instance from an image on the specified remote and project, with specified type.
    
    Returns:    True if the instance was created successfully, False otherwise.
    """
    try:
        remote_client = get_remote_client(remote, project_name=project)  # Function to retrieve the remote client

        # Check if the project exists
        try:
            remote_client.projects.get(project)
            logger.info(f"Project '{project}' exists on remote '{remote}'.")
        except pylxd.exceptions.NotFound:
            logger.info(f"Project '{project}' does not exist on remote '{remote}'. Creating project.")
            if not create_project(remote_client, project):
                logger.error(f"Failed to create project '{project}' on remote '{remote}'.")
                return False

        # Check if the instance already exists
        try:
            existing_instance = remote_client.instances.get(instance_name)
            if existing_instance:
                logger.error(f"Instance '{instance_name}' already exists in project '{project}' on remote '{remote}'.")
                return False
        except pylxd.exceptions.LXDAPIException:
            # Instance does not exist, so proceed with creation
            pass

        # Split the image name to get the server address
        image_server, alias = image.split(':')

        logger.info(f"Creating instance '{instance_name}' of type '{instance_type}' on project '{project}' and remote '{remote}'.")
        logger.info(f"Using image '{alias}' from server '{image_server}'.")

        # Get the server address from the image name
        image_server_address, protocol = get_remote_address(image_server, get_protocol=True)  # Function to retrieve the image server address
        if protocol != "simplestreams":
            logger.error(f"Error: Image server '{image_server}' does not use the 'simplestreams' protocol.")
            return False

        # Create the instance configuration
        config = {
            'name': instance_name,
            'source': {
                'type': 'image',
                "mode": "pull",
                "server": image_server_address,
                "protocol": "simplestreams",
                'alias': alias
            },
            'devices': {
                'root': {
                    'type': 'disk',
                    'pool': 'default',  # Replace 'default' with the name of your storage pool if it's different
                    'path': '/'
                }
            }
        }

        if instance_type == "vm":
            config['type'] = "virtual-machine"

        instance = remote_client.instances.create(config, wait=True)
        logger.info(f"Instance '{instance_name}' created successfully.")
        return True

    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to create instance '{instance_name}': {e}")
        return False

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")
        return False

def delete_instance(instance_name, remote, project):
    """Delete a specific instance on the specified remote and project."""
    try:
        remote_client = get_remote_client(remote, project_name=project) # Function to retrieve the remote client

        # Check if the instance exists
        try:
            instance = remote_client.instances.get(instance_name)
        except pylxd.exceptions.LXDAPIException:
            logger.error(f"Instance '{instance_name}' not found in project '{project}' on remote '{remote}'.")
            return

        # Delete the instance
        instance.delete(wait=True)
        logger.info(f"Instance '{instance_name}' deleted successfully.")
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to delete instance '{instance_name}': {e}")
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}")

#############################################
###### figo gpu command functions ###########
#############################################

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

#############################################
###### figo profile command functions #######
#############################################

def dump_profile_to_file(profile, directory):
    """Helper function to write a profile to a .yaml file."""
    profile_data = {
        'name': profile.name,
        'description': profile.description,
        'config': profile.config,
        'devices': profile.devices
    }
    file_name = os.path.join(directory, f"{profile.name}.yaml")
    with open(file_name, 'w') as file:
        yaml.dump(profile_data, file)
    logger.info(f"Profile '{profile.name}' saved to '{file_name}'.")

def dump_profiles(client):
    """Dump all profiles into .yaml files."""
    profiles = client.profiles.all()
    directory = os.path.expanduser(PROFILE_DIR)
    
    if not os.path.exists(directory):
        os.makedirs(directory)
    
    for profile in profiles:
        dump_profile_to_file(profile, directory)

def dump_profile(client, profile_name):
    """Dump a specific profile into a .yaml file."""
    try:
        profile = client.profiles.get(profile_name)
        directory = os.path.expanduser(PROFILE_DIR)
        
        if not os.path.exists(directory):
            os.makedirs(directory)
        
        dump_profile_to_file(profile, directory)
    
    except pylxd.exceptions.NotFound:
        logger.error(f"Profile '{profile_name}' not found.")
        return

def list_profiles(client):
    """List all profiles and their associated instances."""
    profiles = client.profiles.all()

    print(f"{'PROFILE':<24}{'INSTANCES'}")

    for profile in profiles:
        instances = client.instances.all()
        associated_instances = [
            instance.name for instance in instances
            if profile.name in instance.profiles
        ]
        associated_instances_str = ', '.join(associated_instances) if associated_instances else 'None'
        print(f"{profile.name:<24}{associated_instances_str}")

#############################################
###### figo user command functions ##########
#############################################

def list_users(client, full=False):
    """List all installed certificates with optional full details, adding email, name, and org details with specified lengths."""

    certificates_info = []

    for certificate in client.certificates.all():
        name = certificate.name or "__N/A__"
        fingerprint = certificate.fingerprint[:12]

        # Fetch detailed information about the certificate using incus command
        result = subprocess.run(["incus", "config", "trust", "show", fingerprint], capture_output=True, text=True, check=True)
        user_cert_yaml = yaml.safe_load(result.stdout)  # Load the certificate configuration into a dictionary

        # Parse email, name, and organization from the description if available
        description = user_cert_yaml.get('description', '')
        description_parts = description.split(',') if description else ['', '', '']
        # Ensure that description_parts has exactly three elements
        description_parts += [''] * (3 - len(description_parts))  # Pad list to avoid index errors

        email = truncate(description_parts[0], 30)
        real_name = truncate(description_parts[1], 20)
        org = truncate(description_parts[2], 15)
        projects = ", ".join(certificate.projects) if certificate.projects else "None"
        admin_status = 'no' if certificate.restricted else 'yes'

        certificates_info.append({
            "name": name,
            "fingerprint": fingerprint,
            "type": certificate.type[:3],
            "admin": admin_status,
            "email": email,
            "real_name": real_name,
            "org": org,
            "projects": projects
        })

    # Sort certificates by name
    certificates_info.sort(key=lambda x: x["name"])

    # Print headers
    if full:
        print("{:<18} {:<12} {:<4} {:<5} {:<30} {:<20} {:<15} {:<20}".format(
            "NAME", "FINGERPRINT", "TYPE", "ADMIN", "EMAIL", "REAL NAME", "ORGANIZATION", "PROJECTS"
        ))
    else:
        print("{:<20} {:<12}".format("NAME", "FINGERPRINT"))

    # Print sorted certificates
    for cert in certificates_info:
        if full:
            print("{:<18} {:<12} {:<4} {:<5} {:<30} {:<20} {:<15} {:<20}".format(
                cert["name"], cert["fingerprint"], cert["type"], 
                cert["admin"], cert["email"], cert["real_name"], cert["org"], cert["projects"]
            ))
        else:
            print(f"{cert['name']:<20} {cert['fingerprint']:<12}")

def get_next_wg_client_ip_address():
    # List to contain the IP addresses found in .conf files
    ip_addresses = []

    directory = os.path.expanduser(USER_DIR)

    # Search for all .conf files in the directory folder
    for filename in os.listdir(directory):
        if filename.endswith('.conf'):
            with open(filename, 'r') as file:
                for line in file:
                    if line.startswith('Address ='):
                        ip_str = line.split('=')[1].strip().split('/')[0]
                        ip_addresses.append(ip_str)
                        break
    
    if not ip_addresses:
        # If no IP addresses are found, start from BASE_IP
        return BASE_IP
    
    # Convert IP addresses to ip_address objects and sort
    ip_addresses = sorted([ipaddress.ip_address(ip) for ip in ip_addresses])

    # Find the next available IP address
    last_ip = ip_addresses[-1]
    next_ip = last_ip + 1
    
    return str(next_ip)

def generate_wireguard_config(username, ip_address=None):
    # If no IP address is provided, generate a new one
    if not ip_address:
        ip_address = get_next_wg_client_ip_address()

    # Generate the private and public keys using wg
    private_key = subprocess.check_output(f"wg genkey | tee {username}.key", shell=True).decode('utf-8').strip()
    public_key = subprocess.check_output(f"wg pubkey < {username}.key", shell=True).decode('utf-8').strip()

    # WireGuard configuration template
    config_content = f"""[Interface]
PrivateKey = {private_key}
Address = {ip_address}/24

[Peer]
PublicKey = {PublicKey}
AllowedIPs = {AllowedIPs}
Endpoint = {Endpoint}
"""
    
    directory = os.path.expanduser(USER_DIR)

    # Writes the content to the username.conf file in the directory folder
    config_filename = os.path.join(directory, f"{username}.conf")
    
    with open(config_filename, 'w') as config_file:
        config_file.write(config_content)
    
    print(f"Generated WireGuard configuration: {config_filename}")

def add_friendly_name(pfx_file, friendly_name, password=None):
    """Add a friendlyName attribute to the existing PFX file, overwriting the original."""
    temp_pem_file = "temp.pem"
    temp_pfx_file = "temp_with_friendlyname.pfx"

    # Convert the existing PFX to PEM format
    openssl_cmd = [
        "openssl", "pkcs12", "-in", pfx_file, "-out", temp_pem_file, "-nodes"
    ]
    if password:
        openssl_cmd.extend(["-password", f"pass:{password}"])
    
    subprocess.run(openssl_cmd, check=True)

    # Prepare the command to create the new PFX file with friendlyName
    openssl_cmd = [
        "openssl", "pkcs12", "-export", "-in", temp_pem_file, "-out", temp_pfx_file,
        "-name", friendly_name
    ]
    if password:
        openssl_cmd.extend(["-passin", f"pass:{password}", "-passout", f"pass:{password}"])
    else:
        openssl_cmd.extend(["-passout", "pass:"])

    subprocess.run(openssl_cmd, check=True)

    # Replace the original PFX file with the new one
    subprocess.run(["mv", temp_pfx_file, pfx_file])

    # Clean up temporary files
    subprocess.run(["rm", temp_pem_file])

    logger.info(f"PFX file with friendlyName updated: {pfx_file}")

def generate_key_pair(user_name, crt_file, key_file, pfx_file, pfx_password=None):
    """Generate key pair (CRT and PFX files) for the user.

    Parameters:
    - user_name: Name of the user
    - crt_file: Path to the certificate file
    - key_file: Path to the private key file (PEM format) temporary file
    - pfx_file: Path to the PFX file
    - pfx_password: Password for the PFX file (optional)

    Returns:
    - True if the key pair was generated successfully, False otherwise
    """

    try:
        # Generate private key
        private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=cryptography.hazmat.backends.default_backend()
        )

        # Generate a self-signed certificate with detailed subject and issuer information
        subject = issuer = cryptography.x509.Name([
            cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COUNTRY_NAME, u"IT"),
            cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.STATE_OR_PROVINCE_NAME, u"RM"),
            cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.ORGANIZATION_NAME, u"Restart"),
            cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, f"{FIGO_PREFIX}{user_name}")  # Add the user_name as the Common Name (CN)
        ])

        # Set the certificate validity to 2 years
        certificate = cryptography.x509.CertificateBuilder() \
            .subject_name(subject) \
            .issuer_name(issuer) \
            .public_key(private_key.public_key()) \
            .serial_number(cryptography.x509.random_serial_number()) \
            .not_valid_before(datetime.datetime.utcnow()) \
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=2*365)) \
            .sign(private_key, cryptography.hazmat.primitives.hashes.SHA256(), cryptography.hazmat.backends.default_backend())

        # Write the private key to a file
        try:
            with open(key_file, "wb") as key_out:
                key_out.write(private_key.private_bytes(
                    cryptography.hazmat.primitives.serialization.Encoding.PEM,
                    cryptography.hazmat.primitives.serialization.PrivateFormat.TraditionalOpenSSL,
                    cryptography.hazmat.primitives.serialization.NoEncryption()
                ))
        except IOError as e:
            logger.error(f"Failed to write private key to {key_file}: {e}")
            return False

        # Write the certificate to a file
        try:
            with open(crt_file, "wb") as crt:
                crt.write(certificate.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM))
        except IOError as e:
            logger.error(f"Failed to write certificate to {crt_file}: {e}")
            return False

        # Use OpenSSL to create the PFX file with specific settings
        openssl_cmd = [
            "openssl", "pkcs12", "-export",
            "-out", pfx_file,
            "-inkey", key_file,
            "-in", crt_file,
            "-certpbe", "PBE-SHA1-3DES",  # Use SHA1 and 3DES for encryption
            "-keypbe", "PBE-SHA1-3DES",   # Use SHA1 and 3DES for the key
            "-macalg", "sha1",             # Use SHA1 for MAC
            "-iter", "2048"                # Set iteration count to 2048
        ]

        if pfx_password:
            openssl_cmd.extend(["-passout", f"pass:{pfx_password}"])

        try:
            subprocess.run(openssl_cmd, check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"OpenSSL command failed: {e}")
            return False
        except FileNotFoundError:
            logger.error("OpenSSL is not installed or not found in the system's PATH.")
            return False

        # Delete the key file
        try:
            subprocess.run(["rm", key_file], check=True)
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to delete key file {key_file}: {e}")
            return False

        # Add a friendly name to the PFX file
        try:
            add_friendly_name(pfx_file, f"{FIGO_PREFIX}{user_name}", password=pfx_password)
        except Exception as e:
            logger.error(f"Failed to add a friendly name to the PFX file {pfx_file}: {e}")
            return False

        logger.info(f"PFX file generated: {pfx_file}")
        return True

    except Exception as e:
        logger.error(f"An error occurred while generating the key pair: {e}")
        return False

def create_project(client, project_name):
    try:
        # Explicitly define the project details as a dictionary
        project_data = {
            "name": project_name,  # The project's name (string)
            "description": f"Project for user {project_name}",  # Optional description
            "config": {}  # Empty configuration for now
        }

        # Creating the project using the correct format
        client.api.projects.post(json=project_data)
        logger.info(f"Project '{project_name}' created successfully.")
        return True

    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Error creating project '{project_name}': {str(e)}")
        return False
    except Exception as e:
        logger.error(f"Unexpected error during creation of project: '{project_name}': {str(e)}")
        return False

def edit_certificate_description(client, user_name, email=None, name=None, org=None):
    """Edit the description of a certificate in Incus by the user name.

    Args:
    - user_name: The username associated with the certificate.
    - email: Email address of the user.
    - name: Name of the user.
    - org: Organization of the user.

    Returns:
    True if the description was successfully added, False otherwise.
    """

    if email==None and name==None and org==None:
        logger.info("Warning: certificate description not changed.")
        return True
    
    try:
        # Step 1: Retrieve the certificate by username
        certificates = client.certificates.all()
        user_cert = None
        for cert in certificates:
            if cert.name == user_name:
                user_cert = cert
                break
        
        if not user_cert:
            logger.error(f"User '{user_name}' not found.")
            return
        
        fingerprint = user_cert.fingerprint[:24]

        # Step 2: load the user_cert into a temporary .YAML object using incus config trust show
        result = subprocess.run(["incus", "config", "trust", "show", fingerprint], capture_output=True, text=True, check=True)
        user_cert_yaml = yaml.safe_load(result.stdout)   # Load the certificate configuration into a dictionary
        
        if not user_cert_yaml:
            logger.error(f"Failed to load certificate configuration for '{user_name}'.")
            return False
        
        if "description" not in user_cert_yaml:
            user_cert_yaml["description"] = ""

        original_description = user_cert_yaml["description"] # Get the original description
        target_email = ''
        target_name = ''
        target_org = ''
        if original_description == "":
            pass
        else:
            target_email, target_name, target_org = original_description.split(",")

        if email!=None:
            target_email = email
        if name!=None:
            target_name = name
        if org!=None:
            target_org = org

        # Format the description with the additional user details
        description = f"{target_email},{target_name},{target_org}"  # Format: email,name,org

        if description == ",,":
            description = ""

        user_cert_yaml["description"] = description  # Update the description

        # Step 3: Save the updated configuration to a temporary file
        temp_file = f"/tmp/{user_name}.yaml"
        with open(temp_file, "w") as f:
            yaml.dump(user_cert_yaml, f)
        
        # Step 4: Update the certificate configuration using incus config trust edit
        # The command is: cat temp_file | incus config trust edit fingerprint

        cat_process = subprocess.Popen(
            ['cat', temp_file], 
            stdout=subprocess.PIPE  # Redirect the output to a pipe
        )

        # Create a subprocess to run 'incus config trust edit fingerprint'
        # using the output of the first command as input
        incus_process = subprocess.Popen(
            ['incus', 'config', 'trust', 'edit', fingerprint], 
            stdin=cat_process.stdout,  # Use output of cat as input
            stdout=subprocess.PIPE  # Redirect the output to a pipe if needed
        )

        # Close the output of the first process to allow it to receive a SIGPIPE if the second exits
        cat_process.stdout.close()

        # Get the output of the second command if needed
        output, error = incus_process.communicate()

        if incus_process.returncode != 0:
            logger.error("Error in executing incus command:", error)
            return False

        logger.info(f"Description added to certificate '{user_name}'.")

        # Step 5: Remove the temporary file
        os.remove(temp_file)
        return True

    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to edit certificate description: {e.stderr.strip()}")
        return False
    
    except Exception as e:
        logger.error(f"Unexpected error while editing description: {e}")
        return False

def add_certificate_to_incus(client, user_name, crt_file, project_name, admin=False, email=None, name=None, org=None):
    """Add user certificate to Incus
    
    If the user is an admin, the certificate is added without any restrictions.
    If the user is not an admin, the certificate is restricted to the specified project.

    Args:
    - user_name: The username associated with the certificate.
    - crt_file: Path to the certificate file.
    - project_name: Name of the project to restrict the certificate to.
    - admin: Specifies if the user has admin privileges.
    - email: Email address of the user.
    - name: Name of the user.
    - org: Organization of the user.

    Returns:
    True if the certificate is added successfully, False otherwise.
    """
    try:
        command = [
            "incus", "config", "trust", "add-certificate", crt_file, 
            f"--name={user_name}"
        ]

        if not admin:
            command.extend([
                "--restricted", 
                f"--projects={project_name}"
            ])

        # Execute the command
        subprocess.run(command, capture_output=True, text=True, check=True)
        logger.info(f"Certificate '{user_name}' added to Incus.")

        # Edit the certificate's description if needed
        if email!=None or name!=None or org!=None:
            logger.info(f"Adding description to certificate '{user_name}'")
            if not edit_certificate_description(client, user_name, email, name, org):
                logger.error(f"Failed to add description to certificate '{user_name}'.")
                return False

        return True

    except subprocess.CalledProcessError as e:
        # Print the exact error message from the command's stderr
        logger.error(f"Failed to add certificate to Incus: {e.stderr.strip()}")
        return False

    except Exception as e:
        logger.error(f"Unexpected error while adding certificate: {e}")
        return False

def delete_project(remote_node, project_name):
    """
    Delete a project on a specific remote node (can also be local:)

    Parameters:
    - remote_client: pylxd.Client instance connected to the remote node (can also be local:)
    - remote_node: Name of the remote node where the project is located
    - project_name: Name of the project to delete
    """
    remote_client = get_remote_client(remote_node, project_name=project_name)

    try:
        # Retrieve the project from the remote node
        project = remote_client.projects.get(project_name)
        
        # Delete the project
        project.delete()
        logger.info(f"Deleted project '{project_name}' on remote '{remote_node}'")

    except pylxd.exceptions.NotFound:
        logger.error(f"Project '{project_name}' not found on the remote node. No action taken.")
        
    except pylxd.exceptions.LXDAPIException as e:
        logger.error(f"Failed to delete project '{project_name}' on remote '{remote_node}: {e}")
    
    except Exception as e:
        logger.error(f"Unexpected error while deleting project '{project_name}' on remote '{remote_node}: {e}")

def add_user(user_name, cert_file, client, admin=False, wireguard=False, project=None, email=None, name=None, org=None):
    """
    Add a user to Incus with a certificate.

    Args:
    - user_name (str): The username associated with the certificate.
    - cert_file (str): The certificate file (in .crt format) or None if generating a new key pair.
    - client (object): Client instance for interacting with Incus.
    - admin (bool, optional): Specifies if the user has admin privileges.
    - wireguard (bool, optional): Specifies if WireGuard config for the user has to be generated.
    - project (str, optional): Name of the project to restrict the certificate to.
      if not provided, a project will be created with the name 'figo-<user_name>'.
    - email (str, optional): Email address of the user.
    - name (str, optional): Name of the user.
    - org (str, optional): Organization of the user.

    Returns:
    True if the user is added successfully, False otherwise.
    """

    global PROJECT_PREFIX  # Declare the use of the global variable

    # Check if user already exists in the certificates
    for cert in client.certificates.all():
        if cert.name == user_name:
            logger.error(f"Error: User '{user_name}' already exists.")
            return False

    # Initialize the project name
    project_name = project if project else f"{PROJECT_PREFIX}{user_name}"

    set_of_errored_remotes = set()
    if not project:
        # Retrieve the list of remote servers and check project existence on each
        remotes = get_incus_remotes()
        for remote_node in remotes:
            # Skipping remote node with protocol simplestreams
            if remotes[remote_node]["Protocol"] == "simplestreams":
                continue

            projects = get_projects(remote_node=remote_node)
            if projects is None:
                set_of_errored_remotes.add(remote_node)
                continue

            else: # projects is not None:
                if project_name in [myproject['name'] for myproject in projects]:
                    logger.error(f"Error: Project '{project_name}' already exists on remote '{remote_node}'.")
                    return False
    else:
        # Check if the provided project exists on the local server
        projects = get_projects(remote_node="local")
        if projects is None:
            logger.error(f"Error: Failed to retrieve projects from the local server.")
            return False
        
        if projects is not None:
            if project not in [myproject['name'] for myproject in projects]:
                logger.error(f"Error: Project '{project}' not found on the local server.")
                return False
    
    if set_of_errored_remotes:
        logger.warning(f"Failed to retrieve projects from the following remote nodes: {', '.join(set_of_errored_remotes)}")

    directory = os.path.expanduser(USER_DIR)
    # Ensure the directory exists
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Determine whether to use the provided certificate or generate a new key pair
    if cert_file:
        # If a certificate file is provided, use it
        # the certificate file is in the folder USER_DIR
        # the certificate file should be named as user_name.crt
        # get the certificate file path
        crt_file = os.path.join(directory, cert_file)
        if not os.path.exists(crt_file):
            logger.error(f"Error: Certificate file '{crt_file}' not found.")
            return False
        logger.info(f"Using provided certificate: {crt_file}")

    else:
        # Generate key pair and certificate
        crt_file = os.path.join(directory, f"{user_name}.crt")
        pfx_file = os.path.join(directory, f"{user_name}.pfx")
        key_file = os.path.join(directory, f"{user_name}.key")
        if not generate_key_pair(user_name, crt_file, key_file, pfx_file):
            logger.error(f"Failed to generate key pair and certificate for user: {user_name}") 
            return False
        logger.info(f"Generated certificate and key pair for user: {user_name}")

    # Create project for the user
    project_created = False
    if not admin and project==None:
        project_created = create_project(client, project_name)

    if not project_created:
        logger.error(f"Error: Failed to create project '{project_name}', no certificate added.")
        return False

    # Add the user certificate to Incus
    certificate_added = add_certificate_to_incus(client, user_name, crt_file, project_name, admin=admin, email=email, name=name, org=org)

    if not admin and project==None and not certificate_added:
        delete_project(client, 'local', project_name)
        return False
    
    if wireguard:
        generate_wireguard_config(user_name)

    return True

def grant_user_access(username, projectname, client):
    try:
        # Step 1: Retrieve the certificate by username
        certificates = client.certificates.all()
        user_cert = None
        for cert in certificates:
            if cert.name == username:
                user_cert = cert
                break
        
        if not user_cert:
            logger.error(f"User '{username}' not found.")
            return

        # Step 3: Fetch the user's configuration
        try:
            # Assuming the 'projects' attribute exists on 'user_cert'
            projects = user_cert.projects or []  # Get current projects or initialize an empty list
            
            # Step 4: Modify the user's configuration to add the project
            if projectname not in projects:
                projects.append(projectname)
                user_cert.projects = projects

                # Step 5: Save the updated user configuration
                user_cert.save()  # Save the updated configuration
                logger.info(f"User '{username}' has been granted access to project '{projectname}'.")
            else:
                logger.info(f"User '{username}' already has access to project '{projectname}'.")
        except Exception as e:
            logger.error(f"Error updating user configuration: {e}")
            return

    except Exception as e:
        logger.error(f"Error retrieving certificate for user '{username}': {e}")

def edit_user(username, client, email=None, name=None, org=None):
    """
    Edit user's certificate description in Incus.

    Args:
    - username (str): The username associated with the certificate.
    - client (object): Client instance for interacting with Incus.
    - email (str, optional): The new email address for the user.
    - name (str, optional): The new full name for the user.
    - org (str, optional): The new organization for the user.

    Returns:
    - bool: True if the edit was successful, False otherwise.
    """

    # Update the description using the edit_certificate_description function
    if not edit_certificate_description(client, username, email, name, org):
        logger.error(f"Failed to update description for user '{username}'.")
        return False

    logger.info(f"Updated description for user '{username}' successfully.")
    return True

def get_certificate_path(remote_node):
    """
    Retrieve the path to the self-signed certificate for the specified remote node.
    """
    return os.path.join(CERTIFICATE_DIR, f"{remote_node}.crt")

def get_remote_address(remote_node, get_protocol=False):
    """Retrieve the address of the remote node."""

    remotes = get_incus_remotes()
    remote_info = remotes.get(remote_node, None)
    if remote_info and "Addr" in remote_info:
        if get_protocol:
            if "Protocol" in remote_info:
                return remote_info["Addr"], remote_info["Protocol"]
            else:
                raise ValueError(f"Error: Protocol not found for remote node '{remote_node}'") 
        else:
            return remote_info["Addr"]
    else:
        raise ValueError(f"Error: Address not found for remote node '{remote_node}'")

def list_instances_in_project(remote_node, project_name):
    """List instances associated with a project on a specific remote node."""
    
    remote_client = get_remote_client(remote_node, project_name=project_name)

    # List all instances in the remote node in the given project
    instances = remote_client.instances.all()

    # Filter instances by the project name
    instances_in_project = [
        instance.name for instance in instances if instance.config.get("volatile.project") == project_name
    ]
    return instances_in_project

def list_profiles_in_project(remote_node, project_name):
    """List profiles associated with a project on a specific remote node."""

    remote_client = get_remote_client(remote_node, project_name=project_name)

    profiles_in_project = []

    # Retrieve all profiles on the remote node
    profiles = remote_client.profiles.all()

    for profile in profiles:
        # Check if the profile is associated with the project
        if profile.config.get("volatile.project") == project_name:
            profiles_in_project.append(profile.name)

    return profiles_in_project

def list_storage_volumes_in_project(remote_node, project_name):
    """List storage volumes associated with a project on a specific remote node."""

    remote_client = get_remote_client(remote_node, project_name=project_name)

    storage_volumes_in_project = []

    # Iterate over all storage pools on the remote client
    for pool in remote_client.storage_pools.all():
        try:
            # Retrieve all volumes in the storage pool
            volumes = pool.volumes.all()
        except pylxd.exceptions.NotFound:
            # Handle the case where no volumes are found in the pool
            logger.error(f"No volumes found in storage pool '{pool.name}'.")
            continue

        # Filter volumes by project name in their configuration
        for volume in volumes:
            if volume.config.get("volatile.project") == project_name:
                storage_volumes_in_project.append(volume.name)

    return storage_volumes_in_project

def delete_user(user_name, client, purge=False, removefiles=False):
    """
    Delete a user from the system.

    Parameters:
    - username: Username of the user to delete
    - client: pylxd.Client instance
    - purge: If True, delete associated projects even if the user does not exist
    - removefiles: If True, remove files associated with the user in the USER_DIR
    """

    global PROJECT_PREFIX  # Declare the use of the global variable

    # Construct the project name associated with the user
    project_name = f"{PROJECT_PREFIX}{user_name}"

    # Check if the user exists in the certificates
    cert_exists = False
    for cert in client.certificates.all():
        if cert.name == user_name:
            cert_exists = True
            # Remove the user's certificate
            cert.delete()
            logger.info(f"Certificate for user '{user_name}' has been removed.")
            break

    if not cert_exists:
        if purge:
            logger.info(f"Warning: User '{user_name}' does not exist.")
        else:
            logger.info(f"User '{user_name}' does not exist. No action taken.")
            return

    # Remove the user's files if the flag is set
    if removefiles:
        directory = os.path.expanduser(USER_DIR)
        user_files = [f"{user_name}.crt", f"{user_name}.pfx", f"{user_name}.pub"]
        for file in user_files:
            file_path = os.path.join(directory, file)
            if os.path.exists(file_path):
                os.remove(file_path)
                logger.info(f"File '{file}' has been removed.")

    # Retrieve the list of remote servers
    remotes = get_incus_remotes()

    set_of_errored_remotes = set()
    project_found = False
    for remote_node in remotes:
        # Skipping remote node with protocol simplestreams
        if remotes[remote_node]["Protocol"] == "simplestreams":
            continue

        # Check if the project exists on the remote node
        projects = get_projects(remote_node=remote_node)
        if projects is None:
            set_of_errored_remotes.add(remote_node)
            continue
        else: #if projects is not None:
            if project_name in [project['name'] for project in projects]:
                project_found = True

                #remote_client = get_remote_client(remote_node, remotes)

                # Check if there are any instances in the project
                instances = list_instances_in_project(remote_node, project_name)
                # Check if there are any profiles in the project
                profiles = list_profiles_in_project(remote_node, project_name)
                # Check if there are any storage volumes in the project
                #TODO: Implement this function
                storage_volumes = None
                #storage_volumes = list_storage_volumes_in_project(remote_node, project_name)

                # Warn if the project is not empty
                if instances or profiles or storage_volumes:
                    logger.info(f"Warning: Project '{project_name}' on remote '{remote_node}' is not empty.")
                    if instances:
                        logger.info(f"  - Contains {len(instances)} instance(s)")
                    if profiles:
                        logger.info(f"  - Contains {len(profiles)} profile(s)")
                    if storage_volumes:
                        logger.info(f"  - Contains {len(storage_volumes)} storage volume(s)")
                else:
                    # Delete the empty project
                    #TODO
                    delete_project(remote_node, project_name)
                    logger.info(f"Project '{project_name}' on remote '{remote_node}' has been deleted.")

    if set_of_errored_remotes:
        logger.warning(f"Failed to retrieve projects from the following remote nodes: {', '.join(set_of_errored_remotes)}")

    if not project_found:
        logger.error(f"No associated project '{project_name}' found for user '{user_name}' on any remote.")
    else:
        logger.info(f"User '{user_name}' has been deleted successfully.")

#############################################
###### figo remote command functions ########
#############################################

def list_remotes(client, full=False):
    """Lists the available Incus remotes and their addresses."""
    try:
        remotes = get_incus_remotes()
    except RuntimeError as e:
        logger.error(f"Error: {e}")
        return
    except ValueError as e:
        logger.error(f"Error: {e}")
        return
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return

    if full:
        for remote_name, remote_info in remotes.items():
            print(f"REMOTE NAME: {remote_name}")
            for key, value in remote_info.items():
                print(f"  {key}: {value}")
            print("-" * 60)
    else:
        print("{:<20} {:<40}".format("REMOTE NAME", "ADDRESS"))
        for remote_name, remote_info in remotes.items():
            print("{:<20} {:<40}".format(remote_name, remote_info['Addr']))

def resolve_hostname(hostname):
    """Resolve the hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return None
    

def enroll_remote(remote_server, ip_address_port, cert_filename="~/.config/incus/client.crt",
           user="ubuntu", loc_name="main"):
    """Enroll a remote server by transferring the client certificate and adding it to the remote Incus daemon.
    
    Before enrolling the remote server, the public key of the local incus user needs to be added 
    to the remote server's authorized_keys file.
    """
    ip_address, port = (ip_address_port.split(":") + ["8443"])[:2]

    if not is_valid_ip(ip_address):
        resolved_ip = resolve_hostname(ip_address)
        if resolved_ip:
            ip_address = resolved_ip
        else:
            logger.error(f"Invalid IP address or hostname: {ip_address}")
            return

    cert_filename = os.path.expanduser(cert_filename)
    remote_cert_path = f"{user}@{ip_address}:~/figo/certs/{loc_name}.crt"

    try:
        # Check if the certificate already exists on the remote server
        check_cmd = f"ssh {user}@{ip_address} '[ -f ~/figo/certs/{loc_name}.crt ]'"
        result = subprocess.run(check_cmd, shell=True)

        if result.returncode == 0:
            logger.info(f"Warning: Certificate {loc_name}.crt already exists on {ip_address}.")
        else:
            # Ensure the destination directory exists
            subprocess.run(
                ["ssh", f"{user}@{ip_address}", "mkdir -p ~/figo/certs"],
                check=True
            )

            # Transfer the certificate to the remote server
            subprocess.run(
                ["scp", cert_filename, remote_cert_path],
                check=True
            )
            logger.info(f"Certificate {cert_filename} successfully transferred to {ip_address}.")

            # Add the certificate to the Incus daemon on the remote server
            try:
                add_cert_cmd = (
                    f"incus config trust add-certificate --name incus_{loc_name} ~/figo/certs/{loc_name}.crt"
                )
                subprocess.run(
                    ["ssh", f"{user}@{ip_address}", add_cert_cmd],
                    check=True
                )
                logger.info(f"Certificate incus_{loc_name}.crt added to Incus on {ip_address}.")
            except subprocess.CalledProcessError as e:
                if "already exists" in str(e):
                    logger.info(f"Warning: Certificate incus_{loc_name} already added to Incus on {ip_address}.")
                else:
                    logger.error(f"An error occurred while adding the certificate to Incus: {e}")
                    return

    except subprocess.CalledProcessError as e:
        logger.error(f"An error occurred while processing the certificate: {e}")
        return

    # Check if the remote server already exists
    try:
        remotes = get_incus_remotes()
        if remote_server in remotes:
            logger.info(f"Warning: Remote server {remote_server} is already configured.")
        else:
            # Add the remote server to the client configuration
            subprocess.run(
                ["incus", "remote", "add", remote_server, f"https://{ip_address}:{port}", "--accept-certificate"],
                check=True
            )
            logger.info(f"Remote server {remote_server} added to client configuration.")
    except subprocess.CalledProcessError as e:
        logger.error(f"An error occurred while adding the remote server to the client configuration: {e}")


#############################################
######### Command Line Interface (CLI) ######
#############################################

#############################################
###### figo instance command CLI ############
#############################################

def create_instance_parser(subparsers):
    instance_parser = subparsers.add_parser("instance", help="Manage instances")
    instance_subparsers = instance_parser.add_subparsers(dest="instance_command")

    # Add common options for remote and project to a function to avoid repetition
    def add_common_arguments(parser):
        parser.add_argument("-r", "--remote", help="Specify the remote server name")
        parser.add_argument("-p", "--project", help="Specify the project name")

    instance_list_parser = instance_subparsers.add_parser("list", aliases=["l"],
        help="List instances (use -f or --full for more details)"
    )
    instance_list_parser.add_argument("-f", "--full", action="store_true", help="Show full details of instance profiles")
    instance_list_parser.add_argument("scope", nargs="?", help="Scope in the format 'remote:project', 'project', or 'remote:' to limit the listing")
    add_common_arguments(instance_list_parser)

    start_parser = instance_subparsers.add_parser("start", help="Start a specific instance")
    start_parser.add_argument("instance_name", help="Name of the instance to start. Can include remote and project scope.")
    add_common_arguments(start_parser)

    stop_parser = instance_subparsers.add_parser("stop", help="Stop a specific instance")
    stop_parser.add_argument("instance_name", help="Name of the instance to stop. Can include remote and project scope.")
    add_common_arguments(stop_parser)

    set_key_parser = instance_subparsers.add_parser("set_key", help="Set a public key for a user in an instance")
    set_key_parser.add_argument("instance_name", help="Name of the instance. Can include remote and project scope.")
    set_key_parser.add_argument("key_filename", help="Filename of the public key on the host")
    add_common_arguments(set_key_parser)

    set_ip_parser = instance_subparsers.add_parser("set_ip", help="Set a static IP address and gateway for a stopped instance")
    set_ip_parser.add_argument("instance_name", help="Name of the instance to set the IP address for. Can include remote and project scope.")
    set_ip_parser.add_argument("ip_address", help="Static IP address to assign to the instance")
    set_ip_parser.add_argument("gw_address", help="Gateway address to assign to the instance")
    add_common_arguments(set_ip_parser)

    create_parser = instance_subparsers.add_parser("create", aliases=["c"], help="Create a new instance")
    create_parser.add_argument("instance_name", help="Name of the new instance. Can include remote and project scope in the format 'remote:project.instance_name'")
    create_parser.add_argument("image", help="Image source to create the instance from. Format: 'remote:image' or 'image'.")
    create_parser.add_argument("-t", "--type", choices=["vm", "container", "cnt"], default="container", help="Specify the instance type: 'vm', 'container', or 'cnt' (default: 'container').")
    create_parser.add_argument("-u", "--user", help="Specify the user who will own the instance")
    add_common_arguments(create_parser)

    delete_parser = instance_subparsers.add_parser("delete", aliases=["del", "d"], help="Delete a specific instance")
    delete_parser.add_argument("instance_name", help="Name of the instance to delete. Can include remote and project scope.")
    add_common_arguments(delete_parser)

    subparsers._name_parser_map["in"] = instance_parser
    subparsers._name_parser_map["i"] = instance_parser

    return instance_parser

def handle_instance_list(args):
    remote_node = args.remote
    project_name = args.project

    if args.scope:
        if ":" in args.scope:
            remote_scope, project_scope = args.scope.split(":", 1)
            if project_scope == "":
                project_scope = None

            if args.remote and args.remote != remote_scope:
                logger.error(f"Error: Conflict between scope remote '{remote_scope}' and provided remote '{args.remote}'.")
                return
            if args.project and project_scope and args.project != project_scope:
                logger.error(f"Error: Conflict between scope project '{project_scope}' and provided project '{args.project}'.")
                return

            remote_node = remote_scope
            project_name = project_scope if project_scope else args.project
        else:
            project_scope = args.scope

            if args.project and args.project != project_scope:
                logger.error(f"Error: Conflict between scope project '{project_scope}' and provided project '{args.project}'.")
                return

            project_name = project_scope

    if args.full:
        print_profiles(remote_node, project_name=project_name, full=True)
    else:
        print_profiles(remote_node, project_name=project_name, full=False)

def handle_instance_command(args, parser_dict):
    if not args.instance_command:
        parser_dict['instance_parser'].print_help()
        return

    def check_instance_name(instance_name):
        """Check validity of instance name."""
        # Instance name can only contain letters, numbers, hyphens, no underscores
        if not re.match(r'^[a-zA-Z0-9-]+$', instance_name):
            return False
        return True

    # Function to handle parsing of remote and project from the instance name and arguments
    def parse_instance_scope(instance_name, provided_remote, provided_project):
        remote, project, instance = '', '', instance_name  # Default values

        if ':' in instance_name:
            parts = instance_name.split(':')
            if len(parts) == 2:
                if '.' in parts[1]:
                    remote, project_instance = parts
                    parts_pro_inst = project_instance.split('.')
                    if len(parts_pro_inst) == 2:
                        project, instance = parts_pro_inst
                    else:
                        logger.error(f"Syntax error in instance name '{instance_name}'.")
                        return None, None, None
                else:
                    remote, instance = parts
            else:
                logger.error(f"Syntax error in instance name '{instance_name}'.")
                return None, None, None
        elif '.' in instance_name:
            parts_pro_inst = instance_name.split('.')
            if len(parts_pro_inst) == 2:
                project, instance = parts_pro_inst
            else:
                logger.error(f"Syntax error in instance name '{instance_name}'.")
                return None, None, None

        if not check_instance_name(instance):
            logger.error(f"Error: Instance name can only contain letters, numbers, hyphens: '{instance_name}'.")
            return None, None, None

        # Resolve conflicts
        if provided_remote and remote != '' and provided_remote != remote:
            logger.error(f"Error: Conflict between scope remote '{remote}' and provided remote '{provided_remote}'.")
            return None, None, None
        if provided_project and project != '' and provided_project != project:
            logger.error(f"Error: Conflict between scope project '{project}' and provided project '{provided_project}'.")
            return None, None, None

        # Use provided flags if there's no conflict and they are provided
        remote = provided_remote if provided_remote else remote
        project = provided_project if provided_project else project

        if remote == '':
            remote = 'local'

        if project == '':
            project = 'default'

        return remote, project, instance

    def parse_image(image_name):
        if ':' in image_name:
            parts = image_name.split(':')
            if len(parts) == 2:
                return image_name
            else:
                logger.error(f"Syntax error in image name '{image_name}'.")
                return None
        else:
            return f"images:{image_name}"

    # Handle the user parameter logic
    def derive_project_from_user(user_name):
        return f"{PROJECT_PREFIX}{user_name}"

    # Check the command type and handle appropriately
    if args.instance_command in ["list", "l"]:
        handle_instance_list(args)
    else:
        # Handle project based on user if provided
        user_project = None
        if 'user' in args:
            user_project = derive_project_from_user(args.user) if args.user else None

        # If user_project is set, check for conflicts
        if user_project:
            if args.project and user_project != args.project:
                logger.error(f"Error: Conflict between derived project '{user_project}' from user '{args.user}'"
                             f" and provided project '{args.project}'.")
                return
            else:
                args.project = user_project  # Use the derived project

        remote, project, instance = parse_instance_scope(args.instance_name, args.remote, args.project)
        if remote is None or project is None:
            return  # Error already printed by parse_instance_scope

        if args.instance_command == "start":
            start_instance(instance, remote, project)
        elif args.instance_command == "stop":
            stop_instance(instance, remote, project)
        elif args.instance_command == "set_key":
            set_user_key(instance, remote, project, args.key_filename)
        elif args.instance_command == "set_ip":
            set_ip(instance, remote, project, args.ip_address, args.gw_address)
        elif args.instance_command in ["create", "c"]:
            image = parse_image(args.image)
            if image is None:
                return  # Error already printed by parse_image

            # Determine instance type
            instance_type = args.type
            if instance_type == "cnt":
                instance_type = "container"  # Convert 'cnt' to 'container'

            create_instance(instance, image, remote, project, instance_type)
        elif args.instance_command in ["delete", "del", "d"]:
            delete_instance(instance, remote, project)

#############################################
###### figo gpu command CLI #################
#############################################

def create_gpu_parser(subparsers):
    gpu_parser = subparsers.add_parser("gpu", help="Manage GPUs")
    gpu_subparsers = gpu_parser.add_subparsers(dest="gpu_command")

    gpu_subparsers.add_parser("status", help="Show GPU status")
    gpu_subparsers.add_parser("list", aliases=["l"], help="List GPU profiles")
    add_gpu_parser = gpu_subparsers.add_parser("add", help="Add a GPU profile to a specific instance")
    add_gpu_parser.add_argument("instance_name", help="Name of the instance to add a GPU profile to")
    remove_gpu_parser = gpu_subparsers.add_parser("remove", help="Remove GPU profiles from a specific instance")
    remove_gpu_parser.add_argument("instance_name", help="Name of the instance to remove a GPU profile from")
    remove_gpu_parser.add_argument("--all", action="store_true", help="Remove all GPU profiles from the instance")

    subparsers._name_parser_map["gp"] = gpu_parser
    subparsers._name_parser_map["g"] = gpu_parser

    return gpu_parser

def handle_gpu_command(args, client, parser_dict):
    if not args.gpu_command:
        parser_dict['gpu_parser'].print_help()
    elif args.gpu_command == "status":
        show_gpu_status(client)
    elif args.gpu_command in ["list", "l"]:
        list_gpu_profiles(client)
    elif args.gpu_command == "add":
        add_gpu_profile(args.instance_name, client)
    elif args.gpu_command == "remove":
        if args.all:
            remove_gpu_all_profiles(args.instance_name, client)
        else:
            remove_gpu_profile(args.instance_name, client)

#############################################
###### figo profile command CLI #############
#############################################

def create_profile_parser(subparsers):
    profile_parser = subparsers.add_parser("profile", help="Manage profiles")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")

    dump_profiles_parser = profile_subparsers.add_parser("dump", help="Dump profiles to .yaml files")
    dump_profiles_parser.add_argument("-a", "--all", action="store_true", help="Dump all profiles to .yaml files")
    dump_profiles_parser.add_argument("profile_name", nargs="?", help="Name of the profile to dump")

    profile_subparsers.add_parser("list", aliases=["l"], help="List profiles and associated instances")

    subparsers._name_parser_map["pr"] = profile_parser
    subparsers._name_parser_map["p"] = profile_parser

    return profile_parser

def handle_profile_command(args, client, parser_dict):
    if not args.profile_command:
        parser_dict['profile_parser'].print_help()
    elif args.profile_command == "dump":
        if args.all:
            dump_profiles(client)
        elif args.profile_name:
            dump_profile(client, args.profile_name)
        else:
            logger.error("You must provide a profile name or use the --all option.")
    elif args.profile_command in ["list", "l"]:
        list_profiles(client)

#############################################
###### figo user command CLI ################
#############################################

class NoCommaCheck(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if ',' in values:
            parser.error(f"The {option_string} argument cannot contain commas.")
        else:
            setattr(namespace, self.dest, values)

class NoUnderscoreCheck(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        if '_' in values:
            parser.error(f"The {self.dest} argument cannot contain underscore.")
        else:
            setattr(namespace, self.dest, values)

def create_user_parser(subparsers):
    user_parser = subparsers.add_parser("user", help="Manage users")
    user_subparsers = user_parser.add_subparsers(dest="user_command")

    # List subcommand
    user_list_parser = user_subparsers.add_parser("list", aliases=["l"], help="List installed certificates (use -f or --full for more details)")
    user_list_parser.add_argument("-f", "--full", action="store_true", help="Show full details of installed certificates")

    # Add subcommand
    user_add_parser = user_subparsers.add_parser("add", aliases=["a"], help="Add a new user to the system")
    user_add_parser.add_argument("username", action=NoUnderscoreCheck, help="Username of the new user")
    user_add_parser.add_argument("-c", "--cert", help="Path to the user's certificate file (optional, "
                                 "if not provided a new key pair will be generated)")  
    user_add_parser.add_argument("-a", "--admin", action="store_true", help="Add user with admin privileges (unrestricted)")
    user_add_parser.add_argument("-w", "--wireguard", action="store_true", help="Generate WireGuard config for the user in .conf file") 
    user_add_parser.add_argument("-p", "--project", help="Project name to associate the user with an existing project")
    user_add_parser.add_argument("-e", "--email", action=NoCommaCheck, help="User's email address")
    user_add_parser.add_argument("-n", "--name", action=NoCommaCheck, help="User's full name")
    user_add_parser.add_argument("-o", "--org", action=NoCommaCheck, help="User's organization")

    # Grant subcommand
    user_grant_parser = user_subparsers.add_parser("grant", help="Grant a user access to a specific project")
    user_grant_parser.add_argument("username", help="Username to grant access")
    user_grant_parser.add_argument("projectname", help="Project name to grant access to")

    # Edit subcommand
    user_edit_parser = user_subparsers.add_parser("edit", help="Edit an existing user's details")
    user_edit_parser.add_argument("username", action=NoUnderscoreCheck, help="Username to edit")
    user_edit_parser.add_argument("-e", "--email", action=NoCommaCheck, help="New email for the user")
    user_edit_parser.add_argument("-n", "--name", action=NoCommaCheck, help="New full name for the user")
    user_edit_parser.add_argument("-o", "--org", action=NoCommaCheck, help="New organization for the user")

    # Delete subcommand
    user_delete_parser = user_subparsers.add_parser("delete", aliases=["del", "d"], help="Delete an existing user from the system")
    user_delete_parser.add_argument("username", help="Username of the user to delete")
    user_delete_parser.add_argument("-p", "--purge", action="store_true", help="Delete associated projects and user files (if -r) even if the user does not exist")
    user_delete_parser.add_argument("-r", "--removefiles", action="store_true", help="Remove the associated files of the user from the users folder")

    # Link parsers back to the main command
    subparsers._name_parser_map["us"] = user_parser
    subparsers._name_parser_map["u"] = user_parser

    return user_parser

def handle_user_command(args, client, parser_dict):
    if not args.user_command:
        parser_dict['user_parser'].print_help()
    elif args.user_command in ["list", "l"]:
        list_users(client, full=args.full)
    elif args.user_command == "add":
        add_user(args.username, args.cert, client, admin=args.admin, wireguard=args.wireguard, project=args.project, email=args.email, name=args.name, org=args.org)
    elif args.user_command == "grant":
        grant_user_access(args.username, args.projectname, client)
    elif args.user_command == "edit":
        edit_user(args.username, client, email=args.email, name=args.name, org=args.org)
    elif args.user_command in ["delete", "del", "d"]:
        delete_user(args.username, client, purge=args.purge, removefiles=args.removefiles)

#############################################
###### figo remote command CLI ##############
#############################################

def create_remote_parser(subparsers):
    remote_parser = subparsers.add_parser("remote", help="Manage remotes")
    remote_subparsers = remote_parser.add_subparsers(dest="remote_command")

    remote_list_parser = remote_subparsers.add_parser("list", aliases=["l"], help="List available remotes (use -f or --full for more details)")
    remote_list_parser.add_argument("-f", "--full", action="store_true", help="Show full details of available remotes")

    remote_enroll_parser = remote_subparsers.add_parser("enroll", help="Enroll a remote Incus server")
    remote_enroll_parser.add_argument("remote_server", help="Name to assign to the remote server")
    remote_enroll_parser.add_argument("ip_address", help="IP address or domain name of the remote server")
    remote_enroll_parser.add_argument("port", nargs="?", default="8443", help="Port of the remote server (default: 8443)")
    remote_enroll_parser.add_argument("user", nargs="?", default="ubuntu", help="Username for SSH (default: ubuntu)")
    remote_enroll_parser.add_argument("cert_filename", nargs="?", default="~/.config/incus/client.crt", help="Client certificate file to transfer (default: ~/.config/incus/client.cr)")
    remote_enroll_parser.add_argument("--loc_name", default="main", help="Suffix of certificate name saved on the remote server (default: main)")

    subparsers._name_parser_map["re"] = remote_parser
    subparsers._name_parser_map["r"] = remote_parser

    return remote_parser

def handle_remote_command(args, client, parser_dict):
    if not args.remote_command:
        parser_dict['remote_parser'].print_help()
    elif args.remote_command in ["list", "l"]:
        list_remotes(client, full=args.full)
    elif args.remote_command == "enroll":
        ip_address_port = f"{args.ip_address}:{args.port}"
        enroll_remote(args.remote_server, ip_address_port, args.cert_filename, user=args.user, loc_name=args.loc_name)

#############################################
###### figo main functions
#############################################

def create_parser():
    parser = argparse.ArgumentParser(
        description="Manage a federated testbed with CPUs and GPUs",
        prog="figo"
    )
    subparsers = parser.add_subparsers(dest="command")

    parser.add_argument("--version", action="version", version="%(prog)s 0.1")  # Set the version of the program

    parser_dict = {}
    parser_dict['instance_parser'] = create_instance_parser(subparsers)
    parser_dict['gpu_parser'] = create_gpu_parser(subparsers)
    parser_dict['profile_parser'] = create_profile_parser(subparsers)
    parser_dict['user_parser'] = create_user_parser(subparsers)
    parser_dict['remote_parser'] = create_remote_parser(subparsers)

    return parser, parser_dict

def handle_command(args, parser, parser_dict):

    # if --version is provided, print the version and exit
    if hasattr(args, 'version'):
        print(parser.prog, parser.version)  # prints the version of the parser
        return
    
    # Handle the command based on the subparser
    if args.command in ["instance", "in", "i"]:
        handle_instance_command(args, parser_dict)
    elif args.command in ["gpu", "gp", "g"]:
        client = pylxd.Client()
        handle_gpu_command(args, client, parser_dict)
    elif args.command in ["profile", "pr", "p"]:
        client = pylxd.Client()
        handle_profile_command(args, client, parser_dict)
    elif args.command in ["user", "us", "u"]:
        client = pylxd.Client()
        handle_user_command(args, client, parser_dict)
    elif args.command in ["remote", "re", "r"]:
        client = pylxd.Client()
        handle_remote_command(args, client, parser_dict)

def main():
    parser, parser_dict = create_parser()
    argcomplete.autocomplete(parser)
    args = parser.parse_args()

    if not args.command:
        parser.print_help()
    else:
        handle_command(args, parser, parser_dict)   

if __name__ == "__main__":
    main()