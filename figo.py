# # PYTHON_ARGCOMPLETE_OK
#!/home/gpuserver/figo/venv/bin/python

import argparse
import argcomplete
import pylxd
import subprocess
import logging
import os
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

NET_PROFILE = "net-bridged-br-200-3"
NAME_SERVER_IP_ADDR = "160.80.1.8"
NAME_SERVER_IP_ADDR_2 = "8.8.8.8"
PROFILE_DIR = "./profiles"
USER_DIR = "./users"

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def get_instance_profiles(client):
    """Get profiles for all instances and categorize them by their status."""
    instance_profiles = {}
    running_instances = {}
    stopped_instances = []

    for instance in client.instances.all():
        instance_profiles[instance.name] = instance.profiles
        if instance.status == "Running":
            running_instances[instance.name] = instance.profiles
        else:
            stopped_instances.append(instance.name)

    return instance_profiles, running_instances, stopped_instances

def get_all_profiles(client):
    """Get all available profiles."""
    return [profile.name for profile in client.profiles.all()]

def switch_to_remote(remote_node):
    """Switch the Incus CLI to the specified remote node."""
    try:
        subprocess.run(["incus", "remote", "switch", remote_node], check=True)
    except subprocess.CalledProcessError as e:
        print(f"Error: Failed to switch to remote '{remote_node}'. {e}")
        return False
    except Exception as e:
        print(f"Error: An unexpected error occurred while switching to remote '{remote_node}': {e}")
        return False
    return True

def get_instances(remote_node=None, project_name=None, full=False):
    """Get instances from the specified remote node and project and print their details."""

    RED = "\033[91m"
    GREEN = "\033[92m"
    RESET = "\033[0m"

    # Get the instances from 'incus list -f json'
    instances = run_incus_list(remote_node=remote_node, project_name=project_name)
    if instances is None:
        return  # Exit if fetching the instances failed

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
            print("{:<14} {:<4} {:<5} {:<22} {:<30}".format(name, instance_type, state, context, profiles_str))
        else:
            # Print only GPU profiles with color coding based on state
            gpu_profiles = [profile for profile in instance.get("profiles", []) if profile.startswith("gpu")]
            profiles_str = ", ".join(gpu_profiles)
            colored_profiles_str = f"{RED}{profiles_str}{RESET}" if state == "run" else f"{GREEN}{profiles_str}{RESET}"
            print("{:<14} {:<4} {:<5} {:<22} {:<30}".format(name, instance_type, state, context, colored_profiles_str))

def run_incus_list(remote_node="local", project_name="default"):
    """Run the 'incus list -f json' command, optionally targeting a remote node and project, and return its output as JSON."""
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
        print(f"Error: {e.stderr.strip()}")
        return None
    except json.JSONDecodeError as e:
        print(f"Error: Failed to parse JSON output. {e}")
        return None
    except Exception as e:
        print(f"Error: An unexpected error occurred while running 'incus list -f json': {e}")
        return None

def print_profiles(remote_node=None, project_name=None, full=False):
    """Print profiles of all instances, either from the local or a remote Incus node.
    If full is False, prints only GPU profiles with color coding.
    """
    # Determine the header and profile type based on the 'full' flag
    if full:
        print("{:<14} {:<4} {:<5} {:<22} {:<30}".format("INSTANCE", "TYPE", "STATE", "CONTEXT", "PROFILES"))
    else:
        print("{:<14} {:<4} {:<5} {:<22} {:<30}".format("INSTANCE", "TYPE", "STATE", "CONTEXT", "GPU PROFILES"))

    if remote_node is None:
        # #Listing profiles from the local Incus server
        # remote_node = "local"
        
        #iterate over all remote nodes
        remotes = get_incus_remotes()
        for my_remote_node in remotes:
            if my_remote_node == "images":
                continue
            if project_name is None:
                # iterate over all projects
                projects = get_projects(remote_node=my_remote_node)
                for project in projects:
                    my_project_name = project["name"]
                    get_instances(remote_node=my_remote_node, project_name=my_project_name, full=full)
            else:
                get_instances(remote_node=my_remote_node, project_name=project_name, full=full)
    else:
        if project_name is None:
            # iterate over all projects
            projects = get_projects(remote_node=remote_node)
            for project in projects:
                my_project_name = project["name"]
                get_instances(remote_node=remote_node, project_name=my_project_name, full=full)
        else:
            print("Listing profiles from remote node: ", remote_node)
            print("Listing profiles from project: ", project_name)
            get_instances(remote_node=remote_node, project_name=project_name, full=full)

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
    print(f"Profile '{profile.name}' saved to '{file_name}'.")

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
        print(f"Profile '{profile_name}' not found.")
        return

def is_valid_ip(ip):
    """Check if the provided string is a valid IPv4 address."""
    pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
    if pattern.match(ip):
        octets = ip.split('.')
        if all(0 <= int(octet) <= 255 for octet in octets):
            return True
    return False

def set_ip(instance_name, ip_address, gw_address, client):
    """Set a static IP address and gateway for a stopped instance."""
    if not is_valid_ip(ip_address):
        print(f"Error: '{ip_address}' is not a valid IP address.")
        return
    
    if not is_valid_ip(gw_address):
        print(f"Error: '{gw_address}' is not a valid IP address.")
        return

    try:
        instance = client.instances.get(instance_name)
        if instance.status != "Stopped":
            print(f"Error: Instance '{instance_name}' is not stopped.")
            return
        
        # Check if a profile starting with "net-" is associated with the instance
        net_profiles = [profile for profile in instance.profiles if profile.startswith("net-")]
        if not net_profiles:
            print(f"Instance '{instance_name}' does not have a 'net-' profile associated. Adding '{NET_PROFILE}' profile.")
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
        print(f"IP address '{ip_address}' and gateway '{gw_address}' assigned to instance '{instance_name}'.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to set IP address for instance '{instance_name}': {e}")

def set_user_key(instance_name, key_filename, client):
    """Set a public key in the /home/mpi/.ssh/authorized_keys of the specified instance."""
    try:
        # Read the public key from the file
        with open(key_filename, 'r') as key_file:
            public_key = key_file.read().strip()

        # Get the instance
        instance = client.instances.get(instance_name)

        # Check if the instance is running
        if instance.status != "Running":
            print(f"Error: Instance '{instance_name}' is not running.")
            return

        # Connect to the instance using LXD's exec
        def exec_command(command):
            try:
                exec_result = instance.execute(command)
                output, error = exec_result
                if error:
                    print(f"Error executing command '{' '.join(command)}': {error}")
                return output
            except Exception as e:
                print(f"Exception while executing command '{' '.join(command)}': {e}")
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

        print(f"Public key from '{key_filename}' added to /home/mpi/.ssh/authorized_keys in instance '{instance_name}'.")
    except pylxd.exceptions.LXDAPIException as e:
        print(f"Failed to set user key for instance '{instance_name}': {e}")
    except FileNotFoundError:
        print(f"File '{key_filename}' not found.")
    except Exception as e:
        print(f"An error occurred: {e}")

def list_users(client, full=False):
    """List all installed certificates with optional full details."""
    
    if full:
        print("{:<20} {:<12} {:<5} {:<10} {:<20}".format(
            "NAME", "FINGERPRINT", "TYPE", "RESTRICTED", "PROJECTS"
        ))
    else:
        print("{:<20} {:<12}".format("NAME", "FINGERPRINT"))

    for certificate in client.certificates.all():
        name = certificate.name or "N/A"
        fingerprint = certificate.fingerprint[:12]

        if full:
            projects = ", ".join(certificate.projects)
            print("{:<20} {:<12} {:<5} {:<10} {:<20}".format(
                name, fingerprint, certificate.type[:3], str(certificate.restricted), projects
            ))
        else:
            print(f"{name:<20} {fingerprint:<12}")

def resolve_hostname(hostname):
    """Resolve the hostname to an IP address."""
    try:
        return socket.gethostbyname(hostname)
    except socket.error:
        return None

def get_incus_remotes():
    """Fetches and returns the list of Incus remotes as a JSON object."""
    result = subprocess.run(['incus', 'remote', 'list', '--format', 'json'], capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to retrieve Incus remotes: {result.stderr}")

    try:
        remotes = json.loads(result.stdout)
        return remotes
    except json.JSONDecodeError:
        raise ValueError("Failed to parse JSON. The output may not be in the expected format.")

def get_projects(remote_node="local"): 
    """Fetches and returns the list of projects as a JSON object."""
    result = subprocess.run(['incus', 'project', 'list', f"{remote_node}:", '--format', 'json'], capture_output=True, text=True)

    if result.returncode != 0:
        raise RuntimeError(f"Failed to retrieve projects: {result.stderr}")

    try:
        projects = json.loads(result.stdout)
        return projects
    except json.JSONDecodeError:
        raise ValueError("Failed to parse JSON. The output may not be in the expected format.")


def list_remotes(client, full=False):
    """Lists the available Incus remotes and their addresses."""
    if full:
        list_remotes_full()
    else:
        remotes = get_incus_remotes()
        print("{:<20} {:<40}".format("REMOTE NAME", "ADDRESS"))
        for remote_name, remote_info in remotes.items():
            print("{:<20} {:<40}".format(remote_name, remote_info['Addr']))

def list_remotes_full():
    """Shows all fields for the available Incus remotes."""
    remotes = get_incus_remotes()
    for remote_name, remote_info in remotes.items():
        print(f"REMOTE NAME: {remote_name}")
        for key, value in remote_info.items():
            print(f"  {key}: {value}")
        print("-" * 60)

def enroll(remote_server, ip_address_port, cert_filename="~/.config/incus/client.crt",
           user="ubuntu", loc_name="main"):
    """Enroll a remote server by transferring the client certificate and adding it to the Incus daemon."""
    ip_address, port = (ip_address_port.split(":") + ["8443"])[:2]

    if not is_valid_ip(ip_address):
        resolved_ip = resolve_hostname(ip_address)
        if resolved_ip:
            ip_address = resolved_ip
        else:
            print(f"Invalid IP address or hostname: {ip_address}")
            return

    cert_filename = os.path.expanduser(cert_filename)
    remote_cert_path = f"{user}@{ip_address}:~/figo/certs/{loc_name}.crt"

    try:
        # Check if the certificate already exists on the remote server
        check_cmd = f"ssh {user}@{ip_address} '[ -f ~/figo/certs/{loc_name}.crt ]'"
        result = subprocess.run(check_cmd, shell=True)

        if result.returncode == 0:
            print(f"Warning: Certificate {loc_name}.crt already exists on {ip_address}.")
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
            print(f"Certificate {cert_filename} successfully transferred to {ip_address}.")

            # Add the certificate to the Incus daemon on the remote server
            try:
                add_cert_cmd = (
                    f"incus config trust add-certificate --name incus_{loc_name} ~/figo/certs/{loc_name}.crt"
                )
                subprocess.run(
                    ["ssh", f"{user}@{ip_address}", add_cert_cmd],
                    check=True
                )
                print(f"Certificate {loc_name}.crt added to Incus on {ip_address}.")
            except subprocess.CalledProcessError as e:
                if "already exists" in str(e):
                    print(f"Warning: Certificate incus_{loc_name} already added to Incus on {ip_address}.")
                else:
                    print(f"An error occurred while adding the certificate to Incus: {e}")
                    return

    except subprocess.CalledProcessError as e:
        print(f"An error occurred while processing the certificate: {e}")
        return

    # Check if the remote server already exists
    try:
        remotes = get_incus_remotes()
        if remote_server in remotes:
            print(f"Warning: Remote server {remote_server} is already configured.")
        else:
            # Add the remote server to the client configuration
            subprocess.run(
                ["incus", "remote", "add", remote_server, f"https://{ip_address}:{port}", "--accept-certificate"],
                check=True
            )
            print(f"Remote server {remote_server} added to client configuration.")
    except subprocess.CalledProcessError as e:
        print(f"An error occurred while adding the remote server to the client configuration: {e}")

def add_user(user_name, cert_file, client):
    # Check if user already exists in the certificates
    for cert in client.certificates.all():
        if cert.name == user_name:
            print(f"Error: User '{user_name}' already exists.")
            return

    # Check if the project already exists
    project_name = f"prj-{user_name}"
    if project_name in [project.name for project in client.projects.all()]:
        print(f"Error: Project '{project_name}' already exists.")
        return

    directory = os.path.expanduser(USER_DIR)
    # Ensure directory exists
    if not os.path.exists(directory):
        os.makedirs(directory)

    # Determine whether to use the provided cert or generate a new key pair
    if cert_file:
        # Use the provided certificate
        crt_file = cert_file
        print(f"Using provided certificate: {crt_file}")
    else:
        # Generate key pair and certificate
        crt_file = os.path.join(directory, f"{user_name}.crt")
        pfx_file = os.path.join(directory, f"{user_name}.pfx")
        generate_key_pair(user_name, crt_file, pfx_file)
        print(f"Generated certificate and key pair for user: {user_name}")

    # Create project for the user
    create_project(client, project_name)

    # Add the user certificate to Incus
    add_certificate_to_incus(user_name, crt_file, project_name)

def generate_key_pair(user_name, crt_file, pfx_file):
    """Generate key pair (CRT and PFX files) for the user."""
    # Generate private key
    private_key = cryptography.hazmat.primitives.asymmetric.rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=cryptography.hazmat.backends.default_backend()
    )

    # Generate a self-signed certificate
    subject = issuer = cryptography.x509.Name([
        cryptography.x509.NameAttribute(cryptography.x509.oid.NameOID.COMMON_NAME, user_name),
    ])
    
    certificate = cryptography.x509.CertificateBuilder() \
        .subject_name(subject) \
        .issuer_name(issuer) \
        .public_key(private_key.public_key()) \
        .serial_number(cryptography.x509.random_serial_number()) \
        .not_valid_before(datetime.datetime.utcnow()) \
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365)) \
        .sign(private_key, cryptography.hazmat.primitives.hashes.SHA256(), cryptography.hazmat.backends.default_backend())

    # Write certificate to file
    with open(crt_file, "wb") as crt:
        crt.write(certificate.public_bytes(cryptography.hazmat.primitives.serialization.Encoding.PEM))

    # Write private key and certificate to a PFX file
    with open(pfx_file, "wb") as pfx:
        pfx.write(private_key.private_bytes(
            cryptography.hazmat.primitives.serialization.Encoding.PEM,
            cryptography.hazmat.primitives.serialization.PrivateFormat.PKCS8,
            cryptography.hazmat.primitives.serialization.NoEncryption()
        ))

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
        print(f"Project '{project_name}' created successfully.")

    except pylxd.exceptions.LXDAPIException as e:
        print(f"Error creating project '{project_name}': {str(e)}")


def add_certificate_to_incus(user_name, crt_file, project_name):
    """Add user certificate to Incus with restricted access to the project."""
    try:
        # Execute the incus command to add the certificate
        subprocess.run([
            "incus", "config", "trust", "add-certificate", crt_file, 
            "--restricted", 
            f"--projects={project_name}", 
            f"--name={user_name}"
        ], check=True)
        print(f"User '{user_name}' certificate added to Incus with project '{project_name}'.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to add certificate to Incus: {e}")

def main():
    parser = argparse.ArgumentParser(
        description="Manage a federated testbed with CPUs and GPUs",
        prog="figo"
    )
    subparsers = parser.add_subparsers(dest="command")

    # "instance" command without aliases in the help text
    instance_parser = subparsers.add_parser("instance", help="Manage instances")
    instance_subparsers = instance_parser.add_subparsers(dest="instance_command")

    # Add "list" subcommand under "instance"
    instance_list_parser = instance_subparsers.add_parser("list", help="List instances (use -f or --full for more details)")
    instance_list_parser.add_argument("-f", "--full", action="store_true", help="Show full details of instance profiles")
    instance_list_parser.add_argument("scope", nargs="?", help="Scope in the format 'remote:project' to limit the listing")
    instance_list_parser.add_argument("-p", "--project", help="Project name to list instances from")
    instance_list_parser.add_argument("-r", "--remote", help="Remote Incus server name")

    # Add "start" subcommand under "instance"
    start_parser = instance_subparsers.add_parser("start", help="Start a specific instance")
    start_parser.add_argument("instance_name", help="Name of the instance to start")

    # Add "stop" subcommand under "instance"
    stop_parser = instance_subparsers.add_parser("stop", help="Stop a specific instance")
    stop_parser.add_argument("instance_name", help="Name of the instance to stop")

    # Add "set_key" subcommand under "instance"
    set_key_parser = instance_subparsers.add_parser("set_key", help="Set a public key for a user in an instance")
    set_key_parser.add_argument("instance_name", help="Name of the instance")
    set_key_parser.add_argument("key_filename", help="Filename of the public key on the host")

    # Add "set_ip" subcommand under "instance"
    set_ip_parser = instance_subparsers.add_parser("set_ip", help="Set a static IP address and gateway for a stopped instance")
    set_ip_parser.add_argument("instance_name", help="Name of the instance to set the IP address for")
    set_ip_parser.add_argument("ip_address", help="Static IP address to assign to the instance")
    set_ip_parser.add_argument("gw_address", help="Gateway address to assign to the instance")

    # Manually add aliases for "instance"
    subparsers._name_parser_map["in"] = instance_parser
    subparsers._name_parser_map["i"] = instance_parser

    # "gpu" command without aliases in the help text
    gpu_parser = subparsers.add_parser("gpu", help="Manage GPUs")
    gpu_subparsers = gpu_parser.add_subparsers(dest="gpu_command")

    # Add GPU subcommands
    gpu_status_parser = gpu_subparsers.add_parser("status", help="Show GPU status")
    gpu_list_parser = gpu_subparsers.add_parser("list", help="List GPU profiles")
    add_gpu_parser = gpu_subparsers.add_parser("add", help="Add a GPU profile to a specific instance")
    add_gpu_parser.add_argument("instance_name", help="Name of the instance to add a GPU profile to")
    remove_gpu_parser = gpu_subparsers.add_parser("remove", help="Remove GPU profiles from a specific instance")
    remove_gpu_parser.add_argument("instance_name", help="Name of the instance to remove a GPU profile from")
    remove_gpu_parser.add_argument("--all", action="store_true", help="Remove all GPU profiles from the instance")

    # Manually add aliases for "gpu"
    subparsers._name_parser_map["gp"] = gpu_parser
    subparsers._name_parser_map["g"] = gpu_parser

    # "profile" command without aliases in the help text
    profile_parser = subparsers.add_parser("profile", help="Manage profiles")
    profile_subparsers = profile_parser.add_subparsers(dest="profile_command")

    # Add profile subcommands
    dump_profiles_parser = profile_subparsers.add_parser("dump", help="Dump profiles to .yaml files")
    dump_profiles_parser.add_argument("-a", "--all", action="store_true", help="Dump all profiles to .yaml files")
    dump_profiles_parser.add_argument("profile_name", nargs="?", help="Name of the profile to dump")

    # Add "list" subcommand under "profile"
    profile_list_parser = profile_subparsers.add_parser("list", help="List profiles and associated instances")

    # Manually add aliases for "profile"
    subparsers._name_parser_map["pr"] = profile_parser
    subparsers._name_parser_map["p"] = profile_parser

    # "user" command without aliases in the help text
    user_parser = subparsers.add_parser("user", help="Manage users")
    user_subparsers = user_parser.add_subparsers(dest="user_command")

    # Add user subcommands
    user_list_parser = user_subparsers.add_parser(
        "list", 
        help="List installed certificates (use -f or --full for more details)"
    )
    user_list_parser.add_argument("-f", "--full", action="store_true", help="Show full details of installed certificates")

    # Modify "add" subcommand under "user" to make "key_filename" optional and add "--cert" option
    user_add_parser = user_subparsers.add_parser(
        "add", 
        help="Add a new user to the system"
    )
    user_add_parser.add_argument("username", help="Username of the new user")
    user_add_parser.add_argument("--cert", help="Path to the user's certificate file (optional)")

    # Manually add aliases for "user"
    subparsers._name_parser_map["us"] = user_parser
    subparsers._name_parser_map["u"] = user_parser

    # "remote" command without aliases in the help text
    remote_parser = subparsers.add_parser("remote", help="Manage remotes")
    remote_subparsers = remote_parser.add_subparsers(dest="remote_command")

    # Add remote subcommands
    remote_list_parser = remote_subparsers.add_parser(
        "list", 
        help="List available remotes (use -f or --full for more details)"
    )
    remote_list_parser.add_argument("-f", "--full", action="store_true", help="Show full details of available remotes")
    remote_enroll_parser = remote_subparsers.add_parser("enroll", help="Enroll a remote Incus server")
    remote_enroll_parser.add_argument("remote_server", help="Name to assign to the remote server")
    remote_enroll_parser.add_argument("ip_address", help="IP address or domain name of the remote server")
    remote_enroll_parser.add_argument("port", nargs="?", default="8443", help="Port of the remote server (default: 8443)")
    remote_enroll_parser.add_argument("user", nargs="?", default="ubuntu", help="Username for SSH (default: ubuntu)")
    remote_enroll_parser.add_argument("cert_filename", nargs="?", default="~/.config/incus/client.cr", 
                                      help="Client certificate file to transfer (default: ~/.config/incus/client.cr)")
    remote_enroll_parser.add_argument("--loc_name", default="main", help="Name to use for local storage (default: main)")

    # Manually add aliases for "remote"
    subparsers._name_parser_map["re"] = remote_parser
    subparsers._name_parser_map["r"] = remote_parser

    argcomplete.autocomplete(parser)

    args = parser.parse_args()
    client = pylxd.Client()

    if not args.command:
        parser.print_help()
    elif args.command in ["instance", "in", "i"]:
        if not args.instance_command:
            instance_parser.print_help()
        elif args.instance_command == "list":
            remote_node = args.remote
            project_name = args.project

            if args.scope:
                if ":" in args.scope:
                    # If scope is "remote:project"
                    remote_scope, project_scope = args.scope.split(":", 1)
                    print(f"remote_scope: {remote_scope}, project_scope: {project_scope}")
                    if project_scope == "":
                        project_scope = None

                    if args.remote and args.remote != remote_scope:
                        print(f"Error: Conflict between scope remote '{remote_scope}' and provided remote '{args.remote}'.")
                        return
                    if args.project and project_scope and args.project != project_scope:
                        print(f"Error: Conflict between scope project '{project_scope}' and provided project '{args.project}'.")
                        return

                    remote_node = remote_scope
                    project_name = project_scope if project_scope else args.project
                else:
                    # If scope is only "project"
                    project_scope = args.scope

                    if args.project and args.project != project_scope:
                        print(f"Error: Conflict between scope project '{project_scope}' and provided project '{args.project}'.")
                        return

                    project_name = project_scope

            if args.full:
                print_profiles(remote_node, project_name=project_name, full=True)
            else:
                print_profiles(remote_node, project_name=project_name, full=False)
        elif args.instance_command == "start":
            start_instance(args.instance_name, client)
        elif args.instance_command == "stop":
            stop_instance(args.instance_name, client)
        elif args.instance_command == "set_key":
            set_user_key(args.instance_name, args.key_filename, client)
        elif args.instance_command == "set_ip":
            set_ip(args.instance_name, args.ip_address, args.gw_address, client)
    elif args.command in ["gpu", "gp", "g"]:
        if not args.gpu_command:
            gpu_parser.print_help()
        elif args.gpu_command == "status":
            show_gpu_status(client)
        elif args.gpu_command == "list":
            list_gpu_profiles(client)
        elif args.gpu_command == "add":
            add_gpu_profile(args.instance_name, client)
        elif args.gpu_command == "remove":
            if args.all:
                remove_gpu_all_profiles(args.instance_name, client)
            else:
                remove_gpu_profile(args.instance_name, client)
    elif args.command in ["profile", "pr", "p"]:
        if not args.profile_command:
            profile_parser.print_help()
        elif args.profile_command == "dump":
            if args.all:
                dump_profiles(client)
            elif args.profile_name:
                dump_profile(client, args.profile_name)
            else:
                print("You must provide a profile name or use the --all option.")
        elif args.profile_command == "list":
            list_profiles(client)
    elif args.command in ["user", "us", "u"]:
        if not args.user_command:
            user_parser.print_help()
        elif args.user_command == "list":
            list_users(client, full=args.full)
        elif args.user_command == "add":
            add_user(args.username, args.cert, client)
    elif args.command in ["remote", "re", "r"]:
        if not args.remote_command:
            remote_parser.print_help()
        elif args.remote_command == "list":
            list_remotes(client, full=args.full)
        elif args.remote_command == "enroll":
            enroll(args.remote_server, args.ip_address, args.port, args.user, 
                          args.cert_filename, args.loc_name)

if __name__ == "__main__":
    main()