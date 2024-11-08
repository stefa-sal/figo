# FIGO - Federated Infrastructure for GPU Orchestration

FIGO is a tool for managing federated testbeds with CPUs and GPUs. It provides commands to handle instances (VMs and containers) and GPU profiles.

End user manual (installation and usage) is available [here](https://figo-testbed.readthedocs.io/).

The source code of the documentation site is [here](https://github.com/netgroup/figo-testbed).

## Usage (for administrators)

FIGO provides various commands to manage VM and container instances and GPU profiles. Below is a detailed guide on how to use these commands.

### General Usage

When the script is called with no command parameters, the general usage information is displayed:

```bash
figo
```

### Commands

**Description:**  
This module provides a command-line interface (CLI) to manage a federated testbed with CPUs and GPUs. The `figo` program offers various commands and subcommands for managing instances, GPUs, profiles, users, remotes, projects, and VPNs in a federated environment.

**Usage:**

```bash
figo [command] [subcommand] [options]
```

**Commands:**

- `figo instance`
- `figo gpu`
- `figo profile`
- `figo user`
- `figo remote`
- `figo project`
- `figo vpn`

Each command has its own set of subcommands and options.

### Command and Subcommand Details

#### figo instance

- **Aliases:** `in`, `i`
- **Description:** Manage instances.
- **Subcommands:**

  - **list**
    - **Description:** List instances, with options to show detailed profiles and adjust column width for better readability.
    - **Syntax:**

      ```bash
      figo instance list [scope] [-f | --full] [-p project] [-r remote] [-e | --extend]
      ```

    - **Options:**  
      - `scope`: Define the scope in the format `remote:project` to limit the listing.
      - `-f, --full`: Show full details of instance profiles.
      - `-p, --project`: Specify the project name to list instances from.
      - `-r, --remote`: Specify the remote Incus server name.
      - `-e, --extend`: Extend column width to fit content.

    - **Examples:**
      ```bash
      figo instance list
      figo instance list my_remote:my_project
      figo instance list -f -r my_remote
      figo instance list my_project -p my_project -e
      ```

  - **start**
    - **Description:** Start a specific instance.
    - **Syntax:**

      ```bash
      figo instance start instance_name [-p project] [-r remote]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to start. Can include remote and project scope.
      - `-p, --project`: Specify the project name.
      - `-r, --remote`: Specify the remote Incus server name.

    - **Examples:**
      ```bash
      figo instance start my_instance
      figo instance start my_project.my_instance -r my_remote
      figo instance start my_remote:my_project.my_instance
      ```

  - **stop**
    - **Description:** Stop a specific instance or all instances in a scope.
    - **Syntax:**

      ```bash
      figo instance stop [instance_name] [-a | --all] [-p project] [-r remote]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to stop. Can include remote and project scope.
      - `-a, --all`: Stop all instances within the specified scope.
      - `-p, --project`: Specify the project name.
      - `-r, --remote`: Specify the remote Incus server name.

    - **Examples:**
      ```bash
      figo instance stop my_instance
      figo instance stop my_remote:my_project.my_instance
      figo instance stop my_instance -a -p my_project -r my_remote
      ```

  - **set_key**
    - **Description:** Set a public key for a user in an instance.
    - **Syntax:**

      ```bash
      figo instance set_key instance_name key_filename [-l login] [-d dir] [-f] [-p project] [-r remote]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance. Can include remote and project scope.
      - `key_filename`: The filename of the public key on the host.
      - `-l, --login`: Specify the login name (default: ubuntu).
      - `-d, --dir`: Specify the directory path where the key file is located (default: ./users).
      - `-f, --force`: Start the instance if not running, then stop it after setting the key.
      - `-p, --project`: Specify the project name.
      - `-r, --remote`: Specify the remote Incus server name.

    - **Examples:**
      ```bash
      figo instance set_key my_instance my_key.pub
      figo instance set_key my_project.my_instance my_key.pub -l admin -r my_remote
      figo instance set_key my_remote:my_project.my_instance my_key.pub -f
      ```

  - **set_ip**
    - **Description:** Set a static IP address and gateway for a stopped instance.
    - **Syntax:**

      ```bash
      figo instance set_ip instance_name -i ip_address -g gw_address [-n nic] [-p project] [-r remote]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to set the IP address for. Can include remote and project scope.
      - `-i, --ip`: The static IP address with prefix length (e.g., 192.168.1.10/24).
      - `-g, --gw`: The gateway address.
      - `-n, --nic`: The NIC name (default: eth0 for containers, enp5s0 for VMs).
      - `-p, --project`: Specify the project name.
      - `-r, --remote`: Specify the remote Incus server name.

    - **Examples:**
      ```bash
      figo instance set_ip my_instance -i 192.168.1.10/24 -g 192.168.1.1
      figo instance set_ip my_project.my_instance -i 192.168.1.20/24 -g 192.168.1.1 -r my_remote
      figo instance set_ip my_remote:my_project.my_instance -i 10.0.0.5/16 -g 10.0.0.1 -n eth1
      ```

  - **create**
    - **Description:** Create a new instance.
    - **Syntax:**

      ```bash
      figo instance create instance_name image [-t type] [-p project] [-r remote] [-i ip_address] [-g gw_address] [-n nic] [-f profiles]
      ```

    - **Options:**  
      - `instance_name`: The name of the new instance. Can include remote and project scope in the format `remote:project.instance_name`.
      - `image`: Image source to create the instance from (e.g., `images:ubuntu/20.04`).
      - `-t, --type`: Specify the instance type (`vm`, `container`, or `cnt` for container). Default is `container`.
      - `-p, --project`: Specify the project under which the instance will be created.
      - `-r, --remote`: Specify the remote Incus server.
      - `-i, --ip`: Specify a static IP address for the instance.
      - `-g, --gw`: Specify the gateway address for the instance.
      - `-n, --nic`: Specify the NIC name for the instance (default: `eth0` for containers, `enp5s0` for VMs).
      - `-f, --profile`: Comma-separated list of profiles to apply to the instance.

    - **Examples:**
      ```bash
      # Create a container instance with default options
      figo instance create my_instance images:ubuntu/20.04

      # Create a VM instance with specific project and remote
      figo instance create my_project.my_instance images:debian/11 -t vm -r my_remote

      # Create an instance with a static IP, gateway, and specific NIC
      figo instance create my_remote:my_project.my_instance images:centos/8 -i 10.0.0.10/24 -g 10.0.0.1 -n enp5s0

      # Create an instance and apply specific profiles
      figo instance create my_instance images:ubuntu/22.04 -f profile1,profile2

      # Create an instance with project and remote scope and multiple profiles
      figo instance create my_project.my_instance images:alpine/3.15 -r my_remote -f profile1,profile3
      ```

  - **delete**
    - **Description:** Delete a specific instance, with an option to force deletion.
    - **Syntax:**

      ```bash
      figo instance delete instance_name [-f] [-p project] [-r remote]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to delete. Can include remote and project scope.
      - `-f, --force`: Force delete the instance even if it is running.
      - `-p, --project`: Specify the project name.
      - `-r, --remote`: Specify the remote Incus server name.

    - **Examples:**
      ```bash
      figo instance delete my_instance
      figo instance delete my_remote:my_project.my_instance -f
      figo instance delete my_project.my_instance -p my_project -r my_remote
      ```

  - **bash**
    - **Description:** Execute bash in a specific instance.
    - **Syntax:**

      ```bash
      figo instance bash instance_name [-f] [-t timeout] [-a attempts] [-p project] [-r remote]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to execute bash. Can include remote and project scope.
      - `-f, --force`: Start the instance if not running and execute bash.
      - `-t, --timeout`: Total timeout in seconds for retries.
      - `-a, --attempts`: Number of retry attempts to connect.
      - `-p, --project`: Specify the project name.
      - `-r, --remote`: Specify the remote Incus server name.

    - **Examples:**
      ```bash
      figo instance bash my_instance
      figo instance bash my_project.my_instance -t 60 -a 5
      figo instance bash my_remote:my_project.my_instance -f -r my_remote
      ```
      
#### figo gpu

- **Aliases:** `gp`, `g`
- **Description:** Manage GPUs in instances within the federated testbed.
- **Subcommands:**

  - **status**
    - **Description:** Show the current status of GPUs, including their availability and usage.  
    - **Syntax:**

      ```bash
      figo gpu status [-e | --extend]
      ```

    - **Options:**
      - `-e, --extend`: Extend column width to fit the content for better readability.

    - **Examples:**
      ```bash
      figo gpu status
      figo gpu status --extend
      ```

  - **list**
    - **Description:** List GPU profiles configured in the system, with an option to extend column width.
    - **Syntax:**

      ```bash
      figo gpu list [-e | --extend]
      ```

    - **Options:**
      - `-e, --extend`: Extend column width to fit the content for better readability.

    - **Examples:**
      ```bash
      figo gpu list
      figo gpu list --extend
      ```

  - **add**
    - **Description:** Add a GPU profile to a specific instance. The instance name can include remote and project scope in the format `remote:project.instance_name`. If not provided, use the `-r/--remote` and `-p/--project` options.
    - **Syntax:**

      ```bash
      figo gpu add instance_name [-p | --project project_name] [-r | --remote remote_name] [-u | --user user_name]
      ```

    - **Options:**
      - `instance_name`: The name of the instance to which the GPU profile will be added. Can include remote and project scope.
      - `-p, --project`: Specify the project name for the instance.
      - `-r, --remote`: Specify the remote Incus server name.
      - `-u, --user`: Specify the user to infer the project from.

    - **Examples:**
      ```bash
      figo gpu add my_instance
      figo gpu add my_project.instance_name -r my_remote
      figo gpu add my_remote:my_project.instance_name
      figo gpu add instance_name -p my_project -r my_remote
      figo gpu add my_instance -u user_name
      ```

  - **remove**
    - **Description:** Remove GPU profiles from a specific instance. Optionally, remove all profiles. The instance name can include remote and project scope in the format `remote:project.instance_name`. If not provided, use the `-r/--remote` and `-p/--project` options.
    - **Syntax:**

      ```bash
      figo gpu remove instance_name [-p | --project project_name] [-r | --remote remote_name] [-u | --user user_name] [--all]
      ```

    - **Options:**
      - `instance_name`: The name of the instance from which the GPU profile will be removed. Can include remote and project scope.
      - `-p, --project`: Specify the project name for the instance.
      - `-r, --remote`: Specify the remote Incus server name.
      - `-u, --user`: Specify the user to infer the project from.
      - `--all`: Remove all GPU profiles from the specified instance.

    - **Examples:**
      ```bash
      figo gpu remove my_instance
      figo gpu remove my_project.instance_name --all
      figo gpu remove my_remote:my_project.instance_name
      figo gpu remove instance_name -p my_project -r my_remote --all
      figo gpu remove my_instance -u user_name
      ```

#### figo profile

- **Aliases:** `pr`, `p`
- **Description:** Manage profiles.
- **Subcommands:**
  - **dump**
    - **Description:** Dump profiles to `.yaml` files.
    - **Syntax:**

      ```bash
      figo profile dump [-a | --all] [profile_name]
      ```

    - **Options:**
      - `-a, --all`: Dump all profiles to `.yaml` files.
      - `profile_name`: The name of the profile to dump.

  - **list**
    - **Description:** List profiles and associated instances, with options for inherited profiles and extended column width.
    - **Syntax:**

      ```bash
      figo profile list [scope] [-i | --inherited] [-e | --extend]
      ```

    - **Options:**
      - `scope`: Define the scope in the format `remote:project.profile_name`, `remote:project`, `project.profile_name`, or `profile_name`.
      - `-i, --inherited`: Include inherited profiles in the listing.
      - `-e, --extend`: Extend column width to fit the content.

  - **copy**
    - **Description:** Copy a profile to a new profile name or remote/project.
    - **Syntax:**

      ```bash
      figo profile copy source_profile [target_profile]
      ```

    - **Options:**  
      - `source_profile`: Source profile in the format `remote:project.profile_name` or `project.profile_name` or `profile_name`.
      - `target_profile`: Target profile name or destination, following the same format as `source_profile`.

    - **Examples:**
      ```bash
      figo profile copy remote:project.profile1 remote:project.profile2
      figo profile copy remote:project.profile1 remote:project
      ```

  - **delete**
    - **Description:** Delete a profile.
    - **Syntax:**

      ```bash
      figo profile delete profile_scope
      ```

    - **Options:**
      - `profile_scope`: Profile scope in the format `remote:project.profile_name`, `remote:project`, `project.profile_name`, or `profile_name`.

#### figo user

- **Aliases:** `us`, `u`
- **Description:** Manage users.
- **Subcommands:**
  - **list**  
    - **Description:** List installed certificates, with options to show detailed information and extend column width for better readability.  
    - **Syntax:**

      ```bash
      figo user list [-f | --full] [-e | --extend]
      ```

    - **Options:**  
      - `-f, --full`: Show full details of installed certificates.
      - `-e, --extend`: Extend column width to fit the content.

  - **add**  
    - **Description:** Add a new user to the system.  
    - **Syntax:**

      ```bash
      figo user add username [-c | --cert cert_filename] [-a | --admin] [-w | --wireguard] [-s | --set_vpn] [-p | --project project_name] [-e | --email email] [-n | --name full_name] [-o | --org organization] [-k | --keys]
      ```

    - **Options:**  
      - `username`: Username of the new user.
      - `-c, --cert`: Path to the user's certificate file. If not provided, a new key pair will be generated.
      - `-a, --admin`: Add user with admin privileges.
      - `-w, --wireguard`: Generate WireGuard configuration for the user in a `.conf` file.
      - `-s, --set_vpn`: Set the user's VPN profile into the WireGuard access node.
      - `-p, --project`: Associate the user with an existing project.
      - `-e, --email`: User's email address.
      - `-n, --name`: User's full name.
      - `-o, --org`: User's organization.
      - `-k, --keys`: Generate a key pair for SSH access to instances.

  - **grant**  
    - **Description:** Grant a user access to a specific project.  
    - **Syntax:**

      ```bash
      figo user grant username projectname
      ```

    - **Options:**  
      - `username`: Username to grant access.
      - `projectname`: Project name to grant access to.

  - **edit**  
    - **Description:** Edit an existing user's details.  
    - **Syntax:**

      ```bash
      figo user edit username [-e | --email new_email] [-n | --name new_full_name] [-o | --org new_organization]
      ```

    - **Options:**  
      - `username`: Username to edit.
      - `-e, --email`: New email for the user.
      - `-n, --name`: New full name for the user.
      - `-o, --org`: New organization for the user.

  - **delete**  
    - **Description:** Delete an existing user from the system.  
    - **Syntax:**

      ```bash
      figo user delete username [-p | --purge] [-k | --keepfiles]
      ```

    - **Options:**  
      - `username`: Username of the user to delete.
      - `-p, --purge`: Delete associated projects and user files, even if the user does not exist.
      - `-k, --keepfiles`: Keep the associated files of the user in the users folder.

#### figo remote

- **Aliases:** `re`, `r`
- **Description:** Manage remotes for the FIGO system, including listing, enrolling, and deleting remote servers.
- **Subcommands:**

  - **list**
    - **Description:** List available remotes, with options to show detailed information and adjust column width for better readability.
    - **Syntax:**

      ```bash
      figo remote list [-f | --full] [-e | --extend]
      ```

    - **Options:**
      - `-f, --full`: Show full details of available remotes.
      - `-e, --extend`: Extend column width to fit the content.

    - **Examples:**
      ```bash
      figo remote list
      figo remote list -f
      figo remote list --extend
      ```

  - **enroll**
    - **Description:** Enroll a remote Incus server to set up a connection for managing instances and resources.
    - **Syntax:**

      ```bash
      figo remote enroll remote_server ip_address [port] [user] [cert_filename] [remote_cert_filename] [--loc_name loc_name]
      ```

    - **Options:**
      - `remote_server`: Name to assign to the remote server.
      - `ip_address`: IP address or domain name of the remote server.
      - `port`: Port of the remote server (default: 8443).
      - `user`: Username for SSH into the remote server (default: `ubuntu`).
      - `cert_filename`: Path to the client certificate file on the main node (default: `~/.config/incus/client.crt`).
      - `remote_cert_filename`: Path to the server certificate file on the remote server (default: `/var/lib/incus/server.crt`).
      - `--loc_name`: Suffix for the client certificate name saved on the remote server (default: `main`).
    - **Examples:**
      ```bash
      figo remote enroll my_remote 192.168.1.100
      figo remote enroll my_remote 192.168.1.100 8443 ubuntu ~/.config/incus/client.crt /var/lib/incus/server.crt --loc_name main
      ```

  - **delete**
    - **Description:** Delete a specified remote from the system, removing its configuration.
    - **Syntax:**

      ```bash
      figo remote delete remote_name
      ```

    - **Options:**
      - `remote_name`: The name of the remote to delete.

    - **Examples:**
      ```bash
      figo remote delete my_remote
      figo remote delete test_remote
      ```

#### figo project

- **Description:** Manage projects within the federated testbed.
- **Subcommands:**
  - **list**
    - **Description:** List available projects, optionally specifying a remote or user.
    - **Syntax:**

      ```bash
      figo project list [scope] [--remote remote_name] [--user user_name] [-e | --extend]
      ```

    - **Options:**  
      - `scope`: Scope in the format `remote:project`, `remote:`, or `project.` to limit the listing.
      - `--remote`: Specify the remote server name.
      - `--user`: Specify a user to filter the projects by ownership.
      - `-e, --extend`: Extends column width to fit the content.

  - **create**
    - **Description:** Create a new project, specifying scope, project name, and user ownership.
    - **Syntax:**

      ```bash
      figo project create scope [--project project_name] [--user user_name]
      ```

    - **Options:**  
      - `scope`: Scope in the format `remote:project` or `remote:`.
      - `--project`: Project name, if not provided directly in the scope.
      - `--user`: Specify the user who will own the project.

  - **delete**
    - **Description:** Delete an existing project.
    - **Syntax:**

      ```bash
      figo project delete project_name
      ```

    - **Options:**  
      - `project_name`: Name of the project to delete, in the format `remote:project` or `project`.

#### figo vpn

- **Description:** Manage VPN configuration for secure communication and routing.
- **Subcommands:**
  - **add route**
    - **Description:** Add a new route to an existing VPN configuration.
    - **Syntax:**

      ```bash
      figo vpn add route dst_address via gateway type vpn_type [target|host] target_or_host [-d dev] [-u user] [-p port]
      ```

    - **Options:**  
      - `dst_address`: Destination address in CIDR format (e.g., `10.202.128.0/24`).
      - `via`: The keyword `via` followed by the gateway IP.
      - `gateway`: Gateway address (e.g., `10.202.9.2`) without a prefix.
      - `type`: The keyword `type` followed by the VPN device type, such as `mikrotik` or `linux`.
      - `target`: The keyword `target` followed by the target identifier (if applicable).
      - `host`: The keyword `host` followed by the host address.
      - `target_or_host`: The actual target or host for the VPN configuration.
      - `-d, --dev`: Device interface (e.g., `vlan403`). Required for Linux routers.
      - `-u, --user`: SSH username for logging into the node (default: configured SSH user).
      - `-p, --port`: SSH port for connecting to the VPN host (default: configured SSH port).

    - **Example:** Add a VPN route to a Linux router:

      ```bash
      figo vpn add route 10.202.128.0/24 via 10.202.9.2 type linux target target-name -d vlan403
      ```

## Autocompletion

The CLI supports autocompletion using the `argcomplete` library,

using `argcomplete` library, which must be installed and configured to enable this feature.

## Examples

- List all instances in a specific project:

    ```bash
    figo instance list myproject
    ```

- Start an instance named `test-instance`:

    ```bash
    figo instance start test-instance
    ```

- Add a GPU profile to an instance:

    ```bash
    figo gpu add test-instance
    ```

- Enroll a remote Incus server:

    ```bash
    figo remote enroll my-remote-server 192.168.1.10 8443 myuser ~/.config/incus/client.cr --loc_name backup
    ```

- Add a user, generating a browser client certificate:

    ```bash
    figo user add user-name --email user@email.com --name "Name of User" --org "User organization"
    ```

- Remove a user (also deletes associated projects in all remotes if they are empty):

    ```bash
    figo user delete user-name
    ```

- Remove a user and associated files in the users folder (.pub, .ctr, .pfx, ...):

    ```bash
    figo user delete user-name -r
    ```

- Remove the projects associated with the user even if the user does not exist:

    ```bash
    figo user delete user-name -p
    ```

- Remove the projects and files associated with the user even if the user does not exist:

    ```bash
    figo user delete user-name -rp
    ```
