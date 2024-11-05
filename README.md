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
      - `-f, --full`: Show full details of instance profiles.
      - `scope`: Define the scope in the format `remote:project` to limit the listing.
      - `-p, --project`: Specify the project name to list instances from.
      - `-r, --remote`: Specify the remote Incus server name.
      - `-e, --extend`: Extend column width to fit content.

  - **start**
    - **Description:** Start a specific instance.
    - **Syntax:**

      ```bash
      figo instance start instance_name
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to start. Can include remote and project scope.

  - **stop**
    - **Description:** Stop a specific instance or all instances in a scope.
    - **Syntax:**

      ```bash
      figo instance stop instance_name [-a | --all]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to stop. Can include remote and project scope.
      - `-a, --all`: Stop all instances within the specified scope.

  - **set_key**
    - **Description:** Set a public key for a user in an instance.
    - **Syntax:**

      ```bash
      figo instance set_key instance_name key_filename [-l login] [-d dir] [-f]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance. Can include remote and project scope.
      - `key_filename`: The filename of the public key on the host.
      - `-l, --login`: Specify the login name (default: ubuntu).
      - `-d, --dir`: Specify the directory path where the key file is located (default: ./users).
      - `-f, --force`: Start the instance if not running, then stop it after setting the key.

  - **set_ip**
    - **Description:** Set a static IP address and gateway for a stopped instance.
    - **Syntax:**

      ```bash
      figo instance set_ip instance_name ip_address gw_address [-n nic]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to set the IP address for. Can include remote and project scope.
      - `ip_address`: The static IP address with prefix length (e.g., 192.168.1.10/24).
      - `gw_address`: The gateway address.
      - `-n, --nic`: The NIC name (default: eth0 for containers, enp5s0 for VMs).

  - **create**
    - **Description:** Create a new instance.
    - **Syntax:**

      ```bash
      figo instance create instance_name image [-t type] [-p project] [-r remote]
      ```

    - **Options:**  
      - `instance_name`: The name of the new instance.
      - `image`: Image source to create the instance from (e.g., `images:ubuntu/20.04`).
      - `-t, --type`: Specify the instance type (`vm` or `container`).
      - `-p, --project`: The project under which the instance will be created.
      - `-r, --remote`: Specify the remote Incus server.

  - **delete**
    - **Description:** Delete a specific instance.
    - **Syntax:**

      ```bash
      figo instance delete instance_name [-f]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to delete.
      - `-f, --force`: Force delete the instance even if it is running.

  - **bash**
    - **Description:** Execute bash in a specific instance.
    - **Syntax:**

      ```bash
      figo instance bash instance_name [-f] [-t timeout] [-a attempts]
      ```

    - **Options:**  
      - `instance_name`: The name of the instance to execute bash.
      - `-f, --force`: Start the instance if not running and execute bash.
      - `-t, --timeout`: Total timeout in seconds for retries.
      - `-a, --attempts`: Number of retry attempts to connect.

#### figo gpu

- **Aliases:** `gp`, `g`
- **Description:** Manage GPUs.
- **Subcommands:**
  - **status**
    - **Description:** Show the current status of GPUs, with an option to extend column width.
    - **Syntax:**

      ```bash
      figo gpu status [-e | --extend]
      ```

    - **Options:**
      - `-e, --extend`: Extend column width to fit the content.

  - **list**
    - **Description:** List GPU profiles configured in the system, with an option to extend column width.
    - **Syntax:**

      ```bash
      figo gpu list [-e | --extend]
      ```

    - **Options:**
      - `-e, --extend`: Extend column width to fit the content.

  - **add**
    - **Description:** Add a GPU profile to a specific instance.
    - **Syntax:**

      ```bash
      figo gpu add instance_name
      ```

    - **Options:**
      - `instance_name`: The name of the instance to which the GPU profile will be added.

  - **remove**
    - **Description:** Remove GPU profiles from a specific instance. Optionally, remove all profiles.
    - **Syntax:**

      ```bash
      figo gpu remove instance_name [--all]
      ```

    - **Options:**
      - `instance_name`: The name of the instance from which the GPU profile will be removed.
      - `--all`: Remove all GPU profiles from the specified instance.

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
- **Description:** Manage remotes.
- **Subcommands:**
  - **list**  
    - **Description:** List available remotes, with options to show detailed information and adjust column width to fit content.  
    - **Syntax:**

      ```bash
      figo remote list [-f | --full] [-e | --extend]
      ```

    - **Options:**  
      - `-f, --full`: Show full details of available remotes.
      - `-e, --extend`: Extend column width to fit the content.

  - **enroll**  
    - **Description:** Enroll a remote Incus server.  
    - **Syntax:**

      ```bash
      figo remote enroll remote_server ip_address [port] [user] [cert_filename] [--loc_name loc_name]
      ```

    - **Options:**  
      - `remote_server`: Name to assign to the remote server.
      - `ip_address`: IP address or domain name of the remote server.
      - `port`: Port of the remote server (default: 8443).
      - `user`: Username for SSH into the remote server (default: `ubuntu`).
      - `cert_filename`: Path to the client certificate file (default: `~/.config/incus/client.crt`).
      - `--loc_name`: Suffix of the certificate name saved on the remote server (default: `main`).

    - **Description:**  
      This command allows an administrator to enroll a remote Incus server, setting up a connection that enables the management of resources from a centralized main node in the FIGO system.

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
