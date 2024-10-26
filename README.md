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
    - **Description:** List instances, with an option to show detailed profiles.
    - **Syntax:**

      ```bash
      figo instance list [scope] [-f | --full] [-p project] [-r remote]
      ```

    - **Options:**  
      - `-f, --full`: Show full details of instance profiles.
      - `scope`: Define the scope in the format `remote:project` to limit the listing.
      - `-p, --project`: Specify the project name to list instances from.
      - `-r, --remote`: Specify the remote Incus server name.

  - **start**
    - **Description:** Start a specific instance.
    - **Syntax:**

      ```bash
      figo instance start instance_name
      ```

  - **stop**
    - **Description:** Stop a specific instance.
    - **Syntax:**

      ```bash
      figo instance stop instance_name
      ```

  - **set_key**
    - **Description:** Set a public key for a user in an instance.
    - **Syntax:**

      ```bash
      figo instance set_key instance_name key_filename
      ```

  - **set_ip**
    - **Description:** Set a static IP address and gateway for a stopped instance.
    - **Syntax:**

      ```bash
      figo instance set_ip instance_name ip_address gw_address
      ```

#### figo gpu

- **Aliases:** `gp`, `g`
- **Description:** Manage GPUs.
- **Subcommands:**
  - **status**  
    **Description:** Show GPU status.  
    **Syntax:**

    ```bash
    figo gpu status
    ```

  - **list**  
    **Description:** List GPU profiles.  
    **Syntax:**

    ```bash
    figo gpu list
    ```

  - **add**  
    **Description:** Add a GPU profile to a specific instance.  
    **Syntax:**

    ```bash
    figo gpu add instance_name
    ```

  - **remove**  
    **Description:** Remove GPU profiles from a specific instance.  
    **Syntax:**

    ```bash
    figo gpu remove instance_name [--all]
    ```

#### figo profile

- **Aliases:** `pr`, `p`
- **Description:** Manage profiles.
- **Subcommands:**
  - **dump**  
    **Description:** Dump profiles to `.yaml` files.  
    **Syntax:**

    ```bash
    figo profile dump [-a | --all] [profile_name]
    ```

  - **list**  
    **Description:** List profiles and associated instances.  
    **Syntax:**

    ```bash
    figo profile list
    ```

#### figo user

- **Aliases:** `us`, `u`
- **Description:** Manage users.
- **Subcommands:**
  - **list**  
    **Description:** List installed certificates, with an option to show detailed information.  
    **Syntax:**

    ```bash
    figo user list [-f | --full]
    ```

  - **add**  
    **Description:** Add a new user to the system.  
    **Syntax:**

    ```bash
    figo user add username [--cert cert_filename]
    ```

#### figo remote

- **Aliases:** `re`, `r`
- **Description:** Manage remotes.
- **Subcommands:**
  - **list**  
    **Description:** List available remotes, with an option to show detailed information.  
    **Syntax:**

    ```bash
    figo remote list [-f | --full]
    ```

  - **enroll**  
    **Description:** Enroll a remote Incus server.  
    **Syntax:**

    ```bash
    figo remote enroll remote_server ip_address [port] [user] [cert_filename] [--loc_name loc_name]
    ```

    - **Options:**
      - `remote_server`: The name you want to assign to the remote server.
      - `ip_address`: The IP address or domain name of the remote server.
      - `port`: The port number of the remote server (default: 8443).
      - `user`: The SSH username (default: ubuntu).
      - `cert_filename`: The path to the client certificate file (default: `~/.config/incus/client.cr`).
      - `--loc_name`: The local storage name (default: `main`).

#### figo project

- **Description:** Manage projects within the federated testbed.
- **Subcommands:**
  - **list**
    - **Description:** List available projects, optionally specifying a remote or user.
    - **Syntax:**

      ```bash
      figo project list [scope] [--remote remote_name] [--user user_name]
      ```

    - **Options:**  
      - `scope`: Scope in the format `remote:project`, `remote:`, or `project.` to limit the listing.
      - `--remote`: Specify the remote server name.
      - `--user`: Specify a user to filter the projects by ownership.

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
