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
This module provides a command-line interface (CLI) to manage a federated testbed with CPUs and GPUs. The `figo` program offers various commands and subcommands for managing instances, GPUs, profiles, users, and remotes in a federated environment.

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

    ### Options:
    - `remote_server`: The name you want to assign to the remote server.
    - `ip_address`: The IP address or domain name of the remote server.
    - `port`: The port number of the remote server (default: 8443).
    - `user`: The SSH username (default: ubuntu).
    - `cert_filename`: The path to the client certificate file (default: `~/.config/incus/client.cr`).
    - `--loc_name`: The local storage name (default: `main`).

    This command allows an administrator to enroll a remote Incus server, setting up a connection that enables the management of resources from a centralized main node in the FIGO system.


## Autocompletion

The CLI supports autocompletion using the `argcomplete` library, which must be installed and configured to enable this feature.

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

## Contributing

We welcome contributions to FIGO. To contribute, please follow these steps:

1. **Fork the Repository:** Create your own fork of the repository on GitHub.
2. **Create a Branch:** Create a new branch for your feature or bug fix.
3. **Make Changes:** Make your changes in your branch.
4. **Submit a Pull Request:** Submit a pull request with a description of your changes.

Please ensure that your code adheres to the project's coding style and includes appropriate tests.

## License

FIGO is licensed under the Apache 2.0 License. See the `LICENSE` file for details.

## Acknowledgements

- **Incus:** FIGO uses Incus for container and VM management.
- **pylxd:** Python client library for LXD/Incus.
- **Subprocess Module:** Used for running shell commands.

Thanks to the open-source community for providing the tools and libraries that make this project possible.
