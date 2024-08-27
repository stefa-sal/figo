Main Command-Line Interface Documentation
=========================================

**Description:**

This module provides a command-line interface (CLI) to manage a federated testbed with CPUs and GPUs. The `figo` program offers various commands and subcommands for managing instances, GPUs, profiles, users, and remotes in a federated environment.

**Usage:**

.. code-block:: bash

    figo [command] [subcommand] [options]

**Commands:**

- `instance`
- `gpu`
- `profile`
- `user`
- `remote`

Each command has its own set of subcommands and options.

**Command and Subcommand Details:**

figo instance 
----------------

- **Aliases:** `in`, `i`
- **Description:** Manage instances.

- **Subcommands:**

  - **list**

    - **Description:** List instances, with an option to show detailed profiles.
    - **Syntax:**

      .. code-block:: bash

          figo instance list [scope] [-f | --full] [-p project] [-r remote]

    - **Options:**
        - `-f, --full`: Show full details of instance profiles.
        - `scope`: Define the scope in the format `remote:project` to limit the listing.
        - `-p, --project`: Specify the project name to list instances from.
        - `-r, --remote`: Specify the remote Incus server name.
    - **Conflict Handling:**
        - If `scope` is provided and both the `--project` and `--remote` options are also provided, conflicts are checked:
          - If the `remote` in `scope` conflicts with the `--remote` option, an error is returned.
          - If the `project` in `scope` conflicts with the `--project` option, an error is returned.

  - **start**

    - **Description:** Start a specific instance.
    - **Syntax:**

      .. code-block:: bash

          figo instance start instance_name

    - **Options:**
        - `instance_name`: Name of the instance to start.

  - **stop**

    - **Description:** Stop a specific instance.
    - **Syntax:**

      .. code-block:: bash

          figo instance stop instance_name

    - **Options:**
        - `instance_name`: Name of the instance to stop.

  - **set_key**

    - **Description:** Set a public key for a user in an instance.
    - **Syntax:**

      .. code-block:: bash

          figo instance set_key instance_name key_filename

    - **Options:**
        - `instance_name`: Name of the instance.
        - `key_filename`: Filename of the public key on the host.

  - **set_ip**

    - **Description:** Set a static IP address and gateway for a stopped instance.
    - **Syntax:**

      .. code-block:: bash

          figo instance set_ip instance_name ip_address gw_address

    - **Options:**
        - `instance_name`: Name of the instance.
        - `ip_address`: Static IP address to assign.
        - `gw_address`: Gateway address to assign.

figo gpu
-----------

- **Aliases:** `gp`, `g`
- **Description:** Manage GPUs.

- **Subcommands:**

  - **status**

    - **Description:** Show GPU status.
    - **Syntax:**

      .. code-block:: bash

          figo gpu status

  - **list**

    - **Description:** List GPU profiles.
    - **Syntax:**

      .. code-block:: bash

          figo gpu list

  - **add**

    - **Description:** Add a GPU profile to a specific instance.
    - **Syntax:**

      .. code-block:: bash

          figo gpu add instance_name

    - **Options:**
        - `instance_name`: Name of the instance to add the GPU profile to.

  - **remove**

    - **Description:** Remove GPU profiles from a specific instance.
    - **Syntax:**

      .. code-block:: bash

          figo gpu remove instance_name [--all]

    - **Options:**
        - `instance_name`: Name of the instance to remove the GPU profile from.
        - `--all`: Remove all GPU profiles from the instance.

figo profile
---------------

- **Aliases:** `pr`, `p`
- **Description:** Manage profiles.

- **Subcommands:**

  - **dump**

    - **Description:** Dump profiles to `.yaml` files.
    - **Syntax:**

      .. code-block:: bash

          figo profile dump [-a | --all] [profile_name]

    - **Options:**
        - `-a, --all`: Dump all profiles to `.yaml` files.
        - `profile_name`: Name of the profile to dump.
    - **Notes:**
        - If neither `--all` nor `profile_name` is provided, an error message is displayed.

  - **list**

    - **Description:** List profiles and associated instances.
    - **Syntax:**

      .. code-block:: bash

          figo profile list

figo user
------------

- **Aliases:** `us`, `u`
- **Description:** Manage users.

- **Subcommands:**

  - **list**

    - **Description:** List installed certificates, with an option to show detailed information.
    - **Syntax:**

      .. code-block:: bash

          figo user list [-f | --full]

    - **Options:**
        - `-f, --full`: Show full details of installed certificates.

  - **add**

    - **Description:** Add a new user to the system.
    - **Syntax:**

      .. code-block:: bash

          figo user add username [--cert cert_filename]

    - **Options:**
        - `username`: Username of the new user.
        - `--cert`: Path to the user's certificate file (optional).

figo remote
--------------

- **Aliases:** `re`, `r`
- **Description:** Manage remotes.

- **Subcommands:**

  - **list**

    - **Description:** List available remotes, with an option to show detailed information.
    - **Syntax:**

      .. code-block:: bash

          figo remote list [-f | --full]

    - **Options:**
        - `-f, --full`: Show full details of available remotes.

  - **enroll**

    - **Description:** Enroll a remote Incus server.
    - **Syntax:**

      .. code-block:: bash

          figo remote enroll remote_server ip_address [port] [user] [cert_filename] [--loc_name loc_name]

    - **Options:**
        - `remote_server`: Name to assign to the remote server.
        - `ip_address`: IP address or domain name of the remote server.
        - `port`: Port of the remote server (default: 8443).
        - `user`: Username for SSH (default: ubuntu).
        - `cert_filename`: Client certificate file to transfer (default: `~/.config/incus/client.cr`).
        - `--loc_name`: Name to use for local storage (default: main).

**Autocompletion:**

The CLI supports autocompletion using the `argcomplete` library, which must be installed and configured to enable this feature.

**Examples:**

- List all instances in a specific project:

  .. code-block:: bash

      figo instance list myproject

- Start an instance named `test-instance`:

  .. code-block:: bash

      figo instance start test-instance

- Add a GPU profile to an instance:

  .. code-block:: bash

      figo gpu add test-instance

- Enroll a remote Incus server:

  .. code-block:: bash

      figo remote enroll my-remote-server 192.168.1.10 8443 myuser ~/.config/incus/client.cr --loc_name backup
