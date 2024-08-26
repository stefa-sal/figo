# FIGO - Federated Infrastructure for GPU Orchestration

FIGO is a tool for managing federated testbed with CPUs and GPUs. It provides
commands to handle instances (VMs and contariners) and GPU profiles. 

# Usage

FIGO provides various commands to manage VM and container instances and GPU profiles.
Below is a detailed guide on how to use these commands.

## General Usage

When the script is called with no command parameters, the general usage
information is displayed.

``` bash
figo
```

## Commands

**Description:**

This module provides a command-line interface (CLI) to manage a
federated testbed with CPUs and GPUs. The <span
class="title-ref">figo</span> program offers various commands and
subcommands for managing instances, GPUs, profiles, users, and remotes
in a federated environment.

**Usage:**

``` bash
figo [command] [subcommand] [options]
```

**Commands:**

-   <span class="title-ref">instance</span>
-   <span class="title-ref">gpu</span>
-   <span class="title-ref">profile</span>
-   <span class="title-ref">user</span>
-   <span class="title-ref">remote</span>

Each command has its own set of subcommands and options.

**Command and Subcommand Details:**

1.  **Instance Command**  
    -   **Aliases:** <span class="title-ref">in</span>, <span
        class="title-ref">i</span>
    -   **Description:** Manage instances.
    -   **Subcommands:**
        1.  **list**  
            -   **Description:** List instances, with an option to show
                detailed profiles.

            -   **Syntax:** .. code-block:: bash figo instance list
                \[scope\] \[-f \| --full\] \[-p project\] \[-r remote\]

            -   **Options:**  
                -   \`-f, --full\`: Show full details of instance
                    profiles.
                -   \`scope\`: Define the scope in the format <span
                    class="title-ref">remote:project</span> to limit the
                    listing.
                -   \`-p, --project\`: Specify the project name to list
                    instances from.
                -   \`-r, --remote\`: Specify the remote Incus server
                    name.

            -   **Conflict Handling:**  
                -   If <span class="title-ref">scope</span> is provided and both the <span class="title-ref">--project</span> and <span class="title-ref">--remote</span> options are also provided, conflicts are checked:  
                    -   If the <span class="title-ref">remote</span> in
                        <span class="title-ref">scope</span> conflicts
                        with the <span class="title-ref">--remote</span>
                        option, an error is returned.
                    -   If the <span class="title-ref">project</span> in
                        <span class="title-ref">scope</span> conflicts
                        with the <span
                        class="title-ref">--project</span> option, an
                        error is returned.

        2.  **start**  
            -   **Description:** Start a specific instance.

            -   **Syntax:** .. code-block:: bash figo instance start
                instance_name

            -   **Options:**  
                -   \`instance_name\`: Name of the instance to start.

        3.  **stop**  
            -   **Description:** Stop a specific instance.

            -   **Syntax:** .. code-block:: bash figo instance stop
                instance_name

            -   **Options:**  
                -   \`instance_name\`: Name of the instance to stop.

        4.  **set_key**  
            -   **Description:** Set a public key for a user in an
                instance.

            -   **Syntax:** .. code-block:: bash figo instance set_key
                instance_name key_filename

            -   **Options:**  
                -   \`instance_name\`: Name of the instance.
                -   \`key_filename\`: Filename of the public key on the
                    host.

        5.  **set_ip**  
            -   **Description:** Set a static IP address and gateway for
                a stopped instance.

            -   **Syntax:** .. code-block:: bash figo instance set_ip
                instance_name ip_address gw_address

            -   **Options:**  
                -   \`instance_name\`: Name of the instance.
                -   \`ip_address\`: Static IP address to assign.
                -   \`gw_address\`: Gateway address to assign.

2.  **GPU Command**  
    -   **Aliases:** <span class="title-ref">gp</span>, <span
        class="title-ref">g</span>
    -   **Description:** Manage GPUs.
    -   **Subcommands:**
        1.  **status**  
            -   **Description:** Show GPU status.
            -   **Syntax:** .. code-block:: bash figo gpu status

        2.  **list**  
            -   **Description:** List GPU profiles.
            -   **Syntax:** .. code-block:: bash figo gpu list

        3.  **add**  
            -   **Description:** Add a GPU profile to a specific
                instance.

            -   **Syntax:** .. code-block:: bash figo gpu add
                instance_name

            -   **Options:**  
                -   \`instance_name\`: Name of the instance to add the
                    GPU profile to.

        4.  **remove**  
            -   **Description:** Remove GPU profiles from a specific
                instance.

            -   **Syntax:** .. code-block:: bash figo gpu remove
                instance_name \[--all\]

            -   **Options:**  
                -   \`instance_name\`: Name of the instance to remove
                    the GPU profile from.
                -   \`--all\`: Remove all GPU profiles from the
                    instance.

3.  **Profile Command**  
    -   **Aliases:** <span class="title-ref">pr</span>, <span
        class="title-ref">p</span>
    -   **Description:** Manage profiles.
    -   **Subcommands:**
        1.  **dump**  
            -   **Description:** Dump profiles to <span
                class="title-ref">.yaml</span> files.

            -   **Syntax:** .. code-block:: bash figo profile dump \[-a
                \| --all\] \[profile_name\]

            -   **Options:**  
                -   \`-a, --all\`: Dump all profiles to <span
                    class="title-ref">.yaml</span> files.
                -   \`profile_name\`: Name of the profile to dump.

            -   **Notes:**  
                -   If neither <span class="title-ref">--all</span> nor
                    <span class="title-ref">profile_name</span> is
                    provided, an error message is displayed.

        2.  **list**  
            -   **Description:** List profiles and associated instances.
            -   **Syntax:** .. code-block:: bash figo profile list

4.  **User Command**  
    -   **Aliases:** <span class="title-ref">us</span>, <span
        class="title-ref">u</span>
    -   **Description:** Manage users.
    -   **Subcommands:**
        1.  **list**  
            -   **Description:** List installed certificates, with an
                option to show detailed information.

            -   **Syntax:** .. code-block:: bash figo user list \[-f \|
                --full\]

            -   **Options:**  
                -   \`-f, --full\`: Show full details of installed
                    certificates.

        2.  **add**  
            -   **Description:** Add a new user to the system.

            -   **Syntax:** .. code-block:: bash figo user add username
                \[--cert cert_filename\]

            -   **Options:**  
                -   \`username\`: Username of the new user.
                -   \`--cert\`: Path to the user's certificate file
                    (optional).

5.  **Remote Command**  
    -   **Aliases:** <span class="title-ref">re</span>, <span
        class="title-ref">r</span>
    -   **Description:** Manage remotes.
    -   **Subcommands:**
        1.  **list**  
            -   **Description:** List available remotes, with an option
                to show detailed information.

            -   **Syntax:** .. code-block:: bash figo remote list \[-f
                \| --full\]

            -   **Options:**  
                -   \`-f, --full\`: Show full details of available
                    remotes.

        2.  **enroll**  
            -   **Description:** Enroll a remote Incus server.

            -   **Syntax:** .. code-block:: bash figo remote enroll
                remote_server ip_address \[port\] \[user\]
                \[cert_filename\] \[--loc_name loc_name\]

            -   **Options:**  
                -   \`remote_server\`: Name to assign to the remote
                    server.
                -   \`ip_address\`: IP address or domain name of the
                    remote server.
                -   \`port\`: Port of the remote server (default: 8443).
                -   \`user\`: Username for SSH (default: ubuntu).
                -   \`cert_filename\`: Client certificate file to
                    transfer (default: <span
                    class="title-ref">\~/.config/incus/client.cr</span>).
                -   \`--loc_name\`: Name to use for local storage
                    (default: main).

**Autocompletion:**

The CLI supports autocompletion using the <span
class="title-ref">argcomplete</span> library, which must be installed
and configured to enable this feature.

**Examples:**

1.  List all instances in a specific project:

    ``` bash
    figo instance list myproject
    ```

2.  Start an instance named \`test-instance\`:

    ``` bash
    figo instance start test-instance
    ```

3.  Add a GPU profile to an instance:

    ``` bash
    figo gpu add test-instance
    ```

4.  Enroll a remote Incus server:

    ``` bash
    figo remote enroll my-remote-server 192.168.1.10 8443 myuser ~/.config/incus/client.cr --loc_name backup
    ```


# Contributing

We welcome contributions to FIGO. To contribute, please follow these
steps:

1.  **Fork the Repository:** Create your own fork of the repository on
    GitHub.
2.  **Create a Branch:** Create a new branch for your feature or bug
    fix.
3.  **Make Changes:** Make your changes in your branch.
4.  **Submit a Pull Request:** Submit a pull request with a description
    of your changes.

Please ensure that your code adheres to the project's coding style and
includes appropriate tests.

# License

FIGO is licensed under the MIT License. See the <span
class="title-ref">LICENSE</span> file for details.

# Acknowledgements

-   **LXD:** FIGO uses LXD for container management.
-   **pylxd:** Python client library for LXD.
-   **Subprocess Module:** Used for running shell commands.

Thank you to the open-source community for providing the tools and
libraries that make this project possible.
