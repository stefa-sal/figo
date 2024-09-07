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

-   <span class="title-ref">figo instance</span>
-   <span class="title-ref">figo gpu</span>
-   <span class="title-ref">figo profile</span>
-   <span class="title-ref">figo user</span>
-   <span class="title-ref">figo remote</span>

Each command has its own set of subcommands and options.

**Command and Subcommand Details:**

### figo instance

-   **Aliases:** <span class="title-ref">in</span>, <span
    class="title-ref">i</span>
-   **Description:** Manage instances.
-   **Subcommands:**
    -   **list**
        -   **Description:** List instances, with an option to show
            detailed profiles.

        -   **Syntax:**

            ``` bash
            figo instance list [scope] [-f | --full] [-p project] [-r remote]
            ```

        -   **Options:**  
            -   \`-f, --full\`: Show full details of instance profiles.
            -   \`scope\`: Define the scope in the format <span
                class="title-ref">remote:project</span> to limit the
                listing.
            -   \`-p, --project\`: Specify the project name to list
                instances from.
            -   \`-r, --remote\`: Specify the remote Incus server name.

        -   **Conflict Handling:**  
            -   If <span class="title-ref">scope</span> is provided and
                both the <span class="title-ref">--project</span> and
                <span class="title-ref">--remote</span> options are also
                provided, conflicts are checked:
                -   If the <span class="title-ref">remote</span> in
                    <span class="title-ref">scope</span> conflicts with
                    the <span class="title-ref">--remote</span> option,
                    an error is returned.
                -   If the <span class="title-ref">project</span> in
                    <span class="title-ref">scope</span> conflicts with
                    the <span class="title-ref">--project</span> option,
                    an error is returned.
    -   **start**
        -   **Description:** Start a specific instance.

        -   **Syntax:**

            ``` bash
            figo instance start instance_name
            ```

        -   **Options:**  
            -   \`instance_name\`: Name of the instance to start.
    -   **stop**
        -   **Description:** Stop a specific instance.

        -   **Syntax:**

            ``` bash
            figo instance stop instance_name
            ```

        -   **Options:**  
            -   \`instance_name\`: Name of the instance to stop.
    -   **set_key**
        -   **Description:** Set a public key for a user in an instance.

        -   **Syntax:**

            ``` bash
            figo instance set_key instance_name key_filename
            ```

        -   **Options:**  
            -   \`instance_name\`: Name of the instance.
            -   \`key_filename\`: Filename of the public key on the
                host.
    -   **set_ip**
        -   **Description:** Set a static IP address and gateway for a
            stopped instance.

        -   **Syntax:**

            ``` bash
            figo instance set_ip instance_name ip_address gw_address
            ```

        -   **Options:**  
            -   \`instance_name\`: Name of the instance.
            -   \`ip_address\`: Static IP address to assign.
            -   \`gw_address\`: Gateway address to assign.

### figo gpu

-   **Aliases:** <span class="title-ref">gp</span>, <span
    class="title-ref">g</span>
-   **Description:** Manage GPUs.
-   **Subcommands:**
    -   **status**
        -   **Description:** Show GPU status.

        -   **Syntax:**

            ``` bash
            figo gpu status
            ```
    -   **list**
        -   **Description:** List GPU profiles.

        -   **Syntax:**

            ``` bash
            figo gpu list
            ```
    -   **add**
        -   **Description:** Add a GPU profile to a specific instance.

        -   **Syntax:**

            ``` bash
            figo gpu add instance_name
            ```

        -   **Options:**  
            -   \`instance_name\`: Name of the instance to add the GPU
                profile to.
    -   **remove**
        -   **Description:** Remove GPU profiles from a specific
            instance.

        -   **Syntax:**

            ``` bash
            figo gpu remove instance_name [--all]
            ```

        -   **Options:**  
            -   \`instance_name\`: Name of the instance to remove the
                GPU profile from.
            -   \`--all\`: Remove all GPU profiles from the instance.

### figo profile

-   **Aliases:** <span class="title-ref">pr</span>, <span
    class="title-ref">p</span>
-   **Description:** Manage profiles.
-   **Subcommands:**
    -   **dump**
        -   **Description:** Dump profiles to <span
            class="title-ref">.yaml</span> files.

        -   **Syntax:**

            ``` bash
            figo profile dump [-a | --all] [profile_name]
            ```

        -   **Options:**  
            -   \`-a, --all\`: Dump all profiles to <span
                class="title-ref">.yaml</span> files.
            -   \`profile_name\`: Name of the profile to dump.

        -   **Notes:**  
            -   If neither <span class="title-ref">--all</span> nor
                <span class="title-ref">profile_name</span> is provided,
                an error message is displayed.
    -   **list**
        -   **Description:** List profiles and associated instances.

        -   **Syntax:**

            ``` bash
            figo profile list
            ```

### figo user

-   **Aliases:** <span class="title-ref">us</span>, <span
    class="title-ref">u</span>
-   **Description:** Manage users.
-   **Subcommands:**
    -   **list**
        -   **Description:** List installed certificates, with an option
            to show detailed information.

        -   **Syntax:**

            ``` bash
            figo user list [-f | --full]
            ```

        -   **Options:**  
            -   \`-f, --full\`: Show full details of installed
                certificates.
    -   **add**
        -   **Description:** Add a new user to the system.

        -   **Syntax:**

            ``` bash
            figo user add username [--cert cert_filename]
            ```

        -   **Options:**  
            -   \`username\`: Username of the new user.
            -   \`--cert\`: Path to the user's certificate file
                (optional).

### figo remote

-   **Aliases:** <span class="title-ref">re</span>, <span
    class="title-ref">r</span>
-   **Description:** Manage remotes.
-   **Subcommands:**
    -   **list**
        -   **Description:** List available remotes, with an option to
            show detailed information.

        -   **Syntax:**

            ``` bash
            figo remote list [-f | --full]
            ```

        -   **Options:**  
            -   \`-f, --full\`: Show full details of available remotes.
    -   **enroll**
        -   **Description:** Enroll a remote Incus server.

        -   **Syntax:**

            ``` bash
            figo remote enroll remote_server ip_address [port] [user] [cert_filename] [--loc_name loc_name]
            ```

        -   **Options:**  
            -   \`remote_server\`: Name to assign to the remote server.
            -   \`ip_address\`: IP address or domain name of the remote
                server.
            -   \`port\`: Port of the remote server (default: 8443).
            -   \`user\`: Username for SSH (default: ubuntu).
            -   \`cert_filename\`: Client certificate file to transfer
                (default: <span
                class="title-ref">\~/.config/incus/client.cr</span>).
            -   \`--loc_name\`: Name to use for local storage (default:
                main).

## Autocompletion:

The CLI supports autocompletion using the <span
class="title-ref">argcomplete</span> library, which must be installed
and configured to enable this feature.

## Examples

-   List all instances in a specific project:

    ``` bash
    figo instance list myproject
    ```

-   Start an instance named \`test-instance\`:

    ``` bash
    figo instance start test-instance
    ```

-   Add a GPU profile to an instance:

    ``` bash
    figo gpu add test-instance
    ```

-   Enroll a remote Incus server:

    ``` bash
    figo remote enroll my-remote-server 192.168.1.10 8443 myuser ~/.config/incus/client.cr --loc_name backup
    ```

-   Add a user, generating browser client certificate:

    ``` bash
    figo user add user-name --email user@email.com --name "Name of User" --org "User organization"
    ```

-   Remove a user (also deletes associated projects in all remotes if they are empty):

    ``` bash
    figo user delete user-name 
    ```

-   Remove a user, its projects in all remotes and the files associated with the user in the users folder (.pub, .ctr, .pfx, ...)

    ``` bash
    figo user delete user-name -r 

-   Remove the projects associated with the user even if the user does not exist

    ``` bash
    figo user delete user-name -p 
    ```
    ```

-   Remove the projects and the files associated with the user even if the user does not exist

    ``` bash
    figo user delete user-name -rp 
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

-   **Incus:** FIGO uses Incus for container and VM management.
-   **pylxd:** Python client library for LXD/Incus.
-   **Subprocess Module:** Used for running shell commands.

Thank you to the open-source community for providing the tools and
libraries that make this project possible.
