# FIGO - Federated Infrastructure for GPU Orchestration

FIGO is a tool for managing LXD instances and GPU profiles. It provides
commands to handle instances and GPU profiles, including showing
information, starting and stopping instances, and managing GPU profiles.

# Usage

FIGO provides various commands to manage LXD instances and GPU profiles.
Below is a detailed guide on how to use these commands.

## General Usage

When the script is called with no command parameters, the general usage
information is displayed.

``` bash
python figo.py
```

## Commands

### show

The `show` command provides information about instances and their
profiles.

``` bash
python figo.py show
```

If called with no subcommand, the subcommands are displayed.

``` bash
python figo.py show profile
```

Displays instance profiles.

``` bash
python figo.py show gpu
```

Displays GPU profiles.

### stop

Stops a specific instance.

``` bash
python figo.py stop <instance_name>
```

### start

Starts a specific instance.

``` bash
python figo.py start <instance_name>
```

### gpu

Provides GPU-related information.

``` bash
python figo.py gpu
```

If called with no subcommand, the subcommands are displayed.

``` bash
python figo.py gpu status
```

Shows the status of GPUs.

``` bash
python figo.py gpu list
```

Lists all GPU profiles.

### add_gpu

Adds a GPU profile to a specific instance.

``` bash
python figo.py add_gpu <instance_name>
```

### remove_gpu

Removes a GPU profile from a specific instance.

``` bash
python figo.py remove_gpu <instance_name>
```

### remove_gpu_all

Removes all GPU profiles from a specific instance.

``` bash
python figo.py remove_gpu_all <instance_name>
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
