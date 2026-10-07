(credentials)=

# Passing Credentials Safely

```{versionadded} 26.0.8
```

Passing a password as a command line argument exposes it to every other user
of the machine. On Linux the command line of a running process is world
readable through {command}`ps` and {file}`/proc/<pid>/cmdline`, on Windows it
is shown by the task manager and by
{code}`Get-CimInstance Win32_Process`. On top of that the shell records the
whole command in its history file.

{program}`gvm-tools` therefore offers three ways to hand over a password
without putting it on the command line. They are available for the
{term}`GMP` credentials of all tools and for the SSH credentials of the
{ref}`ssh connection type <ssh-connection-type>`.

## Reading the password from a file

```shell
gvm-cli --gmp-username user --gmp-password-file ~/.gmp-password \
    ssh --hostname myappliance --ssh-password-file ~/.ssh-password \
    --xml "<get_version/>"
```

The file must contain the password on the first line, a trailing newline is
ignored. A warning is printed when the file is readable by other users, so
restrict it with {command}`chmod 600`.

A single dash reads the password from standard input, which is convenient
when it comes from a password manager:

```shell
pass show greenbone/appliance | gvm-cli ssh --hostname myappliance \
    --ssh-password-file - --xml "<get_version/>"
```

## Reading the password from the environment

```shell
export GVMTOOLS_GMP_PASSWORD=secret
export GVMTOOLS_SSH_PASSWORD=secret
gvm-cli --gmp-username user ssh --hostname myappliance --xml "<get_version/>"
```

The environment of a process is only readable by its owner and by root,
unlike the command line. The variables take precedence over the password in
the {ref}`configuration file <config>` and are overridden by an explicit
command line argument.

## Asking for the password on the terminal

```shell
gvm-cli --gmp-username user --gmp-password-prompt \
    ssh --hostname myappliance --ssh-password-prompt --xml "<get_version/>"
```

The password is read without echoing it. The SSH password is asked for
first, followed by the GMP password.

## What happens when a credential is passed as an argument

{command}`--gmp-password` and {command}`--ssh-password` keep working. As soon
as the arguments have been parsed, {program}`gvm-tools` overwrites the
credentials in the command line of the running process, so that they are no
longer visible to anything that inspects the process afterwards. The user
name is masked as well, because it is half of a credential:

```
$ ps -o args= -p 12345
gvm-cli --gmp-username ******** --gmp-password ******** ssh --hostname myappliance
```

On Windows the same is done by rewriting the command line in the process
environment block, which is where the task manager and
{code}`Win32_Process.CommandLine` read it from.

Two limitations are worth knowing:

- There is a short window between the start of the process and the moment
  the arguments are parsed, roughly a tenth of a second, in which the
  password is still visible. The methods above do not have this window.
- The shell history is written by the shell, not by {program}`gvm-tools`,
  and still contains the password.

## Log output

Credentials are removed from the log output of all {program}`gvm-tools`
programs, including the parsed arguments that are written with
{command}`--log DEBUG` and the {code}`<username>` and {code}`<password>`
elements of GMP requests. This also covers the log output of the underlying
{program}`python-gvm` and {program}`paramiko` libraries.

The same applies to {command}`--help`: the user name and the password from
the {ref}`configuration file <config>` are no longer printed as the default
value of the corresponding option.
