NOTE content is from https://www.pierov.org/2014/11/17/python-ssh-tunnel-server/

Imported into git, available at https://github.com/clach04/python-ssh-tunnel-server

# [Python SSH Tunnel Server](https://www.pierov.org/2014/11/17/python-ssh-tunnel-server/ "Python SSH Tunnel Server")

Piero V.


SSH tunnels are great!

They allow to bypass firewalls and NAT problems, and you can use as unprivileged user, since you don’t have to install virtual network devices such as TUN or TAP.

Another good reason to chose SSH is that it is a standard protocol, so there are many implementations: OpenSSH on most Unices, PuTTY on Windows and cross platform libraries (Java, Python…).

However there is a great disadvantage: the SSH server. If you have a server you probably already use SSH, therefore you don’t want to share your custom port and grant access to your server, or create accounts to allow it.

A solution could be creating a chroot or something like that, but I wasn’t really confident in it, therefore I looked for an alternative SSH server, and I’ve come up with this library: _TunnelServer_.

Python already has a brilliant SSH library: Paramiko. It’s very transparent: it manages the packages for you, but you are the one who should manage the rest (login check, shell comunication, PTY allocation…, socket-ssh channel synchronization). That’s great, but sometimes unhandy, so I’ve written this class, which is a middleware: the class user still has to check login, but you don’t have to create threads to listen on forwards etc…<a id="readmore-entry141117-120308"></a>

I’ve included a demo server in the archive (`server.py`). The core is the class `Server`. As you can see you just have to check logins with `check_auth_password` or `check_auth_publickey` and tell your auth methods with `get_allowed_auths` and you have a SSH server which will accept logins, allow port forwarding and direct TCP connections, but won’t have an interactive shell.

You can allow or deny forwardings and direct connections by overriding two methods: `check_forward_address` and `check_direct`. By default they allow everything.

You can change the “sorry, we have not shell access” by overriding the variable `no_shell`.

All Paramiko abilities are kept: you can implement your own shell, or SFTP server etc… But please mind some things:

*   You need to save the session channel. My class saves it in a member. If you don’t do it, Python garbage collector will delete the channel and your session will suddenly close. This is a difficult bug to catch.
*   For forwardings, you can’t know the original address, but only the one which you have to listen to. Port 0 means that the server will chose the port. If you don’t like the port that you were asked for, you can’t change, you can only deny access.
*   TunnelServer needs the paramiko.Transport which manages the current connection.

`server.py` contains other parts, such as listening for SSH connections, but I invite you to read the code, I tried to comment it very much.

This topic is very interesing and I’ve learnt very much about SSH, so if you are interested in this protocol, I advise you to work with paramiko and to look at RFC4254 (_Secure Shell Protocol_) to understand darkest parts of the code.

TunnelServer is based on Paramiko and Paramiko demos, so it’s released under GNU LGPL 2.1 (please refer to `LICENSE` file).

You can download from here: [tunnelserver.tar.gz](https://www.pierov.org/media/attachs/tunnelserver.tar.gz).
