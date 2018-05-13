# very-easy-rsa
This is a OpenVPN frontend, which makes it ridiculously easy to setup and manage a OpenVPN server.

**IMPORTANT** I tested it on Debian 9 only.

## Install
To install this script, clone the repository:

`git clone https://github.com/denialofsandwich/very-easy-rsa.git`

Execute `setup.sh` and edit the new configuration located in `/etc/versa/config.sh`

If everything is properly configured, install OpenVPN with:

`versa install`

This process is completely automated and should take some time.
After that, you should restart your session to take advantage of the bash-completion feature.

## Adding and removing users

Adding a new user is fairly easy:

`versa useradd peter`

Just enter a password, an optional IP and the permissions that should be granted to the user.
Take the following groups if the user should be an admin: `gateway,admin` //Note that there are no whitespaces in between!
And just take `gateway` if it is a standard user.

To remove an existing user:

`versa userdel peter`

## Groupsystem (target-groups and access-groups)
versa can handle VLAN and custom vpn-configs via a groupsystem.
You can define your own groups in your configuration file.

### Access-group
Access-groups grant permissions to a user.
Example: If a user is in the access-group `gateway`, it now has permissions to access the internet via the VPN.

The following default access-groups are available:
 * gateway (Grants permissions to reach the internet via VPN)
 * admin (Grants permissions to reach everything in the VPN (excluding the gateway))
 * server (Grants permissions to reach everything on the vpn-server)
 * gaming (Everyone who is in the access-group gaming, can reach every client who is in the target-group gaming)
 * infrastructure (same as gaming)

### Target-groups
Target-groups are used to mark a collective of clients.
Example:

| User          | Access    | Target  |
| ------------- |:---------:| -----:  |
| Tom           | gaming    | gaming  |
| James         | gaming    |         |
| Paul          |           | gaming  |

 * Tom can reach Paul
 * James can reach Tom and Paul
 * Paul cannot reach anyone


## Need more information?
Just type `versa` in the terminal to get a list of all available commands.
