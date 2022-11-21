# PicoDAV

## Single-file WebDAV server in PHP, just drop it in a directory!

If you drop the [`index.php`](./index.php) file in a directory of your web-server, it will make the contents of this directory available via WebDAV, and will also provide a nice web UI to manage the files, using [WebDAV Manager.js](https://github.com/kd2org/webdav-manager.js).

![Web UI screenshot](https://raw.githubusercontent.com/kd2org/webdav-manager.js/main/scr_desktop.png)

## WebDAV clients

You can use any WebDAV client, but we recommend these:

* Windows/OSX: [CyberDuck](https://cyberduck.io/download/)
* Linux: Any file manager should be able to connect to WebDAV (Dolphin, Thunar, Nautilus, etc.), but you can also use [FUSE webdavfs](https://github.com/miquels/webdavfs)
* Android: [RCX](https://f-droid.org/en/packages/io.github.x0b.rcx/) and [DAVx⁵](https://www.davx5.com/), see [the manual](https://manual.davx5.com/webdav_mounts.html)

## Install

It's really as simple as it says: just upload the `index.php` to a directory on your web-server, and it will now be available via WebDAV.

If you are using Apache (version 2.3.9 or later is required), a .htaccess file will be created if it does not exist, to redirect requests to `index.php`. If not, you can use 

The only requirement is PHP 7.4, or more recent (8.0 and 8.1 are also supported, not tested with PHP 8.2).

Note that by default, write access is disabled for security purposes. See below to enable write access.

### Other web servers than Apache

This is designed to work best with Apache web servers. If you are using another web server, you'll have to adapt the rules described in `.htaccess` to your own server.

### Configuration

PicoDAV accepts a configuration file named `.picodav.ini`.

It should be in the same directory as `index.php`.

### Users and passwords

By default, the WebDAV server is accessible to everyone.

You can disable anonymous access by writing the following line inside `.picodav.ini`:

```
ANONYMOUS_READ = false
```

Then you need to create user accounts, for that add a new section to `.picodav.ini` for each user. For example if we want to give write access to a user named `greta`:

```
[greta]
password = verySecret
write = true
```

Note that PicoDAV will replace this password with an encrypted version the next time it is accessed, don't worry about that, this is for extra safety, just in case the `.picodav.ini` is accessed by a hacker if you made mistake in your web server configuration.

Here is an example of the password once it has been encrypted:

```
password = '$2y$10$fbdabTjNPN3gMAUlaSEoR.kKHLnh0yMGneuJ7P2AOhSSNr8gUaCPu'
```

Of course you can also only give a read access to this user by changing the `write` line to:

```
write = false
```

All users have read access to everything by default.

#### Restricting users to some directories

You can also limit users in which directories and files they can access by using the `restrict` and `restrict_write` configuration directives:

```
[emusk]
password = youSuck
write = false
restrict[] = 'kill-twitter/'

[pouyane]
password = youArePaidWayTooMuch
write = false
restrict[] = 'total/'
restrict_write[] = 'total/kill-the-planet/'
```

### Allow unrestricted access to everyone

This will allow anonymous visitors to read and write to all the files:

```
ANONYMOUS_READ = true
ANONYMOUS_WRITE = true
```

Please note: if you do this, **EVERYONE** visiting your PicoDAV URL will be able to edit, delete or create files!

### Other notes

If you don't want to use the included users feature, you can also restrict access by using a [`.htpasswd` Apache file](https://www.cyberciti.biz/faq/create-update-user-authentication-files/).

For security purposes, the WebDAV server will not allow to read or delete UNIX hidden files (with the file name beginning with a dot, eg. `.htaccess` etc.).

Access to PHP files is also disabled for the same reasons.

## Dependencies

This software includes the KD2\WebDAV class from the [KD2FW package](https://fossil.kd2.org/kd2fw/).

It is a lightweight and easy to use library, designed to to add support for WebDAV and NextCloud clients to your software.

Contact us for a commercial license.

## Author

BohwaZ. Contact me on: Web: https://bohwaz.net / IRC = bohwaz@irc.libera.chat / Mastodon = https://mamot.fr/@bohwaz

## License

This software and its dependencies are available in open source with the AGPL v3 license. This requires you to share all your source code if you include this in your software. This is voluntary.

For entities wishing to use this software or libraries in a project where you don't want to have to publish all your source code, we can also sell this software with a commercial license, contact me at bohwaz at kd2 dot org. We can do that as we wrote and own 100% of the source code, dependencies included, there is no third-party code here.
