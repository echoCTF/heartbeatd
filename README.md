# heartbeatd

A small OpenBSD daemon that watches a pflog interface and notes in memcached which IP addresses are being talked to.

We use it in [echoCTF](https://github.com/echoCTF/echoCTF.RED) to tell whether an on-demand target is still in use. If nobody has touched it for a while, the platform shuts it down.

## How it works

pf logs matching packets to a pflog interface. heartbeatd reads that interface and, for every packet it sees, sets this key in memcached:

```
target_heartbeat:<destination ip>
```

The key expires after an hour by default. If the key exists, somebody reached that IP recently. If it is gone, nobody did. Only the destination address is stored, and only for IPv4.

## Requirements

* OpenBSD
* libmemcached and libpcap
* a running memcached
* root to start it (it drops to an unprivileged user right after opening the interface)

Per-packet lines from `-v` go to syslog at `daemon.debug`, which the default `/etc/syslog.conf` discards. Add a `daemon.debug` (or `!heartbeatd` program block) line there if you want to keep them.

## Build and install

```
make
install -c -s -o root -g bin -m 555 heartbeatd /usr/local/sbin/heartbeatd
install -c -o root -g wheel -m 555 heartbeatd.rc /etc/rc.d/heartbeatd
```

## Usage

```
heartbeatd [-Dv] [-l pflog_interface] [-u user] [-s socket] [-t wait_timeout] [-f pcap filter]
```

| Flag | What it does | Default |
|------|--------------|---------|
| `-s` | memcached unix socket, absolute path | `/var/run/memcached/memcached.sock` |
| `-l` | pflog interface to read | `pflog0` |
| `-u` | user to drop privileges to | `_memcached` |
| `-t` | seconds a key lives in memcached | `3600` |
| `-f` | pcap filter | TCP SYN, UDP and ICMP over IPv4 |
| `-D` | stay in the foreground and log to stderr, including every packet | off |
| `-v` | log every packet seen (to syslog at `daemon.debug`, or stderr with `-D`) | off |

## Example

Send the traffic you care about to a pflog interface in pf.conf:

```
match log (to pflog2) inet from <offense_activated> to <heartbeat>
```

Then run the daemon against it:

```
heartbeatd -l pflog2 -s /var/run/memcached/memcached.sock -u _memcached
```

Or let rc manage it:

```
rcctl enable heartbeatd
rcctl set heartbeatd flags -l pflog2 -s /var/run/memcached/memcached.sock -u _memcached
rcctl start heartbeatd
```

## Credits

Based on OpenBSD's spamlogd. The original copyright notices are kept in `heartbeatd.c`.
