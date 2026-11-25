# Ordryx Bridge

## 0.3.1

The installer names its release by its tag and checks the files by their own
hash, so `curl -fsSL https://get.ordryx.com/bridge | sh` installs exactly what
was released. Nothing else changes.

## 0.3.0

The first release: pairs with an Ordryx by a code or by being found on the
network, carries its calls to Moonraker printers this computer may reach
(status, history, camera pictures; pause, resume, cancel), looks for printers
when asked, and serves live video on the network once it has a certificate.
Away from the network it sends a camera's newest pictures up its connection, and
it says when one of its printers starts doing something else. Only one bridge
runs per folder.
