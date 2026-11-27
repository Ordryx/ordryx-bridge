# Ordryx Bridge

## 0.3.2

The installer takes its packages from PyPI only, whatever the computer's own
pip settings say. Raspberry Pi OS adds piwheels.org to every install; on a
network where that can't be reached, installing waited minutes on each package
and looked like a failure.

Moonraker's update entry is `[update_manager ordryx-bridge]`, the service's own
name: under the earlier `ordryx_bridge` Moonraker warned that it couldn't
restart the service after an update. Running the installer again renames an
entry already there.

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
