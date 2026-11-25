# Ordryx Bridge

Connects the printers on a shop's network to its hosted Ordryx, outward only:
nothing on the shop's network is opened to the internet. Install it with the
command Ordryx shows on Add a bridge (`curl -fsSL https://get.ordryx.com/bridge | sh`);
`install.sh` here is that script before its release is filled in.

- It does only what `ordryx_bridge/calls.py` lists, to addresses that answer as
  Moonraker. Never a general tunnel.
- Its key stays in `~/.ordryx-bridge` (0600) and is never sent.
- `reach: this-computer` or `discovery: off` in `ordryx-bridge.conf` is a limit
  Ordryx can tighten but never loosen.

Commands: `ordryx-bridge status`, `code`, `scan`, `add <address>`, `unpair`, `version`.

Licence: GPL version 2 or later (`LICENSE`).
