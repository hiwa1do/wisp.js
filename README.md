# wisp.js

This is an implementation of a [Wisp](https://github.com/MercuryWorkshop/wisp-protocol) server, written in a single JavaScript file made for cloudflare web workers.

## Installation:
### Install From Source:
Clone this repository and cd into it, then run the following commands:
```
python3 -m venv .venv
source .venv/bin/activate
pip3 install -e .
```

### Install From PyPI:
Run the following command to install this program:
```
pip3 install wisp-python
```

To install the Cloudflare Warp proxy feature:
```
pip3 install wisp-python[warp]
```
This allows you proxy all exit traffic through Cloudflare Warp.
