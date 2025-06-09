# bds-modding-devkit
This developer kit allows you to quickly and easily start modding the Bedrock Dedicated Server.

It's used for dumping information for protocol updates for PocketMine-MP, but the tools provided here can be used for much more than that.

The following mods are included as git submodules:
- [minecraft-linux/server-modloader-coremod](https://github.com/minecraft-linux/server-modloader-coremod)
- [pmmp/bds-mod-mapping](https://github.com/pmmp/bds-mod-mapping)

## Things you'll need
- A Linux environment with a 5.4 kernel or newer (WSL2 is fine)
- `python3`
- `pip`
- `clang`
- `libc++-dev`
- `libc++abi-dev`
- `binutils` (for `protocol_info_dumper.py`)
- A folder or zip of [Bedrock Dedicated Server](https://minecraft.net/download/server/bedrock)

## Getting started in 60 seconds
1. Clone the repo
2. `git submodule update --init`
3. `python3 -m venv ./python-venv` (or any path of your choice)
4. `source ./python-venv/bin/activate`
5. `python3 -m pip install -r python_requirements.txt`
6. `./scripts/setup path/to/bds/server/files` or `./scripts/setup path/to/bds.zip`
7. `./start.sh` to run the server with mods loaded

Run `./helper.sh help` to get more usage info.

## Updating the devkit after initial setup
1. `git pull`
2. `source ./python-venv/bin/activate`
3. `python3 -m pip install -r python_requirements.txt`

## Updating BDS with an existing installation
1. `source ./python-venv/bin/activate`
2. `./scripts/install-server path/to/bds/server/files` or `./scripts/install-server path/to/bds.zip`
3. `./start.sh` to run the server with mods loaded

> [!WARNING]
> It's very likely that new versions of BDS will cause mods like `mapping` to not work anymore.
> Updating these is sometimes complex and outside of the scope of this readme. Best to seek
> support from the community if you don't know what you're doing.

## Things in the repo
| File name | Description |
|:----------|:------------|
| `export-symbols.py` | Uses [LIEF](https://github.com/lief-project/LIEF) to patch BDS and make the symbols linkable |
| `helper.sh` | Helper script based on [modloader-helper](https://github.com/Frago9876543210/modloader-helper) |
| `protocol_info_dumper.py` | Uses `objdump` to dump basic version info and packet ID lists from BDS for data generation |
| `start.sh` | Runs the server with mods loaded. From [modloader-helper](https://github.com/Frago9876543210/modloader-helper) |
| `tracer.py` | Uses [Frida](https://frida.re) to hook packet functions in BDS and create packet traces. Run this while you have a BDS instance already running. Requires `sudo`. |

## Adding your own mods
Mod code is placed in the `code` directory. Build them by invoking `./scripts/build all`.

To generate skeleton files for a new mod, use the tool `./scripts/gen`.

## Credits
- [@Frago9876543210](https://github.com/Frago9876543210)
  - Writing [modloader-helper](https://github.com/Frago9876543210/modloader-helper)
  - Writing the original version of [mapping](https://github.com/pmmp/mapping)
  - Revamping `tracer.py` ([gist](https://gist.github.com/Frago9876543210/2e5de55f1bb7e42594b73f5665391bf4#file-tracer-py))
- [@MCMrARM](https://github.com/MCMrARM)
  - Creating [server-modloader](https://github.com/minecraft-linux/server-modloader), without which this endeavour would simply not be possible.
  - Writing `export-symbols.py`
- [@Intyre](https://github.com/Intyre)
  - Helping me to write the initial versions of `tracer.py` which are still used today
