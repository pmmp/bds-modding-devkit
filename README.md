# bds-mod-workspace
Auxiliary scripts used for modding BDS for generating protocol data

## Things you'll need
- A Linux environment with a 5.4 kernel or newer (WSL2 is fine)
- `python3`
- `pip`
- [LIEF](https://github.com/lief-project/LIEF): `pip install --index-url https://lief-project.github.io/packages lief==0.12.0.dev0`
- [Frida](https://frida.re): `pip install frida frida-tools`
- A folder with an unpacked version of [Bedrock Dedicated Server](https://minecraft.net/download/server/bedrock)

## Getting started in 60 seconds
1. Clone the repo
2. `git submodule update --init`
3. `./helper.sh setup path/to/bds/server/files`
4. `./start.sh` to run the server with mods loaded

Run `./helper.sh help` to get more usage info.

## Things in the repo
| File name | Description |
|:----------|:------------|
| `export-symbols.py` | Uses [LIEF](https://github.com/lief-project/LIEF) to patch BDS and make the symbols linkable |
| `helper.sh` | Helper script based on [modloader-helper](https://github.com/Frago9876543210/modloader-helper) |
| `start.sh` | Runs the server with mods loaded. From [modloader-helper](https://github.com/Frago9876543210/modloader-helper) |
| `tracer.py` | Uses [Frida](https://frida.re) to hook packet functions in BDS and create packet traces. Run this while you have a BDS instance already running. Requires `sudo`. |

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
