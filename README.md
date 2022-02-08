# bds-mod-workspace
Auxiliary scripts used for modding BDS for generating protocol data

## Things you'll need
- A Linux environment with a 5.4 kernel or newer (WSL2 is fine)
- `python3`
- `pip`
- [LIEF](https://github.com/lief-project/LIEF): `pip install --index-url https://lief-project.github.io/packages lief==0.12.0.dev0`
- [Frida](https://frida.re): `pip install frida frida-tools`

## Things in the repo
| File name | Description |
|:----------|:------------|
| `export-symbols.py` | Uses [LIEF](https://github.com/lief-project/LIEF) to patch BDS and make the symbols linkable |
| `helper.sh` | Carbon copy of the helper.sh from [modloader-helper](https://github.com/Frago9876543210/modloader-helper) (To be removed and downloaded automatically instead) |
| `start.sh` | From [modloader-helper](https://github.com/Frago9876543210/modloader-helper) |
| `Makefile` | Script added by me to ease the process of working with custom builds of BDS |
| `tracer.py` | Uses [Frida](https://frida.re) to hook packet functions in BDS and create packet traces. Run this while you have a BDS instance already running. Requires `sudo`. |

## Why publish this in such a mess?
In case I get hit by a bus tomorrow. The files in here and the knowledge conveyed by them are essential for updating PocketMine-MP to each new version. The lack of public availability of this information has denied the community the ability to adapt to newer updates by themselves in recent versions.

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
