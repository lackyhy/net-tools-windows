# net-tools-windows

Native Windows ports of the Linux networking commands **`ip`** (iproute2), **`ss`** (iproute2) and **`ifconfig`** (net-tools).

Нативные утилиты `ip`, `ss`, `ifconfig` для Windows с синтаксисом и выводом как в Linux.

- Plain C + WinAPI (IP Helper), statically linked: no runtime, no dependencies, ~200 KB per exe.
- Fast: a call takes about 20–30 ms from PowerShell, process startup included. `ss -tunap` lists around 900 sockets with process names in about 30 ms.
- Unicode interface names (e.g. Cyrillic `Подключение по локальной сети`) display correctly in the console and through pipes.
- Works in PowerShell, cmd and Windows Terminal.

## Install

Prebuilt: download `net-tools-windows-x64.zip` from Releases, unpack it, then run:

```powershell
powershell -ExecutionPolicy Bypass -File install.ps1
```

From source (needs Visual Studio Build Tools with the C++ workload):

```powershell
git clone https://github.com/lackyhy/net-tools-windows.git
cd net-tools-windows
powershell -ExecutionPolicy Bypass -File install.ps1   # builds automatically if bin\ is missing
```

The script copies the tools to `%LOCALAPPDATA%\Programs\net-tools-windows` and adds that folder to the user `PATH`, so admin rights aren't needed. Open a new terminal afterwards. To remove the tools, run `uninstall.ps1`.

## Usage

```text
ip a | ip addr show dev Ethernet | ip -4 a | ip -br a | ip -br -c a | ip -o a
ip l | ip -s link | ip -s -h link show Wi-Fi | ip -d link
ip r | ip -6 r | ip route show table all | ip route get 8.8.8.8
ip n | ip neigh show dev Ethernet nud reachable
ip -j -p a                      # JSON (pretty)

ss | ss -tulpn | ss -tan | ss -s
ss -tn state established '( dport = :443 or sport = :443 )'
ss -ltn 'sport > :1024' | ss -t dst 192.168.1.0/24

ifconfig | ifconfig -a | ifconfig -s | ifconfig Ethernet
```

### Changing settings (run as Administrator)

```text
ip addr add 10.0.0.5/24 dev Ethernet        ip addr del 10.0.0.5/24 dev Ethernet
ip addr flush dev Ethernet scope global
ip route add 10.10.0.0/16 via 192.168.1.1   ip route del 10.10.0.0/16
ip route replace default via 192.168.1.1 dev Ethernet metric 10
ip link set dev Wi-Fi down|up               ip link set dev Ethernet mtu 1400
ip link set dev "Ethernet 2" name LAN2
ip neigh add 192.168.1.50 lladdr aa:bb:cc:dd:ee:ff dev Ethernet
ip neigh del 192.168.1.50 dev Ethernet      ip neigh flush all
ifconfig Ethernet add 10.0.0.5/24           ifconfig Wi-Fi down
ss -K dst 1.2.3.4                           # kill matching IPv4 TCP connections
```

Without admin rights you get `RTNETLINK answers: Operation not permitted`, the same as on Linux.

## Differences from Linux

| | |
|---|---|
| Interface names | Windows names (`Ethernet`, `Wi-Fi`, `vEthernet (WSL)`). `dev` also accepts the adapter description, GUID or index. Quote names that contain spaces. |
| Route metric | Shows the effective Windows metric, which is the route metric plus the interface metric (as in `route print`). |
| `ip route` | The main table hides local, broadcast and multicast routes. Use `table local` or `table all` to see them. |
| `ss` Recv-Q / Send-Q | Always `0`, because Windows doesn't expose per-socket queues. |
| `ss -p` | Shows `users:(("name.exe",pid=N))` with no fd. |
| `ss -x`, raw sockets | Not available on Windows, so nothing is printed. |
| `ip link set up/down/name` | Uses `netsh` internally. |
| `ifconfig` | Without `-a`, shows only interfaces whose link is up. `ifconfig IF ADDR` adds an address instead of replacing it. |
| Not supported | `ip rule`, `ip tunnel`, `ip netns`, `ip monitor`, `ip xfrm` and virtual links (`ip link add`). |

`netstat`, `route` and `arp` are not included because Windows already ships commands with these names.

## Build

```bat
build.bat
```

This produces `bin\ss.exe`, `bin\ip.exe` and `bin\ifconfig.exe` with MSVC (`/O2 /GL /MT`, LTCG).

## License

MIT
