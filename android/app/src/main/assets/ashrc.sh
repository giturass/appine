# Written by Appine beside /etc/profile.d/appine.sh, which names this file in ENV, and replaced
# together with it.
#
# Every interactive busybox ash reads the file ENV names, a login shell after /etc/profile and
# ~/.profile. ash runs nothing before a prompt, so this puts the shell integration marks (OSC 133,
# see appine.sh) around whatever PS1 and PS2 are by then: a prompt ~/.profile set keeps its marks,
# and a nested ash (ash, su without -l, doas -s) gets them too. If PS1 is overwritten later, the
# terminal falls back to foreground-process detection for busy state, titles and command timing.
if [ -n "${BB_ASH_VERSION-}" ]; then
    if [ -z "${ENV-}" ] && [ -r /etc/profile.d/appine.ashrc ]; then
        export ENV=/etc/profile.d/appine.ashrc
    fi
    # ash expands PS1, then BusyBox line editing interprets backslash escapes in the result.
    __appine_ash_path() {
        local p="$PWD"
        if [ "$1" = prompt ]; then
            # BusyBox's visible path follows symlinks. This cd is local to the prompt
            # substitution, so the shell and its directory title keep the logical PWD.
            cd -P . 2>/dev/null && p=$PWD
            if [ -n "${HOME-}" ]; then
                case "$p" in
                "$HOME") p='~' ;;
                "$HOME"/*) p="~${p#"$HOME"}" ;;
                esac
            fi
        fi
        p=${p//[[:cntrl:]]/?}
        printf '%s' "${p//\\/\\\\}"
    }
    # Nested interactive ash starts with BusyBox's plain prompt.
    case ${PS1-} in
    '\w \$ ') PS1='$(__appine_ash_path prompt) \$ ' ;;
    esac
    # The prompt reports the last command's status (D) and starts on a fresh line (A, its cursor
    # moved with the arrows), and the typed command starts after it (B). ash says nothing when the
    # command ends, and breaks one longer than the screen's width into rows itself, so the prompts
    # ask Appine's terminal to read ash's line feeds (appine_lf=output): one ash breaks a line
    # with goes on with the command, and any other ends it and starts the output
    case ${PS1-} in
    *'133;A'*) ;;
    *)
        __appine_ps1=${PS1-}
        __appine_cont='\[\e]133;P;k=c;appine_lf=output\a\]'
        case $__appine_ps1 in
        *'\n'*) __appine_ps1=${__appine_ps1//\\n/\\n$__appine_cont} ;;
        esac
        PS1='\[\e]133;D;$?\a\e]133;A;cl=line;appine_lf=output\a\]'$__appine_ps1'\[\e]133;B\a\e]2;$(__appine_ash_path title)\a\]'
        unset __appine_ps1 __appine_cont
        ;;
    esac
    case ${PS2-} in
    *'133;P'*) ;;
    *) PS2='\[\e]133;P;k=s;appine_lf=output\a\]'${PS2-}'\[\e]133;B\a\]' ;;
    esac
fi
