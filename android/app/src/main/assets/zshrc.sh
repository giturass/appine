# Written by Appine beside /etc/profile.d/appine.sh, which reads this file, and replaced together
# with it.
#
# zsh's shell integration marks and titles (OSC 133 and OSC 2, see appine.sh). The profile sets
# the default prompt; these hooks wrap whichever prompt the user or a theme chooses afterwards.
# Alpine's zprofile reads /etc/profile in sh emulation. Register the hooks in local zsh mode so
# array operations work without changing the caller's options. Reading this file again keeps
# other hooks and registers each Appine hook only once.
() {
    builtin emulate -L zsh -o no_aliases
    # Wraps a zsh prompt string in %{...%} marks, doubling a trailing bare '%' so it cannot join
    # with the closing mark's '{'.
    __appine_wrap_zsh_prompt() {
        local p=$1 open=$2 close=$3
        [[ $p == *[^%]% || $p == % ]] && p=${p}%
        REPLY=${open}${p}${close}
    }
    __appine_restore_zsh_prompts() {
        if [[ -n ${__appine_saved_ps1+x} && $PS1 == $__appine_marked_ps1 ]]; then
            PS1=$__appine_saved_ps1
        fi
        if [[ -n ${__appine_saved_ps2+x} && $PS2 == $__appine_marked_ps2 ]]; then
            PS2=$__appine_saved_ps2
        fi
        if [[ -n ${__appine_saved_rps1+x} && ${RPROMPT-} == $__appine_marked_rps1 ]]; then
            RPROMPT=$__appine_saved_rps1
        fi
        if [[ -n ${__appine_saved_rps2+x} && ${RPS2-} == $__appine_marked_rps2 ]]; then
            RPS2=$__appine_saved_rps2
        fi
    }
    # Before each prompt: the end of the last command with its status (D); the marks around PS1
    # (A: the prompt starts, its cursor moved with the arrows; k=c on later rows of a multi-line
    # PS1; B: the input starts), PS2, RPROMPT (k=r on a single-line PS1, k=c on a multi-line PS1
    # so it keeps the row marked as a continuation, followed by B so user input stays input) and
    # RPS2 are restored before commands and re-wrapped before each prompt, and are sent again at
    # each redraw, as zle redraws the whole prompt. The function moves itself last, to run after
    # the hooks of themes that set prompts before each prompt.
    __appine_precmd() {
        local ret=$? pp=0
        [[ -o prompt_percent ]] && pp=1
        builtin emulate -L zsh -o no_aliases
        builtin printf '\033]133;D;%s\007' "$ret"
        builtin printf '\033]2;%s\007' "${PWD//[[:cntrl:]]/?}"
        __appine_restore_zsh_prompts
        if (( pp )); then
            local REPLY multiline=0
            [[ $PS1 == *$'\n'* ]] && multiline=1
            if [[ $PS1 != *'133;B'* ]]; then
                __appine_saved_ps1=$PS1
                local ps1=$PS1
                if (( multiline )); then
                    ps1=${ps1//$'\n'/$'\n'$'%{\e]133;P;k=c\a%}'}
                fi
                __appine_wrap_zsh_prompt "$ps1" $'%{\e]133;A;cl=line\a%}' $'%{\e]133;B\a%}'
                PS1=$REPLY
                __appine_marked_ps1=$PS1
            else
                builtin unset __appine_saved_ps1 __appine_marked_ps1
            fi
            if [[ $PS2 != *'133;B'* ]]; then
                __appine_saved_ps2=$PS2
                local ps2=$PS2
                if [[ $ps2 == *$'\n'* ]]; then
                    ps2=${ps2//$'\n'/$'\n'$'%{\e]133;P;k=c\a%}'}
                fi
                __appine_wrap_zsh_prompt "$ps2" $'%{\e]133;P;k=s\a%}' $'%{\e]133;B\a%}'
                PS2=$REPLY
                __appine_marked_ps2=$PS2
            else
                builtin unset __appine_saved_ps2 __appine_marked_ps2
            fi
            if [[ -n ${RPROMPT-} && $RPROMPT != *'133;B'* ]]; then
                __appine_saved_rps1=$RPROMPT
                local rk=r
                (( multiline )) && rk=c
                __appine_wrap_zsh_prompt "$RPROMPT" $'%{\e]133;P;k='"$rk"$'\a%}' $'%{\e]133;B\a%}'
                RPROMPT=$REPLY
                __appine_marked_rps1=$RPROMPT
            else
                builtin unset __appine_saved_rps1 __appine_marked_rps1
            fi
            if [[ -n ${RPS2-} && $RPS2 != *'133;B'* ]]; then
                __appine_saved_rps2=$RPS2
                __appine_wrap_zsh_prompt "$RPS2" $'%{\e]133;P;k=s\a%}' $'%{\e]133;B\a%}'
                RPS2=$REPLY
                __appine_marked_rps2=$RPS2
            else
                builtin unset __appine_saved_rps2 __appine_marked_rps2
            fi
        else
            builtin printf '\033]133;A;cl=line\007'
        fi
        [[ $precmd_functions[-1] == __appine_precmd ]] ||
            precmd_functions=(${precmd_functions:#__appine_precmd} __appine_precmd)
    }
    # Before each command: restore clean prompts for other hooks and the command, mark the start of
    # its output (C), then report the literal submitted command.
    __appine_preexec() {
        builtin emulate -L zsh -o no_aliases
        __appine_restore_zsh_prompts
        builtin printf '\033]133;C\007'
        builtin printf '\033]2;%s\007' "${1//[[:cntrl:]]/?}"
    }
    precmd_functions=(${precmd_functions:#__appine_precmd} __appine_precmd)
    preexec_functions=(${preexec_functions:#__appine_preexec} __appine_preexec)
}
