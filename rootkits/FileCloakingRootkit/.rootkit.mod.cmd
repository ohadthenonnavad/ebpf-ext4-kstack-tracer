savedcmd_rootkit.mod := printf '%s\n'   rootkit.o | awk '!x[$$0]++ { print("./"$$0) }' > rootkit.mod
