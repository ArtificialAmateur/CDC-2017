val_admins="$(cat data/valid_admins | awk -F: '{ print $1 }')"

    for i in $val_admins; do
        if ! id -nG "$i" | grep -qw "sudo"; then
            usermod -a -G sudo $i
        fi
    done
