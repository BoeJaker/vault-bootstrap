#!/bin/bash

# Prompt for the root password
echo -n "Enter root password: "
read -s password
echo

# Validate the root password
if [ "$password" != "your_root_password" ]; then
  echo "Incorrect password. Access denied."
  exit 1
fi

# If the password is correct, start the shell
exec /bin/bash