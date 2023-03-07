#!/bin/bash

sudo apt-get install -y python3 python3-pip
sudo pip3 install pycryptodome

sudo bash -c "echo '#!$(which python3)' > /usr/bin/local_chat"
sudo bash -c "cat code/main.py >> /usr/bin/local_chat"

sudo chmod +x /usr/bin/local_chat
