#!/bin/bash

sudo apt-get install -y python3 python3-pip
sudo pip3 install -r requirements.txt

sudo cp code/main.py /usr/bin/local_chat

sudo chmod +x /usr/bin/local_chat
