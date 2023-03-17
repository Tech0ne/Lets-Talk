#!/bin/bash

echo "You should realy think about not using fedora, u know ?"
echo "Press enter to accept that you use an OS that is inferior :eyes:"
read

sudo dnf install -y python3 python3-pip
sudo yum install -y python3-netifaces
sudo pip3 install -r requirements.txt

sudo cp code/main.py /usr/bin/local_chat

sudo chmod +x /usr/bin/local_chat
