FROM ubuntu:22.04

WORKDIR /src/

COPY . .
COPY ./code/main.py ./main.py

RUN apt-get update
RUN apt-get install -y sudo

RUN chmod +x install_ubuntu.sh
RUN ./install_ubuntu.sh

RUN python3 /src/main.py --no-scan

CMD [ "python3", "/src/main.py", "--no-scan" ]
