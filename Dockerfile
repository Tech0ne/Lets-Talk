FROM ubuntu:22.04

WORKDIR /src/

COPY . .

RUN chmod +x install_ubuntu.sh
RUN ./install_ubuntu.sh

CMD [ "python3", "/src/main.py", "--no-scan" ]
