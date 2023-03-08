FROM ubuntu:22.04

WORKDIR /src/

COPY code/main.py .
COPY requirements.txt .

RUN apt-get update
RUN apt-get install -y python3 python3-pip
RUN pip3 install -r requirements.txt

CMD [ "python3", "/src/main.py", "--no-scan" ]
