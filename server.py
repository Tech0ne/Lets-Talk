import socket as s

server = s.socket(s.AF_BLUETOOTH, s.SOCK_STREAM, s.BTPROTO_RFCOMM)
server.bind(("54:14:F3:B4:14:4A", 4))
server.listen(1)

client, addr = server.accept()

try:
    while True:
        data = client.recv(4096)
        if not data:
            break
        print(f"Message : {data.decode('utf-8')}")
        message = input("Enter a message : ")
        client.send(message.encode('utf-8'))
except Exception as e:
    print(f"Error : {e}")

client.close()
server.close()
