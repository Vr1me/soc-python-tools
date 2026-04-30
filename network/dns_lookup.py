import socket

domain = input("Enter domain: ")
ip = socket.gethostbyname(domain)
print(f"{domain} -> {ip}")