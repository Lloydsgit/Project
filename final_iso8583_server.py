import socket
import threading

def handle_client(conn, addr):
    print(f"[ISO8583 SERVER] Connection from {addr}")
    try:
        while True:
            data = conn.recv(2048)
            if not data:
                break
            request = data.decode()
            print(f"[RECEIVED] {request}")
            response = f"ISO8583-REPLY: Approved {request[:4]}-{request[-4:]}"
            conn.sendall(response.encode())
    except Exception as e:
        print(f"[ERROR] {e}")
    finally:
        conn.close()
        print(f"[DISCONNECTED] {addr}")

def run_server(host="0.0.0.0", port=8583):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[ISO8583 SERVER] Listening on {host}:{port}")
    while True:
        conn, addr = server.accept()
        thread = threading.Thread(target=handle_client, args=(conn, addr))
        thread.start()

if __name__ == "__main__":
    run_server()
