import socket, os, time

home = os.environ['USERPROFILE']

def test_rpc(port, state_dir):
    token_path = os.path.join(state_dir, 'rpc-token')
    print(f"Token path: {token_path} exists={os.path.exists(token_path)}")
    with open(token_path) as f:
        token = f.read().strip()
    print(f"Token: {token[:16]}...")
    
    s = socket.socket()
    s.settimeout(5)
    try:
        s.connect(('127.0.0.1', port))
        print(f"Connected to port {port}")
        s.sendall(f'{token}\n'.encode())
        print("Sent token")
        s.sendall(b'{"id":1,"method":"node_info","params":{}}\n')
        print("Sent request")
        
        # Try to read response
        resp = b''
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    print("Connection closed by server (empty chunk)")
                    break
                resp += chunk
                print(f"Received {len(chunk)} bytes: {chunk[:100]!r}")
                if b'\n' in chunk:
                    break
            except socket.timeout:
                print("Timeout reading response")
                break
            except Exception as e:
                print(f"Error reading: {e}")
                break
        print(f"Total response: {resp!r}")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        s.close()

print("=== Node A (9821) ===")
test_rpc(9821, home + '\\.vess-artery-9821')
