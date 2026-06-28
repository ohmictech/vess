import socket, json, os

home = os.environ['USERPROFILE']

def test_rpc(port, state_dir, label):
    token_path = os.path.join(state_dir, 'rpc-token')
    with open(token_path) as f:
        token = f.read().strip()
    
    s = socket.socket()
    s.settimeout(20)
    s.connect(('127.0.0.1', port))
    s.sendall(f'{token}\n'.encode())
    s.sendall(b'{"id":1,"method":"node_info","params":{}}\n')
    
    resp = b''
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
            if b'\n' in chunk: break
        except socket.timeout:
            print(f"{label}: Timeout")
            break
    s.close()
    
    try:
        line = resp.decode().strip().split('\n')[0]
        j = json.loads(line)
        print(f"\n=== {label} ===")
        print(json.dumps(j, indent=2))
    except Exception as e:
        print(f"{label}: Parse error: {e}")
        print(f"Raw: {resp[:500]!r}")

test_rpc(9821, home + '\\.vess-artery-9821', 'Node A')
test_rpc(9822, home + '\\.vess-artery-9822', 'Node B')
