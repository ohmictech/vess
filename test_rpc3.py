import socket, json, os

home = os.environ['USERPROFILE']

def test_rpc(port, state_dir):
    token_path = os.path.join(state_dir, 'rpc-token')
    with open(token_path) as f:
        token = f.read().strip()
    
    s = socket.socket()
    s.settimeout(15)
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
            print("Timeout reading response")
            break
    s.close()
    
    line = resp.decode().strip().split('\n')[0]
    j = json.loads(line)
    d = j.get('result',{}).get('data',{})
    print(f"peer_count={d.get('peer_count')} discovered={d.get('discovered_peer_count')} verified={d.get('verified_peer_count')} cached={d.get('cached_peer_count')}")
    print(f"node_id={d.get('node_id','?')[:16]}...")

test_rpc(9821, home + '\\.vess-artery-9821')
