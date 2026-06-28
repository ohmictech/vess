import socket, json, time, os

def rpc(port, state_dir):
    token_path = os.path.join(state_dir, 'rpc-token')
    with open(token_path) as f:
        token = f.read().strip()
    s = socket.socket()
    s.settimeout(15)
    s.connect(('127.0.0.1', port))
    s.sendall(f'{token}\n'.encode())
    s.sendall(b'{"id":1,"method":"node_info","params":{}}\n')
    time.sleep(0.5)
    resp = b''
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk: break
            resp += chunk
            if b'\n' in chunk: break
        except:
            break
    s.close()
    j = json.loads(resp.decode().strip())
    d = j.get('result',{}).get('data',{})
    print(f"peer_count={d.get('peer_count')} node_id={d.get('node_id','?')[:12]}...")

home = os.environ['USERPROFILE']
rpc(9821, home + '\\.vess-artery-9821')
rpc(9822, home + '\\.vess-artery-9822')
