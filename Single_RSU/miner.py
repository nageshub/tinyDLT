# miner.py -- craft a transaction, do PoW and post to node
import requests, json, hashlib, time, random

NODE = 'http://localhost:8000'

def get_tips():
    r = requests.get(NODE + '/tips')
    return r.json()

def mine_and_post(payload, difficulty=3):
    tips = get_tips()['tips']
    tx = {'parents': tips, 'payload': payload, 'nonce': 0, 'pow_hash': ''}
    while True:
        s = json.dumps({k: tx[k] for k in sorted(tx) if k != 'pow_hash'}, sort_keys=True)
        h = hashlib.sha256(s.encode()).hexdigest()
        if h.startswith('0' * difficulty):
            tx['pow_hash'] = h
            break
        tx['nonce'] += 1
    # compute deterministic id
    txid = hashlib.sha256(json.dumps(tx, sort_keys=True).encode()).hexdigest()
    r = requests.post(NODE + '/tx', json={'id': txid, **tx})
    print(r.status_code, r.text)

if __name__ == '__main__':
    for i in range(3):
        mine_and_post({'sensor': 'temp', 'value': random.randint(20,30), 'i': i}, difficulty=3)
        time.sleep(1)
