# Avraham Sikirov, 318731478, Kehat Sudri, 318409745

from cgitb import text
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization
from numpy import inf

def buildTree(leaf_list):
    node_list = []
    for i in leaf_list:
        node_list.append(Merkle(i))
    node_f = 0
    i = 0
    while(True):
        if (len(node_list) == 1):
            break
        if (i >= len(node_list)):
            i = 0
            continue
        node1 = node_list.pop(i)
        if (i >= len(node_list)):
            node_list.insert(i, node1)
            i = 0
            continue
        node2 = node_list.pop(i)
        hash_maker = hashlib.sha256()
        hash_maker.update((node1.key + node2.key).encode('ascii'))
        hashed = hash_maker.hexdigest()
        node_f = Merkle(hashed)
        node_f.left = node1
        node_f.right = node2
        node_list.insert(i,node_f)
        i = i + 1
    return node_f



def buildProof(root,str):
    proof = []
    while(root != None):
        if (root.key == str):
            return proof
        if(isValExists(root.left, str)):
            proof.insert(0,  '1' + root.right.key)
            
            root = root.left
        else:
            proof.insert(0, '0' + root.left.key)
            root = root.right
    return None



def isValExists(root, key):
    if (root == None):
        return False
    if (root.key == key):
        return True
    left_tree = isValExists(root.left, key)
    if left_tree:
        return True
    res2 = isValExists(root.right, key)
    return res2



def postOrder(root):
    if root == None:
        return
    postOrder(root.left)
    postOrder(root.right)
    print(root.key)


def addNode(string):
    hash_maker = hashlib.sha256()
    hash_maker.update(string.encode('ascii'))
    leaf_list.append(hash_maker.hexdigest())

def calculateHashRoot(leaf_list):
    if(len(leaf_list) == 0):
        return ""
    if (len(leaf_list) == 1):
        return leaf_list[0]
    hashed_list = []
    for i in range(0,len(leaf_list) - 1, 2):
        new_leaf = leaf_list[i] + leaf_list[i + 1]
        hash_maker = hashlib.sha256()
        hash_maker.update(new_leaf.encode('ascii'))
        hashed_list.append(hash_maker.hexdigest())
    if(len(leaf_list) % 2 != 0):
        hashed_list.append(leaf_list[-1])
    return calculateHashRoot(hashed_list)
    

def calculateHashRootFromProof(leaf_list):
    if(len(leaf_list) == 0):
        return ""
    if (len(leaf_list) == 1):
        return leaf_list[0]
    hashed_list = []
    for i in range(0,len(leaf_list) - 1, 2):
        new_leaf = ''
        if(leaf_list[i + 1][0] == '1'):
            new_leaf = leaf_list[i] + leaf_list[i + 1][1:]
        else:
            new_leaf = leaf_list[i + 1][1:] + leaf_list[i]
        hash_maker = hashlib.sha256()
        hash_maker.update(new_leaf.encode('ascii'))
        hashed_list.append(hash_maker.hexdigest())
    if(len(leaf_list) % 2 != 0):
        hashed_list.append(leaf_list[-1])
    return calculateHashRootFromProof(hashed_list)



def proofOfInclusionToLeaf(leaf_num):
    leaf = leaf_list[leaf_num]
    proof = calculateHashRoot(leaf_list)
    root = buildTree(leaf_list)
    proof = proof + " " + " ".join(buildProof(root,leaf))  
    return proof

def proofOfInclusion(x):
    x = x.split()
    leaf = x[0]
    hash_maker = hashlib.sha256()
    hash_maker.update(leaf.encode('ascii'))
    hashed_leaf = hash_maker.hexdigest()
    correct = x[1]
    hashed_list = x[2:]
    hashed_list.insert(0, hashed_leaf)
    print("correct: " + correct)
    print("calculated: " + calculateHashRootFromProof(hashed_list))
    if(calculateHashRootFromProof(hashed_list) == correct):
        return True
    return False


def CreateKeys():
    keys = []
    private_key =rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key=private_key.public_key()
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    keys.append(private_pem.decode())
    keys.append(public_pem.decode())
    return keys

def createSignRoot(sign_key_string):

    pk_lines = []
    info = sign_key_string
    pk_lines.append(info)
    while info:
        info = input()
        pk_lines.append(info)
    pk = '\n'.join(pk_lines)
    
    root = calculateHashRoot(leaf_list)
    sign_key = serialization.load_pem_private_key(
        pk.encode('ascii'),
        password=None,
        backend=default_backend()
    )
    signature = sign_key.sign(
        root.encode('ascii'),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return base64.encodebytes(signature).decode()


def VerifySign(verify_key_first_line):

    pk_lines = []
    info = verify_key_first_line
    pk_lines.append(info)
    while info:
        info = input()
        pk_lines.append(info)
    pk_b = '\n'.join(pk_lines)



    x= input().split()
    sign = x[0]
    verify_text = x[1]


    pk = serialization.load_pem_public_key(
        pk_b.encode('ascii'),
        backend=default_backend()
    )

    try:

        res = pk.verify(
            #sign.encode('ascii'),
            #verify_text.encode('ascii'),
            #base64.decodebytes(sign.encode()),
            #verify_text.encode('ascii'),
            base64.decodebytes(sign.encode()),
            verify_text.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
    except:
        return False
    return True

class Merkle:
    def __init__(self,key):
        self.key = key
        self.left = None
        self.right = None

    def findHash(self, file):
        return

leaf_list = []
keys=[]

# root = Merkle(50)
# node1 = Merkle(5)
# root.left = node1
# leaf_list = ["a", "b", "c", "d", "e"]
# postOrder(buildTree(leaf_list))
# root = buildTree(leaf_list)
# str = "b"
# print(buildProof(root, str))
# print(proofOfInclusionToLeaf())
# exit()

while(True):
    x = input()
    pick = x[0]

    try:
        pick = int(pick)
    except:
        print('')
        continue
    if(pick < 1 or pick > 7):
        print('')
        continue
    if(pick == 1):
        try:
            addNode(x[2:])
        except:
            print('')
    if(pick == 2):
        try:
            print(calculateHashRoot(leaf_list))
        except:
            print('')
    if(pick == 3):
        try:
            print(proofOfInclusionToLeaf(int(x[2:])))
        except:
            print('')
    if(pick == 4):
        try:
            print(proofOfInclusion(x[2::]))
        except:
            print('')
    if(pick == 5):
        try:
            keys = CreateKeys()
            print(keys[0] + '\n' + keys[1])
        except:
            print('')
    if(pick == 6):
        try:
            print(createSignRoot(x[2:]))
        except:
            print('')
    if(pick == 7):
        try:
            print(VerifySign(x[2:]))
        except:
            print('')