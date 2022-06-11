import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding



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
    return calculateHashRoot(hashed_list)



def proofOfInclusionToLeaf(leaf_num):
    leaf = leaf_list[leaf_num]
    proof = calculateHashRoot(leaf_list)
    root = buildTree(leaf_list)
    proof = proof + " " + " ".join(buildProof(root,leaf))  
    return proof

def proofOfInclusion(x):
    x = x.split()
    info = x[0]
    hash_maker = hashlib.sha256()
    hash_maker.update(info.encode('ascii'))
    hashed_info = hash_maker.hexdigest()
    print(leaf_list)
    index_info = leaf_list.index(hashed_info)
    proof = proofOfInclusionToLeaf(index_info).split()
    correct = proof[0]
    hashed_list = proof[1:]
    hashed_list.insert(0, hashed_info)
    print("correct: " + correct)
    print("calculated: " + calculateHashRootFromProof(hashed_list))
    if(calculateHashRootFromProof(hashed_list) == correct):
        return True
    return False


def CreateKeys():
    
    private_key =rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key=private_key.public_key()
    keys.insert(0,private_key)
    keys.insert(1,public_key)
    return

def createSignRoot():
    sign_key = keys[0]
    root = calculateHashRoot(leaf_list)
    signature = sign_key.sign(
        root,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    


def VerifySign():
    verify_key = input()
    sign = input()
    verify_text = input()
    verify_key.verify(
    sign,
    verify_text,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )

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
    x = x.split()
    pick = x[0]

    try:
        pick = int(pick)
    except:
        print("Please enter a valid number 1-7")
        continue
    if(pick < 0 or pick > 8):
        print("Please enter a valid number 1-7")
        continue
    if(pick == 0):
        exit()
    if(pick == 1):
        addNode(x[1])
    if(pick == 2):
        print(calculateHashRoot(leaf_list))
    if(pick == 3):
        print(proofOfInclusionToLeaf(int(x[1])))
    if(pick == 4):
        print(proofOfInclusion(x[1]))
    if(pick == 5):
        CreateKeys()
        print(keys)
    if(pick == 6):
        createSignRoot()
    if(pick == 7):
        VerifySign()
    if(pick == 8):
        print(leaf_list[-1:])
    
