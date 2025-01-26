from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import unpad
import random
from hashlib import sha256

# Task 2.2
def main():
    # agreeing on q and a between Bob and Alice
    q = "B10B8F96 A080E01D DE92DE5E AE5D54EC 52C99FBC FB06A3C6 9A6A9DCA 52D23B61 6073E286 75A23D18 9838EF1E 2EE652C0 13ECB4AE A9061123 24975C3C D49B83BF ACCBDD7D 90C4BD70 98488E9C 219A7372 4EFFD6FA E5644738 FAA31A4F F55BCCC0 A151AF5F 0DC8B4BD 45BF37DF 365C1A65 E68CFDA7 6D4DA708 DF1FB2BC 2E4A4371"
    a = "A4D1CBD5 C3FD3412 6765A442 EFB99905 F8104DD2 58AC507F D6406CFF 14266D31 266FEA1E 5C41564B 777E690F 5504F213 160217B4 B01B886A 5E91547F 9E2749F4 D7FBD7D3 B9A92EE1 909D0D22 63F80A76 A6A24C08 7A091F53 1DBF0A01 69B6A28A D662A4D1 8E73AFA3 2D779D59 18D08BC8 858F4DCE F97C2A24 855E6EEB 22B3B2E5"

# convert ascii into numbers
    new_q = ""
    for i in q:
        if i != " ":
            new_q += str(ord(i))

    new_a = ""
    for i in a:
        if i != " ":
            new_a += str(ord(i))

    q = int(new_q)
    a = int(new_a)

    print("q is: ", q)
    print("a is: ", a)
    # mallory changes a to q, q - 1, or 1
    a = 1
    print("Oh no! Mallory has changed the value of a to ", a, "\n")

    # generating private keys
    # alice
    XA = random.randint(1, 1000)
    # bob
    XB = random.randint(1, 1000)
    print("Bob's private key: ", XB)
    print("Alice's private key: ", XA)

    # generate public keys
    # alice
    YA = pow(a, XA) % q
    # bob
    YB = pow(a, XB) % q

    # exchange keys and now generate secret key
    # alice
    s_alice = pow(YB, XA) % q
    # bob
    s_bob = pow(YA, XB) % q
    # both secret keys should be exactly the same
    # this is their shared secret
    print("Bob's secret key: ", s_bob)
    print("Alice's secret key: ", s_alice, "\n")

    # derive and make sure to only get 16 bytes
    # alice
    k_alice = sha256(str(s_alice).encode("utf-8")).hexdigest()[:16]
    # bob
    k_bob = sha256(str(s_bob).encode("utf-8")).hexdigest()[:16]
    print("Bob and Alice's key respectively: ", k_alice, ", ", k_bob)

    # mallory determining shared secret
    s_mallory = 0
    if a == 1:
        s_mallory = 1
    elif a == q:
        s_mallory = 0
    elif a == (q - 1):
        s_mallory = 1
    # mallory deriving her secret key
    k_mallory = sha256(str(s_mallory).encode("utf-8")).hexdigest()[:16]
    print("Mallory has gotten her key from changing a! It is ", k_mallory)

    # create a shared initialization vector of 16 bytes
    IV = get_random_bytes(16)

    # create a message
    # alice
    m_alice = "Hi Bob, it's Alice!"
    print("Alice's message to Bob before encryption: ", m_alice)
    alice_sends_to_bob(m_alice, k_alice, k_bob, k_mallory, IV)

    # create a message
    # bob
    m_bob = "Hey Alice, what's up! Long time no talk!"
    print("Bob's message to Alice before encryption: ", m_bob)
    bob_sends_to_alice(m_bob, k_alice, k_bob, k_mallory, IV)

def alice_sends_to_bob(m_alice, k_alice, k_bob, k_mallory, IV):
    # encrypt on alice's side
    # convert alice's message into bytes
    m_alice = m_alice.encode("utf-8")
    # get the length of the message of bytes
    n = len(m_alice)

    # create a cipher block
    cipher_object_alice = AES.new(k_alice.encode("utf-8"), AES.MODE_CBC, IV)
    bytes_to_add = 16 - n % 16

    # pad the message
    m_alice += bytes([bytes_to_add] * bytes_to_add)
    # encrypt the message
    encryption_alice = cipher_object_alice.encrypt(m_alice)
    print("Alice's message to Bob after encryption: ", encryption_alice, "\n")

    print("Alice is sending encrypted message along with IV...oops! Mallory intercepted it!")
    print("Decrypting on Mallory's end...")
    # mallory decrypting alice's message
    k_mallory = k_mallory.encode("utf-8")
    # create a cipher block
    cipher_object_mallory = AES.new(k_mallory, AES.MODE_CBC, IV)
    n = len(encryption_alice)
    decrypted_message_alice = cipher_object_mallory.decrypt(encryption_alice)
    # unpad the message
    unpadded_message_alice = unpad(decrypted_message_alice, 16).decode("utf-8")
    print("What Mallory reads from Alice: ", unpadded_message_alice)
    print("Mallory sends the encrypted message from Alice to Bob\n")

    # on bob's side
    k_bob = k_bob.encode("utf-8")
    # create a cipher block
    cipher_object_bob = AES.new(k_bob, AES.MODE_CBC, IV)
    n = len(encryption_alice)
    decrypted_message_alice = cipher_object_bob.decrypt(encryption_alice)
    # unpad the message
    unpadded_message_alice = unpad(decrypted_message_alice, 16).decode("utf-8")
    print("Alice's message after decryption: ", unpadded_message_alice, "\n")

def bob_sends_to_alice(m_bob, k_alice, k_bob, k_mallory, IV):
    # encrypt on bob's side
    # convert bob's message into bytes
    m_bob = m_bob.encode("utf-8")
    # get the length of the message of bytes
    n = len(m_bob)

    # create a cipher block
    cipher_object_bob = AES.new(k_bob.encode("utf-8"), AES.MODE_CBC, IV)
    bytes_to_add = 16 - n % 16

    # pad the message
    m_bob += bytes([bytes_to_add] * bytes_to_add)
    # encrypt the message
    encryption_bob = cipher_object_bob.encrypt(m_bob)
    print("Bob's message to Alice after encryption: ", encryption_bob, "\n")

    print("Bob is sending encrypted message along with IV...oops! Mallory intercepted it!")
    print("Decrypting on Mallory's end...")
    # mallory decrypting bob's message
    k_mallory = k_mallory.encode("utf-8")
    # create a cipher block
    cipher_object_mallory = AES.new(k_mallory, AES.MODE_CBC, IV)
    n = len(encryption_bob)
    decrypted_message_bob = cipher_object_mallory.decrypt(encryption_bob)
    # unpad the message
    unpadded_message_bob = unpad(decrypted_message_bob, 16).decode("utf-8")
    print("What Mallory reads from Bob: ", unpadded_message_bob)
    print("Mallory sends the encrypted message from Bob to Alice\n")

    # on alice's side
    k_alice = k_alice.encode("utf-8")
    # create a cipher block
    cipher_object_alice = AES.new(k_alice, AES.MODE_CBC, IV)
    n = len(encryption_bob)
    decrypted_message_bob = cipher_object_alice.decrypt(encryption_bob)
    # unpad the message
    unpadded_message_bob = unpad(decrypted_message_bob, 16).decode("utf-8")
    print("Bob's message after decryption: ", unpadded_message_bob)

main()