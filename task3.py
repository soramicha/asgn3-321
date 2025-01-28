import random
from Crypto.Util import number
from math import gcd
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def mod_pow(base, exponent, modulus):
  #(base^exponent) % modulus
  result = 1
  base = base % modulus
  while exponent > 0:
    if exponent % 2 == 1:
      result = (result * base) % modulus
    exponent = exponent  >> 1
    base = (base*base) % modulus
  return result

def mod_inverse(a, m):
  # modular inverse
  def helper(a, b):
    if a == 0: return (b, 0, 1)
    else:
      g, y, x = helper(b % a, a)
      return (g, x- (b//a )* y, y)
  g, x, _ = helper(a, m)
  if g != 1: raise Exception ('inverse doesnt exist')
  else: return x % m

def aes_encrypt(key, data):
  cipher = AES.new(key, AES.MODE_CBC)
  ct_bytes = cipher.encrypt(pad(data, AES.block_size))
  return cipher.iv + ct_bytes  # Returning IV and ciphertext together

def aes_decrypt(key, data):
  iv = data[:AES.block_size]
  ct = data[AES.block_size:]
  cipher = AES.new(key, AES.MODE_CBC, iv)
  pt = unpad(cipher.decrypt(ct), AES.block_size)
  return pt

def attack(attack1, attack2):
  p = 5
  q = 7
  n = p * q
  e = 65537
  phi = (p - 1) * (q - 1)
  d = mod_inverse(e, phi)
  print(f"\np is: {p} and q is: {q}")

  # our keys
  pub = (e, n)
  priv = (d, n)

  #alice sends to bob
  s = 3
  print(f"alice chooses s: {s}")
  ctext = mod_pow(s, e, n)
  print(f"Alice sends: {ctext}")

  if attack1:
    # modifying the ciphertext for attack 1
    k = 2
    c_prime = (ctext * mod_pow(k, e, n)) % n
    print(f"Mallory modifies it to: {c_prime}")
  else:
    s_pr = 2*s
    c_prime = mod_pow(s_pr, e, n)
    print(f"Mallory modifies it to: {c_prime}")


  #decrpyting s'
  s_prime = mod_pow(c_prime, d, n)
  print(f"Bob gets s': {s_prime}") 

  #getting s from s'
  k = 2
  s = (s_prime * mod_inverse(k, n)) % n
  print(f"Mallory recovers s: {s}")

  #alice sends a message
  m = "hi bob".encode('utf-8')
  print(f"Alice sends the message hi bob")
  key = hashlib.sha256(s.to_bytes((s.bit_length() + 7) // 8, 'big')).digest()
  c0 = aes_encrypt(key, m)

  #mallory decrypts
  decrypted_message = aes_decrypt(key, c0)
  print(f"Mallory decrypts the message: {decrypted_message.decode('utf-8')}")

def attack2():
  p = 5
  q = 7
  n = p * q
  e = 65537
  phi = (p - 1) * (q - 1)
  d = mod_inverse(e, phi)
  print(f"\np is: {p} and q is: {q}")

  # our keys
  pub = (e, n)
  priv = (d, n)

  #creating messages
  m1 = 12345
  m2 = 67890

  #sign
  s1 =  mod_pow(m1, d, n)
  s2 = mod_pow(m2, d, n)

  print(f"Alice publishes (m1, s1) = ({m1}, {s1}) and (m2, s2) = ({m2}, {s2})")

  #intercepting the messages
  m3 = (m1 * m2) % n
  s3 = (s1*s2) % n
  print(f"Mallory publishes (m3, s3) ({m3}, {s3})")

  verified_message = mod_pow(s3, e, n)

  if verified_message == m3:
    print("Valid")
    return 0
  print("damn broski")

def rsa():
  #generating vals
  bits = random.randint(2, 2048)  # variable bit size
  p = number.getPrime(bits)
  q = number.getPrime(bits)
  n = p*q
  e = 65537
  phi = (p - 1) * (q - 1)
  d = mod_inverse(e, phi)
  print(f"p is {p} and q is {q}")

  # our keys
  pub = (e, n)
  priv = (d,n)

  #encrypt
  m = int.from_bytes("hi bri".encode(), 'big')
  print(f"before encyption: hi bri")
  ctext = mod_pow(m, e, n)
  print(f"ciphertext is {ctext}")

  #decrypt
  dtext = mod_pow(ctext, d, n)
  #back into a string
  decrypted_message = dtext.to_bytes((dtext.bit_length() + 7) // 8, 'big').decode('utf-8')
  print(f"Plaintext is: {decrypted_message}")
  return 0

if __name__ == "__main__":
  rsa()
  print(3.2)
  attack(True, False)
  attack(False, True)
  attack2()