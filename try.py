from Crypto.Cipher import DES
from Crypto.Util.Padding import pad, unpad
import base64

# Generate a random 8-byte key
key = b'secretkey'

# Create a DES cipher object with the key and using CBC mode
cipher = DES.new(key, DES.MODE_CBC)

# Encrypt a message
plaintext = b'This is a secret message'
padded_plaintext = pad(plaintext, DES.block_size)
ciphertext = cipher.iv + cipher.encrypt(padded_plaintext)

# Decrypt the message
iv = ciphertext[:DES.block_size]
cipher = DES.new(key, DES.MODE_CBC, iv=iv)
decrypted_plaintext = unpad(cipher.decrypt(ciphertext[DES.block_size:]), DES.block_size)

# Print the results
print("Original message:", plaintext.decode('utf-8'))
print("Encrypted message (in base64):", base64.b64encode(ciphertext).decode('utf-8'))
print("Decrypted message:", decrypted_plaintext.decode('utf-8'))
