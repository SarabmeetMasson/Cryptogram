import string

# Create the Playfair cipher key table
def create_table(key):
    alphabet = string.ascii_lowercase
    key = key.lower().replace('j', 'i')
    table = []
    for c in key + alphabet:
        if c not in table and c != 'j':
            table.append(c)
    return table

# Find the row and column of a given letter in the Playfair cipher key table
def find_position(table, letter):
    row = col = 0
    for i, c in enumerate(table):
        if letter == c:
            row, col = divmod(i, 5)
            break
    return row, col

# Encrypt a pair of plaintext letters using the Playfair cipher
def encrypt_pair(table, pair):
    a, b = pair
    a_row, a_col = find_position(table, a)
    b_row, b_col = find_position(table, b)
    if a_row == b_row: # letters are in the same row
        return table[a_row*5 + (a_col+1)%5] + table[b_row*5 + (b_col+1)%5]
    elif a_col == b_col: # letters are in the same column
        return table[((a_row+1)%5)*5 + a_col] + table[((b_row+1)%5)*5 + b_col]
    else: # letters form a rectangle
        return table[a_row*5 + b_col] + table[b_row*5 + a_col]

# Decrypt a pair of ciphertext letters using the Playfair cipher
def decrypt_pair(table, pair):
    a, b = pair
    a_row, a_col = find_position(table, a)
    b_row, b_col = find_position(table, b)
    if a_row == b_row: # letters are in the same row
        return table[a_row*5 + (a_col-1)%5] + table[b_row*5 + (b_col-1)%5]
    elif a_col == b_col: # letters are in the same column
        return table[((a_row-1)%5)*5 + a_col] + table[((b_row-1)%5)*5 + b_col]
    else: # letters form a rectangle
        return table[a_row*5 + b_col] + table[b_row*5 + a_col]

# Encrypt plaintext using the Playfair cipher
def encrypt(plaintext, key):
    plaintext = plaintext.lower().replace('j', 'i').replace(' ', '')
    table = create_table(key)
    ciphertext = ''
    for i in range(0, len(plaintext), 2):
        pair = plaintext[i:i+2]
        if len(pair) == 1: # add padding
            pair += 'x'
        ciphertext += encrypt_pair(table, pair)
    return ciphertext.upper()

# Decrypt ciphertext using the Playfair cipher
def decrypt(ciphertext, key):
    ciphertext = ciphertext.lower().replace('j', 'i').replace(' ', '')
    table = create_table(key)
    plaintext = ''
    for i in range(0, len(ciphertext), 2):
        pair = ciphertext[i:i+2]
        plaintext += decrypt_pair(table, pair)
    return plaintext.upper()

# Example usage
key = input("Enter Playfair cipher key: ")
plaintext = input("Enter plaintext: ")
ciphertext = encrypt(plaintext, key)
print("Ciphertext:", ciphertext)
decrypted = decrypt(ciphertext, key)
print("Decrypted plaintext:", decrypted)
