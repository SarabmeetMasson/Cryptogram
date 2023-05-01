from colored import fg, bg, attr

logo_ascii = """
   _____                  _         _____                     
  / ____|                | |       / ____|                    
 | |     _ __ _   _ _ __ | |_ ___ | |  __ _ __ __ _ _ __ ___  
 | |    | '__| | | | '_ \| __/ _ \| | |_ | '__/ _` | '_ ` _ \ 
 | |____| |  | |_| | |_) | || (_) | |__| | | | (_| | | | | | |
  \_____|_|   \__, | .__/ \__\___/ \_____|_|  \__,_|_| |_| |_|
               __/ | |    
              |___/|_|    "Crack the Code, Unveil the Mystery“  
    
Created By: Sarabmeet Singh Masson
"""
print("%s %s %s" %(attr(1), fg(46), logo_ascii))

x1 = 1
while x1 == 1:

    print(attr(1), fg(46), "\nWhat would you like to do?\n1. Cryptography\n2. Steganography")
    try:
        action = int(input("You Chose: "))
    except:
        print(attr(1), fg(1),"\nIllegal action, try again.")

    if action == 1:

        x2 = 1
        while x2 == 1:

            print(attr(1), fg(178),"\nCryptography:")
            try:
                crypt = int(input("1. SHA256 \n2. SHA384 \n3. SHA224 \n4. SHA512 \n5. SHA1 \n6. MD5 \n7. Base64 \n8. Caesar Cipher \n9. Playfair Cipher \n10. ROT13 \n11. ROT47 \n12. Morse Code \n13. Binary \n14. Decimal \n15. Hexadecimal \nSelect a Cryptography Algorithm: "))
            except:
                print(attr(1), fg(1),"\nIllegal action, try again.")



            if crypt == 1:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153),"\nSHA256 Encoding", attr(1), fg(105))   
                    
                    import hashlib

                    # Get input from user
                    input_str = input("Enter a string to Hash: ")

                    # Encode input string to bytes
                    input_bytes = input_str.encode('utf-8')

                    # Hash input bytes using SHA256
                    hashed_bytes = hashlib.sha256(input_bytes)

                    # Convert hashed bytes to hexadecimal representation
                    hashed_str = hashed_bytes.hexdigest()

                    # Print the hash
                    print("SHA256 hash of '" + input_str + "':")
                    print(hashed_str)

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 2:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153),"\nSHA384 Encoding", attr(1), fg(105)) 
                    
                    import hashlib

                    # Get input from user
                    input_str = input("Enter a string to Hash: ")

                    # Encode input string to bytes
                    input_bytes = input_str.encode('utf-8')

                    # Hash input bytes using SHA256
                    hashed_bytes = hashlib.sha384(input_bytes)

                    # Convert hashed bytes to hexadecimal representation
                    hashed_str = hashed_bytes.hexdigest()

                    # Print the hash
                    print("SHA384 hash of '" + input_str + "':")
                    print(hashed_str)

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 3:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153),"\nSHA224 Encoding", attr(1), fg(105))  
                    
                    import hashlib

                    # Get input from user
                    input_str = input("Enter a string to Hash: ")

                    # Encode input string to bytes
                    input_bytes = input_str.encode('utf-8')

                    # Hash input bytes using SHA256
                    hashed_bytes = hashlib.sha224(input_bytes)

                    # Convert hashed bytes to hexadecimal representation
                    hashed_str = hashed_bytes.hexdigest()

                    # Print the hash
                    print("SHA224 hash of '" + input_str + "':")
                    print(hashed_str)

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 4:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153),"\nSHA512 Encoding", attr(1), fg(105))  
                    
                    import hashlib

                    # Get input from user
                    input_str = input("Enter a string to Hash: ")

                    # Encode input string to bytes
                    input_bytes = input_str.encode('utf-8')

                    # Hash input bytes using SHA256
                    hashed_bytes = hashlib.sha512(input_bytes)

                    # Convert hashed bytes to hexadecimal representation
                    hashed_str = hashed_bytes.hexdigest()

                    # Print the hash
                    print("SHA512 hash of '" + input_str + "':")
                    print(hashed_str)

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 5:

                x3 = 1
                while x3 == 1:
                
                    print(attr(1), fg(153),"\nSHA1 Encoding", attr(1), fg(105)) 
                    
                    import hashlib

                    # Get input from user
                    input_str = input("Enter a string to Hash: ")

                    # Encode input string to bytes
                    input_bytes = input_str.encode('utf-8')

                    # Hash input bytes using SHA256
                    hashed_bytes = hashlib.sha1(input_bytes)

                    # Convert hashed bytes to hexadecimal representation
                    hashed_str = hashed_bytes.hexdigest()

                    # Print the hash
                    print("SHA1 hash of '" + input_str + "':")
                    print(hashed_str)

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 6:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153),"\nMD5 Hash", attr(1), fg(105))
                    
                    import hashlib

                    # Get input from user
                    input_str = input("Enter a string to hash: ")

                    # Encode input string to bytes
                    input_bytes = input_str.encode('utf-8')

                    # Hash input bytes using MD5
                    hashed_bytes = hashlib.md5(input_bytes)

                    # Convert hashed bytes to hexadecimal representation
                    hashed_str = hashed_bytes.hexdigest()

                    # Print the hash
                    print("MD5 hash of '" + input_str + "':")
                    print(hashed_str)

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 7:
                    
                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153),"\nBase64:")

                    try:
                        base64 = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                    if base64 == 1:
                        print(attr(1), fg(105), "\nBase64 Encryption: ")
                        import base64
                        # Get user input
                        message = input("Enter Text to Encrypt: ")
                        # Encode the message in Base64
                        encoded_message = base64.b64encode(message.encode('utf-8'))
                        print("Encrypted Text: ", encoded_message)

                    elif base64 == 2:
                        print(attr(1), fg(105), "\nBase64 Decryption: ")
                        import base64
                        # Get user input
                        message = input("Enter Text to Decrypt: ")
                        # Decode the Base64 message
                        decoded_message = base64.b64decode(message).decode('utf-8')
                        print("Decoded Text: ", decoded_message)
                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 8:
                    
                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153),"\nCaesar Cipher: ")

                    try:
                        caesar_cipher = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                    if caesar_cipher == 1:
                        print(attr(1), fg(105), "\nCaesar Cipher Encryption: ")

                        plaintext = input("Enter Text to Encrypt: ")
                        shift = int(input("Enter Shift value: "))
                        
                        def encrypt_text(plaintext,shift):
                            ciphertext = ""
                            # Iterate over the given text
                            for i in range(len(plaintext)):
                                ch = plaintext[i]
                                # For empty space
                                if ch==" ":
                                    ciphertext+=" "
                                # For Uppercase Characters 
                                elif (ch.isupper()):
                                    ciphertext += chr((ord(ch) + shift-65) % 26 + 65)
                                # For Lowercase Characters
                                elif (ch.islower()):
                                    ciphertext += chr((ord(ch) + shift-97) % 26 + 97)
                                # For Special/Unsupported Characters
                                else:
                                    ciphertext+=ch
                            return ciphertext
                        encrypted_message = encrypt_text(plaintext,shift)
                        print("Encrypted Text: ", encrypted_message)

                    elif caesar_cipher == 2:
                        print(attr(1), fg(105), "\nCaesar Cipher Decryption:")
                        
                        ciphertext = input("Enter Text to Decrypt: ")
                        shift = int(input("Enter Shift value: "))
                        
                        def decrypt_text(ciphertext,shift):
                            plaintext = ""
                            # Iterate over the given text
                            for i in range(len(ciphertext)):
                                ch = ciphertext[i]
                                # For empty space 
                                if ch==" ":
                                    plaintext+=" "
                                # For Uppercase Characters 
                                elif (ch.isupper()):
                                    plaintext += chr((ord(ch) - shift-65) % 26 + 65)
                                # For Lowercase Characters
                                elif (ch.islower()):
                                    plaintext += chr((ord(ch) - shift-97) % 26 + 97)
                                # For Special/Unsupported Characters
                                else:
                                    plaintext+=ch
                            return plaintext
                        decrypted_message = decrypt_text(ciphertext,shift)
                        print("Decrypted Text: ", decrypted_message)

                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))


            if crypt == 9:
                    
                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153),"\nPlayfair Cipher:")

                    try:
                        playfair_cipher = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                    if playfair_cipher == 1:
                        print(attr(1), fg(105), "\nPlayfair Cipher Encryption:")

                        # Function to convert the string to lowercase
                        def toLowerCase(text):
                            return text.lower()

                        # Function to remove all spaces in a string
                        def removeSpaces(text):
                            newText = ""
                            for i in text:
                                if i == " ":
                                    continue
                                else:
                                    newText = newText + i
                            return newText

                        # Function to group 2 elements of a string as a list element
                        def Diagraph(text):
                            Diagraph = []
                            group = 0
                            for i in range(2, len(text), 2):
                                Diagraph.append(text[group:i])

                                group = i
                            Diagraph.append(text[group:])
                            return Diagraph

                        # Function to fill a letter in a string element
                        # If 2 letters in the same string matches
                        def FillerLetter(text):
                            k = len(text)
                            if k % 2 == 0:
                                for i in range(0, k, 2):
                                    if text[i] == text[i+1]:
                                        new_word = text[0:i+1] + str('x') + text[i+1:]
                                        new_word = FillerLetter(new_word)
                                        break
                                    else:
                                        new_word = text
                            else:
                                for i in range(0, k-1, 2):
                                    if text[i] == text[i+1]:
                                        new_word = text[0:i+1] + str('x') + text[i+1:]
                                        new_word = FillerLetter(new_word)
                                        break
                                    else:
                                        new_word = text
                            return new_word

                        list1 = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'k', 'l', 'm',
                                'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z']

                        # Function to generate the 5x5 key square matrix
                        def generateKeyTable(word, list1):
                            key_letters = []
                            for i in word:
                                if i not in key_letters:
                                    key_letters.append(i)

                            compElements = []
                            for i in key_letters:
                                if i not in compElements:
                                    compElements.append(i)
                            for i in list1:
                                if i not in compElements:
                                    compElements.append(i)

                            matrix = []
                            while compElements != []:
                                matrix.append(compElements[:5])
                                compElements = compElements[5:]

                            return matrix

                        def search(mat, element):
                            for i in range(5):
                                for j in range(5):
                                    if(mat[i][j] == element):
                                        return i, j

                        def encrypt_RowRule(matr, e1r, e1c, e2r, e2c):
                            char1 = ''
                            if e1c == 4:
                                char1 = matr[e1r][0]
                            else:
                                char1 = matr[e1r][e1c+1]

                            char2 = ''
                            if e2c == 4:
                                char2 = matr[e2r][0]
                            else:
                                char2 = matr[e2r][e2c+1]

                            return char1, char2


                        def encrypt_ColumnRule(matr, e1r, e1c, e2r, e2c):
                            char1 = ''
                            if e1r == 4:
                                char1 = matr[0][e1c]
                            else:
                                char1 = matr[e1r+1][e1c]

                            char2 = ''
                            if e2r == 4:
                                char2 = matr[0][e2c]
                            else:
                                char2 = matr[e2r+1][e2c]

                            return char1, char2

                        def encrypt_RectangleRule(matr, e1r, e1c, e2r, e2c):
                            char1 = ''
                            char1 = matr[e1r][e2c]

                            char2 = ''
                            char2 = matr[e2r][e1c]

                            return char1, char2

                        def encryptByPlayfairCipher(Matrix, plainList):
                            CipherText = []
                            for i in range(0, len(plainList)):
                                c1 = 0
                                c2 = 0
                                ele1_x, ele1_y = search(Matrix, plainList[i][0])
                                ele2_x, ele2_y = search(Matrix, plainList[i][1])

                                if ele1_x == ele2_x:
                                    c1, c2 = encrypt_RowRule(Matrix, ele1_x, ele1_y, ele2_x, ele2_y)
                                    # Get 2 letter cipherText
                                elif ele1_y == ele2_y:
                                    c1, c2 = encrypt_ColumnRule(Matrix, ele1_x, ele1_y, ele2_x, ele2_y)
                                else:
                                    c1, c2 = encrypt_RectangleRule(
                                        Matrix, ele1_x, ele1_y, ele2_x, ele2_y)

                                cipher = c1 + c2
                                CipherText.append(cipher)
                            return CipherText


                        text_Plain = input("Enter Plain Text to Encrypt: ")
                        text_Plain = removeSpaces(toLowerCase(text_Plain))
                        PlainTextList = Diagraph(FillerLetter(text_Plain))
                        if len(PlainTextList[-1]) != 2:
                            PlainTextList[-1] = PlainTextList[-1]+'z'

                        key = input("Enter Key for Encryption: ")
                        
                        key = toLowerCase(key)
                        Matrix = generateKeyTable(key, list1)

                        CipherList = encryptByPlayfairCipher(Matrix, PlainTextList)

                        CipherText = ""
                        for i in CipherList:
                            CipherText += i
                        print("Encrypted Text: ", CipherText)


                    elif playfair_cipher == 2:
                        print(attr(1), fg(105), "\nPlayfair Cipher Decryption:")
                        # Define the Playfair decryption function
                        def playfair_decrypt(ciphertext, key):
                            # Create the Playfair square
                            alphabet = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
                            square = [['' for x in range(5)] for y in range(5)]
                            key = key.upper().replace("J", "I") + alphabet
                            key = ''.join(sorted(set(key), key=key.index))
                            k = 0
                            for i in range(5):
                                for j in range(5):
                                    square[i][j] = key[k]
                                    k += 1

                            # Remove any whitespace and make the ciphertext uppercase
                            ciphertext = ''.join(ciphertext.split()).upper().replace("J", "I")

                            # Split the ciphertext into pairs of letters
                            pairs = []
                            for i in range(0, len(ciphertext), 2):
                                if i == len(ciphertext) - 1:
                                    pairs.append(ciphertext[i] + 'X')
                                elif ciphertext[i] == ciphertext[i+1]:
                                    pairs.append(ciphertext[i] + 'X')
                                else:
                                    pairs.append(ciphertext[i:i+2])

                            # Decrypt each pair of letters
                            plaintext = ''
                            for pair in pairs:
                                letter1, letter2 = pair
                                row1, col1 = 0, 0
                                row2, col2 = 0, 0
                                for i in range(5):
                                    for j in range(5):
                                        if square[i][j] == letter1:
                                            row1, col1 = i, j
                                        elif square[i][j] == letter2:
                                            row2, col2 = i, j
                                if row1 == row2:
                                    plaintext += square[row1][(col1-1)%5] + square[row2][(col2-1)%5]
                                elif col1 == col2:
                                    plaintext += square[(row1-1)%5][col1] + square[(row2-1)%5][col2]
                                else:
                                    plaintext += square[row1][col2] + square[row2][col1]

                            # Remove any trailing X's
                            if plaintext[-1] == 'X':
                                plaintext = plaintext[:-1]

                            # Return the plaintext
                            return plaintext

                        # Get user input
                        ciphertext = input("Enter Ciphertext to Decrypt: ")
                        key = input("Enter Key for Decryption: ")

                        # Decrypt the ciphertext
                        plaintext = playfair_decrypt(ciphertext, key)

                        # Print the plaintext
                        print("Decrypted Text: " + plaintext)

                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 10:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153), "\nROT13")

                    try:
                        rot13 = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                    if rot13 == 1:
                        print(attr(1), fg(105), "\nROT13 Encryption:")
                        # Define the alphabet and special characters
                        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?\\ "
                        n = len(alphabet)

                        # Function to encrypt a message using ROT13
                        def encrypt(message):
                            encrypted_message = ""
                            for char in message:
                                if char == " ":
                                    encrypted_message += " "
                                elif char in alphabet:
                                    index = (alphabet.index(char) + 13) % n
                                    encrypted_message += alphabet[index]
                                else:
                                    encrypted_message += char
                            return encrypted_message
                        
                        # Get the message from user input
                        message = input("Enter Text to Encrypt: ")
                        # Encrypt the message using ROT13
                        encrypted_message = encrypt(message)
                        print("Encrypted Text: ", encrypted_message)

                    elif rot13 == 2:
                        print(attr(1), fg(105), "\nROT13 Decryption:")
                        # Define the alphabet and special characters
                        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?\\ "
                        n = len(alphabet)

                        # Function to decrypt a message using ROT13
                        def decrypt(encrypted_message):
                            decrypted_message = ""
                            for char in encrypted_message:
                                if char == " ":
                                    decrypted_message += " "
                                elif char in alphabet:
                                    index = (alphabet.index(char) - 13) % n
                                    decrypted_message += alphabet[index]
                                else:
                                    decrypted_message += char
                            return decrypted_message

                        # Get the decrypted message from user input
                        encrypted_message = input("Enter Text to Decrypt: ")
                        # Decrypt the message using ROT13
                        decrypted_message = decrypt(encrypted_message)
                        print("Decrypted Text: ", decrypted_message)


                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 11:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153), "\nROT47")
                
                    try:
                        rot47 = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                    if rot47 == 1:
                        print(attr(1), fg(105), "\nROT47 Encryption:")
                        # Define the alphabet and special characters
                        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?\\ "
                        n = len(alphabet)

                        # Function to encrypt a message using ROT47
                        def encrypt(message):
                            encrypted_message = ""
                            for char in message:
                                if char == " ":
                                    encrypted_message += " "
                                elif char in alphabet:
                                    index = (alphabet.index(char) + 47) % n
                                    encrypted_message += alphabet[index]
                                else:
                                    encrypted_message += char
                            return encrypted_message
                        
                        # Get the message from user input
                        message = input("Enter Text to Encrypt: ")
                        # Encrypt the message using ROT47
                        encrypted_message = encrypt(message)
                        print("Encrypted message: ", encrypted_message)

                    elif rot47 == 2:
                        print(attr(1), fg(105), "\nROT47 Decryption:")
                        # Define the alphabet and special characters
                        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;':\",./<>?\\ "
                        n = len(alphabet)

                        # Function to decrypt a message using ROT47
                        def decrypt(encrypted_message):
                            decrypted_message = ""
                            for char in encrypted_message:
                                if char == " ":
                                    decrypted_message += " "
                                elif char in alphabet:
                                    index = (alphabet.index(char) - 47) % n
                                    decrypted_message += alphabet[index]
                                else:
                                    decrypted_message += char
                            return decrypted_message

                        # Get the decrypted message from user input
                        encrypted_message = input("Enter Text to Decrypt: ")
                        # Decrypt the message using ROT13
                        decrypted_message = decrypt(encrypted_message)
                        print("Decrypted Text: ", decrypted_message)


                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                    
                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



            elif crypt == 12:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153), "\nMorse Code:")

                    try:
                        morse_code = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print(attr(1), fg(1),"\nIllegal action, try again.")

                    if morse_code == 1:
                        print(attr(1), fg(105), "\nMorse Code Encryption: ")
                        morse_code = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', ' ': '/'}

                        def to_morse_code(text):
                            morse_text = ''
                            for letter in text.upper():
                                if letter in morse_code:
                                    morse_text += morse_code[letter] + ' '
                                else:
                                    morse_text += letter
                            return morse_text
                        user_input = input("Enter Text to Encrypt in Morse Code: ")
                        morse_text = to_morse_code(user_input)
                        print("Morse Code: ", morse_text)

                    elif morse_code == 2:
                        print(attr(1), fg(105), "\nMorse Code Decryption:")
                        morse_code = {'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.', 'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..', 'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.', 'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-', 'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---', '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...', '8': '---..', '9': '----.', ' ': '/'}
                        def from_morse_code(morse_text):
                            text = ''
                            morse_to_char = {v: k for k, v in morse_code.items()}
                            for morse_letter in morse_text.split(' '):
                                if morse_letter in morse_to_char:
                                    text += morse_to_char[morse_letter]
                                elif morse_letter == '/':
                                    text += ' '
                            return text
                        decryption_input = input("Enter the Morse Code to Decrypt: ")
                        text = from_morse_code(decryption_input)
                        print("Decrypted Text: ", text)

                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                
                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))




            elif crypt == 13:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153), "\nBinary Code:")

                    try:
                        binary = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print("\nIllegal action, try again.")

                    def encrypt(message):
                        binary_message = ' '.join(format(ord(char), '08b') for char in message)
                        return binary_message

                    def decrypt(binary_message):
                        binary_message = binary_message.replace(' ', '')
                        binary_chunks = [binary_message[i:i+8] for i in range(0, len(binary_message), 8)]
                        message = ''.join(chr(int(chunk, 2)) for chunk in binary_chunks)
                        return message
                    
                    if binary == 1:
                        print(attr(1), fg(105), "\nBinary Code Encryption:")
                        message = input("Enter Text to Encrypt: ")
                        encrypted_message = encrypt(message)
                        print("Encrypted Text: ", encrypted_message)

                    elif binary == 2:
                        print(attr(1), fg(105), "\nBinary Code Decryption:")
                        binary_message = input("Enter Text to Decrypt: ")
                        decrypted_message = decrypt(binary_message)
                        print("Decrypted Text: ", decrypted_message)

                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                    
                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))




            elif crypt == 14:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153), "\nDecimal Code:")

                    try:
                        decimal = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print("\nIllegal action, try again.")

                    def ascii_to_decimal(character):
                        decimal_number = ord(character)
                        return decimal_number

                    def decimal_to_ascii(decimal_number):
                        character = chr(decimal_number)
                        return character

                    if decimal == 1:
                        print(attr(1), fg(105), "\nDecimal Code Encryption:")
                        text = input("Enter Text to Encrypt: ")
                        decimal_str = " ".join(str(ascii_to_decimal(character)) for character in text)
                        print("Encrypted Text: ", decimal_str)

                    elif decimal == 2:
                        print(attr(1), fg(105), "\nDecimal Code Decryption:")
                        decimal_list = input("Enter Text to Decrypt: ").split()
                        ascii_text = "".join([decimal_to_ascii(int(decimal_number)) for decimal_number in decimal_list])
                        print("Decrypted Text: ", ascii_text)

                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")

                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))


            elif crypt == 15:

                x3 = 1
                while x3 == 1:

                    print(attr(1), fg(153), "\nHexadecimal Code:")

                    try:
                        hexadecimal = int(input("1. Encryption \n2. Decryption \nYou Chose: "))
                    except:
                        print("\nIllegal action, try again.")

                    def hex_to_ascii(hex_string):
                        ascii_string = bytes.fromhex(hex_string.replace(' ', '')).decode('utf-8')
                        return ascii_string

                    def ascii_to_hex(ascii_string):
                        hex_string = ascii_string.encode('utf-8').hex()
                        return ' '.join(hex_string[i:i+2] for i in range(0, len(hex_string), 2))

                    if hexadecimal == 1:
                        print(attr(1), fg(105), "\nHexadecimal Code Encryption:")
                        ascii_text = input("Enter Text to Encrypt: ")
                        hex_string = ascii_to_hex(ascii_text)
                        print("Encrypted Text: ", hex_string)

                    elif hexadecimal == 2:
                        print(attr(1), fg(105), "\nHexadecimal Code Decryption:")
                        hex_string = input("Enter Text to Decrypt: ")
                        ascii_text = hex_to_ascii(hex_string)
                        print("Decrypted Text: ", ascii_text)

                    else:
                        print(attr(1), fg(1),"\nIllegal action, try again.")
                    
                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))

            x2 = int(input("Visit Algorithms again?[1=Yes / 0=No]: "))



    elif action == 2:

        x2 = 1
        while x2 == 1:

            print(attr(1), fg(178),"\nSteganography:")
            try:
                stegano = int(input("1. IMAGE Steganography \n2. VIDEO Steganography \n3. AUDIO Steganography \n4. TEXT Steganography \nSelect a Steganography Algorithm: "))
            except:
                print(attr(1), fg(1), "\nIllegal action, try again.")


            if stegano == 1:

                x3 = 1
                while x3 == 1:

                    from PIL import Image

                    # Convert encoding data into 8-bit binary
                    # form using ASCII value of characters
                    def genData(data):

                            # list of binary codes
                            # of given data
                            newd = []

                            for i in data:
                                newd.append(format(ord(i), '08b'))
                            return newd

                    # Pixels are modified according to the
                    # 8-bit binary data and finally returned
                    def modPix(pix, data):

                        datalist = genData(data)
                        lendata = len(datalist)
                        imdata = iter(pix)

                        for i in range(lendata):

                            # Extracting 3 pixels at a time
                            pix = [value for value in imdata.__next__()[:3] +
                                                    imdata.__next__()[:3] +
                                                    imdata.__next__()[:3]]

                            # Pixel value should be made
                            # odd for 1 and even for 0
                            for j in range(0, 8):
                                if (datalist[i][j] == '0' and pix[j]% 2 != 0):
                                    pix[j] -= 1

                                elif (datalist[i][j] == '1' and pix[j] % 2 == 0):
                                    if(pix[j] != 0):
                                        pix[j] -= 1
                                    else:
                                        pix[j] += 1
                                    # pix[j] -= 1

                            # Eighth pixel of every set tells
                            # whether to stop ot read further.
                            # 0 means keep reading; 1 means thec
                            # message is over.
                            if (i == lendata - 1):
                                if (pix[-1] % 2 == 0):
                                    if(pix[-1] != 0):
                                        pix[-1] -= 1
                                    else:
                                        pix[-1] += 1

                            else:
                                if (pix[-1] % 2 != 0):
                                    pix[-1] -= 1

                            pix = tuple(pix)
                            yield pix[0:3]
                            yield pix[3:6]
                            yield pix[6:9]

                    def encode_enc(newimg, data):
                        w = newimg.size[0]
                        (x, y) = (0, 0)

                        for pixel in modPix(newimg.getdata(), data):

                            # Putting modified pixels in the new image
                            newimg.putpixel((x, y), pixel)
                            if (x == w - 1):
                                x = 0
                                y += 1
                            else:
                                x += 1

                    # Encode data into image
                    def encode():
                        print(attr(1), fg(105), "\nIMAGE Stegano Encryption:")
                        img = input("Image to hide the message in[with extension]: ")
                        image = Image.open(img, 'r')

                        data = input("Message to hide:  ")
                        if (len(data) == 0):
                            raise ValueError('Data is Empty')

                        newimg = image.copy()
                        encode_enc(newimg, data)

                        new_img_name = input("New image name[with extension]: ")
                        newimg.save(new_img_name, str(new_img_name.split(".")[1].upper()))

                    # Decode the data in the image
                    def decode():
                        print(attr(1), fg(105), "\nIMAGE Stegano Decryption:")
                        img = input("Image to extract hidden message from[with extension]: ")
                        image = Image.open(img, 'r')

                        data = ''
                        imgdata = iter(image.getdata())

                        while (True):
                            pixels = [value for value in imgdata.__next__()[:3] +
                                                    imgdata.__next__()[:3] +
                                                    imgdata.__next__()[:3]]

                            # string of binary data
                            binstr = ''

                            for i in pixels[:8]:
                                if (i % 2 == 0):
                                    binstr += '0'
                                else:
                                    binstr += '1'

                            data += chr(int(binstr, 2))
                            if (pixels[-1] % 2 != 0):
                                return data

                    # Main Function
                    def main():
                        print(attr(1), fg(153), "\nIMAGE Steganography")
                        a = int(input("1. Encode \n2. Decode \nYou Chose: "))
                        if (a == 1):
                            encode()

                        elif (a == 2):
                            print("Decoded Word :  " + decode())
                        else:
                            print(attr(1), fg(1),"\nIllegal action, try again.")

                    # Driver Code
                    if __name__ == '__main__' :

                        # Calling main function
                        main()
                    
                    x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))
            


            elif stegano == 2:

                import numpy as np
                import pandas as pand
                import os
                import cv2
                from PIL import Image
                from matplotlib import pyplot as plt

                def msgtobinary(msg):
                    if type(msg) == str:
                        result= ''.join([ format(ord(i), "08b") for i in msg ])
                    
                    elif type(msg) == bytes or type(msg) == np.ndarray:
                        result= [ format(i, "08b") for i in msg ]
                    
                    elif type(msg) == int or type(msg) == np.uint8:
                        result=format(msg, "08b")

                    else:
                        raise TypeError(attr(1), fg(1), "Input type is not supported in this function.")
                    
                    return result


                def KSA(key):
                    key_length = len(key)
                    S=list(range(256)) 
                    j=0
                    for i in range(256):
                        j=(j+S[i]+key[i % key_length]) % 256
                        S[i],S[j]=S[j],S[i]
                    return S


                def PRGA(S,n):
                    i=0
                    j=0
                    key=[]
                    while n>0:
                        n=n-1
                        i=(i+1)%256
                        j=(j+S[i])%256
                        S[i],S[j]=S[j],S[i]
                        K=S[(S[i]+S[j])%256]
                        key.append(K)
                    return key


                def preparing_key_array(s):
                    return [ord(c) for c in s]


                def encryption(plaintext):
                    print("Enter the key: ")
                    key=input()
                    key=preparing_key_array(key)

                    S=KSA(key)

                    keystream=np.array(PRGA(S,len(plaintext)))
                    plaintext=np.array([ord(i) for i in plaintext])

                    cipher=keystream^plaintext
                    ctext=''
                    for c in cipher:
                        ctext=ctext+chr(c)
                    return ctext


                def decryption(ciphertext):
                    print("Enter the key: ")
                    key=input()
                    key=preparing_key_array(key)

                    S=KSA(key)

                    keystream=np.array(PRGA(S,len(ciphertext)))
                    ciphertext=np.array([ord(i) for i in ciphertext])

                    decoded=keystream^ciphertext
                    dtext=''
                    for c in decoded:
                        dtext=dtext+chr(c)
                    return dtext


                def embed(frame):
                    data=input("\nEnter the data to be Encoded in Video: ") 
                    data=encryption(data)
                    if (len(data) == 0): 
                        raise ValueError(attr(1), fg(1), 'Data entered to be encoded is empty.')

                    data +='*^*^*'
                    
                    binary_data=msgtobinary(data)
                    length_data = len(binary_data)
                    
                    index_data = 0
                    
                    for i in frame:
                        for pixel in i:
                            r, g, b = msgtobinary(pixel)
                            if index_data < length_data:
                                pixel[0] = int(r[:-1] + binary_data[index_data], 2) 
                                index_data += 1
                            if index_data < length_data:
                                pixel[1] = int(g[:-1] + binary_data[index_data], 2) 
                                index_data += 1
                            if index_data < length_data:
                                pixel[2] = int(b[:-1] + binary_data[index_data], 2) 
                                index_data += 1
                            if index_data >= length_data:
                                break
                        return frame


                def extract(frame):
                    data_binary = ""
                    final_decoded_msg = ""
                    for i in frame:
                        for pixel in i:
                            r, g, b = msgtobinary(pixel) 
                            data_binary += r[-1]  
                            data_binary += g[-1]  
                            data_binary += b[-1]  
                            total_bytes = [ data_binary[i: i+8] for i in range(0, len(data_binary), 8) ]
                            decoded_data = ""
                            for byte in total_bytes:
                                decoded_data += chr(int(byte, 2))
                                if decoded_data[-5:] == "*^*^*": 
                                    for i in range(0,len(decoded_data)-5):
                                        final_decoded_msg += decoded_data[i]
                                    final_decoded_msg = decryption(final_decoded_msg)
                                    print("The Encoded data which was hidden in the Video was: ",final_decoded_msg)
                                    return 


                def encode_vid_data():
                    video_file = input("\nEnter the name of the Video file[with extention]: ")
                    new_file_name = input("Enter the name of the Stegano Video file to be generated[with extention]: ")
                    cap=cv2.VideoCapture(video_file)
                    vidcap = cv2.VideoCapture(video_file)
                    fourcc = cv2.VideoWriter_fourcc(*'mp4v')
                    frame_width = int(cap.get(3))
                    frame_height = int(cap.get(4))
                    size = (frame_width, frame_height)
                    out = cv2.VideoWriter(new_file_name, fourcc, 25.0, size)
                    
                    max_frame=0;
                    while(cap.isOpened()):
                        ret, frame = cap.read()
                        if ret == False:
                            break 
                        max_frame+=1
                    cap.release()
                    print("Total number of Frame in selected Video: ",max_frame)
                    print("Enter the frame number to embed data: ")
                    n=int(input())
                    frame_number = 0
                    while(vidcap.isOpened()):
                        frame_number += 1
                        ret, frame = vidcap.read()
                        if ret == False:
                            break
                        if frame_number == n:    
                            change_frame_with = embed(frame)
                            frame_ = change_frame_with
                            frame = change_frame_with
                        out.write(frame)
                    
                    print("Encoded the data successfully in the video file.\n")
                    return frame_


                def decode_vid_data(frame_):
                    filename = input("\nEnter the name of the Stegano Video file[with extention]: ")
                    cap = cv2.VideoCapture(filename)
                    max_frame = 0
                    while(cap.isOpened()):
                        ret, frame = cap.read()
                        if ret == False:
                            break
                        max_frame += 1
                    print("Total number of Frame in selected Video: ", max_frame)
                    n = int(input("Enter the frame number to extract the data from: "))
                    vidcap = cv2.VideoCapture(filename)
                    # rest of the code

                    frame_number = 0
                    while(vidcap.isOpened()):
                        frame_number += 1
                        ret, frame = vidcap.read()
                        if ret == False:
                            break
                        if frame_number == n:
                            extract(frame_)
                            return


                def vid_steg():
                    x3 = 1
                    while x3 == 1:
                        print(attr(1), fg(153), "\nVIDEO Stegnography")
                        choice1 = int(input("1. VIDEO Encode\n2. VIDEO Decode\nYou Chose: "))   
                        if choice1 == 1:
                            print(attr(1), fg(105), "\nVIDEO Encode")
                            a=encode_vid_data()
                        elif choice1 == 2:
                            print(attr(1), fg(105), "\nVIDEO Decode")
                            decode_vid_data(a)
                        else:
                            print(attr(1), fg(1), "Illegal action, try again.")
                        x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



                # Driver Code
                if __name__ == '__main__' :
                    # Calling main function
                    vid_steg()



            elif stegano == 3:

                def encode_aud_data():
                    import wave

                    nameoffile=input("\nEnter the name of the Audio file[with extention]: ")
                    song = wave.open(nameoffile, mode='rb')

                    nframes=song.getnframes()
                    frames=song.readframes(nframes)
                    frame_list=list(frames)
                    frame_bytes=bytearray(frame_list)

                    data = input("Enter the data to be Encoded in Audio: ")

                    res = ''.join(format(i, '08b') for i in bytearray(data, encoding ='utf-8'))     
                    length = len(res)
                    data = data + '*^*^*'

                    result = []
                    for c in data:
                        bits = bin(ord(c))[2:].zfill(8)
                        result.extend([int(b) for b in bits])

                    j = 0
                    for i in range(0,len(result),1): 
                        res = bin(frame_bytes[j])[2:].zfill(8)
                        if res[len(res)-4]== result[i]:
                            frame_bytes[j] = (frame_bytes[j] & 253)      #253: 11111101
                        else:
                            frame_bytes[j] = (frame_bytes[j] & 253) | 2
                            frame_bytes[j] = (frame_bytes[j] & 254) | result[i]
                        j = j + 1
                    
                    frame_modified = bytes(frame_bytes)

                    stegofile=input("Enter the name of the Stegano Audio file to be generated[with extention]: ")
                    with wave.open(stegofile, 'wb') as fd:
                        fd.setparams(song.getparams())
                        fd.writeframes(frame_modified)
                    print("Encoded the data successfully in the audio file.\n")    
                    song.close()


                def decode_aud_data():
                    import wave

                    nameoffile=input("\nEnter the name of the Stegano Audio file[with extention]: ")
                    song = wave.open(nameoffile, mode='rb')

                    nframes=song.getnframes()
                    frames=song.readframes(nframes)
                    frame_list=list(frames)
                    frame_bytes=bytearray(frame_list)

                    extracted = ""
                    p=0
                    for i in range(len(frame_bytes)):
                        if(p==1):
                            break
                        res = bin(frame_bytes[i])[2:].zfill(8)
                        if res[len(res)-2]==0:
                            extracted+=res[len(res)-4]
                        else:
                            extracted+=res[len(res)-1]
                    
                        all_bytes = [ extracted[i: i+8] for i in range(0, len(extracted), 8) ]
                        decoded_data = ""
                        for byte in all_bytes:
                            decoded_data += chr(int(byte, 2))
                            if decoded_data[-5:] == "*^*^*":
                                print("The Encoded data which was hidden in the Audio was: ",decoded_data[:-5])
                                p=1
                                break  


                def aud_steg():
                    x3 = 1
                    while x3 == 1:
                        print(attr(1), fg(153), "\nAUDIO Stegnography")
                        choice1 = int(input("1. AUDIO Encode\n2. AUDIO Decode\nYou Chose: "))   
                        if choice1 == 1:
                            print(attr(1), fg(105), "\nAUDIO Encode")
                            encode_aud_data()
                        elif choice1 == 2:
                            print(attr(1), fg(105), "\nAUDIO Decode")
                            decode_aud_data()
                        else:
                            print(attr(1), fg(1), "Illegal action, try again.")
                        x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))



                if __name__ == "__main__":
                    aud_steg()


        
            elif stegano == 4:

                def txt_encode(text, input_file):
                    l=len(text)
                    i=0
                    add=''
                    while i<l:
                        t=ord(text[i])
                        if(t>=32 and t<=64):
                            t1=t+48
                            t2=t1^170       #170: 10101010
                            res = bin(t2)[2:].zfill(8)
                            add+="0011"+res
                        
                        else:
                            t1=t-48
                            t2=t1^170
                            res = bin(t2)[2:].zfill(8)
                            add+="0110"+res
                        i+=1
                    res1=add+"111111111111"
                    HM_SK=""
                    ZWC={"00":u'\u200C',"01":u'\u202C',"11":u'\u202D',"10":u'\u200E'}      
                    
                    nameoffile = input("Enter the name of the Stegano Text file to be generated[with extention]: ")
                    file1 = open(input_file,"r+")
                    file3= open(nameoffile,"w+", encoding="utf-8")
                    word=[]
                    for line in file1: 
                        word+=line.split()
                    i=0
                    while(i<len(res1)):  
                        s=word[int(i/12)]
                        j=0
                        x=""
                        HM_SK=""
                        while(j<12):
                            x=res1[j+i]+res1[i+j+1]
                            HM_SK+=ZWC[x]
                            j+=2
                        s1=s+HM_SK
                        file3.write(s1)
                        file3.write(" ")
                        i+=12
                    t=int(len(res1)/12)     
                    while t<len(word): 
                        file3.write(word[t])
                        file3.write(" ")
                        t+=1
                    file3.close()  
                    file1.close()
                    print("File Generated Successfully.\n")


                def encode_txt_data():
                    count2=0
                    input_file = input("\nEnter the name of the Text file[with extention]: ")
                    file1 = open(input_file,"r")
                    for line in file1: 
                        for word in line.split():
                            count2=count2+1
                    file1.close()       
                    bt=int(count2)
                    print("Maximum number of words that can be Inserted: ",int(bt/6))
                    text1=input("Enter the data to be Encoded in TXT: ")
                    l=len(text1)
                    if(l<=bt):
                        txt_encode(text1, input_file)
                    else:
                        print("String is too long, try again.")
                        encode_txt_data()

                def BinaryToDecimal(binary):
                    string = int(binary, 2)
                    return string

                def decode_txt_data():
                    ZWC_reverse={u'\u200C':"00",u'\u202C':"01",u'\u202D':"11",u'\u200E':"10"}
                    stego=input("\nEnter the name of the Stegano Text file[with extention]: ")
                    file4= open(stego,"r", encoding="utf-8")
                    temp=''
                    for line in file4: 
                        for words in line.split():
                            T1=words
                            binary_extract=""
                            for letter in T1:
                                if(letter in ZWC_reverse):
                                    binary_extract+=ZWC_reverse[letter]
                            if binary_extract=="111111111111":
                                break
                            else:
                                temp+=binary_extract
                    lengthd = len(temp)
                    i=0
                    a=0
                    b=4
                    c=4
                    d=12
                    final=''
                    while i<len(temp):
                        t3=temp[a:b]
                        a+=12
                        b+=12
                        i+=12
                        t4=temp[c:d]
                        c+=12
                        d+=12
                        if(t3=='0110'):
                            decimal_data = BinaryToDecimal(t4)
                            final+=chr((decimal_data ^ 170) + 48)
                        elif(t3=='0011'):
                            decimal_data = BinaryToDecimal(t4)
                            final+=chr((decimal_data ^ 170) - 48)
                    print("The Encoded data which was hidden in the Text was: ",final)


                def txt_steg():
                    x3 = 1
                    while x3 == 1:
                        print(attr(1), fg(153), "\nTEXT Stegnography")
                        choice1 = int(input("1. TEXT Encode\n2. TEXT Decode\nYou Chose: "))   
                        if choice1 == 1:
                            print(attr(1), fg(105), "\nTEXT Encode")
                            encode_txt_data()
                        elif choice1 == 2:
                            print(attr(1), fg(105), "\nTEXT Decode")
                            decrypted=decode_txt_data() 
                        else:
                            print(attr(1), fg(1), "Illegal action, try again.")
                        x3 = int(input("Do you want to try again?[1=Yes / 0=No]: "))


                # Driver Code
                if __name__ == '__main__' :
                    # Calling main function
                    txt_steg()




            x2 = int(input("Visit Algorithms again?[1=Yes / 0=No]: "))


    else:
        print(attr(1), fg(1),"\nIllegal action, try again.")

    x1 = int(input("Revisit main Menu?[1=Yes / 0=No]: "))

    