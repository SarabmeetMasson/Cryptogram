print("What would you like to do?\n1. Cryptography\n2. Stegnography")
try:
    action = int(input("You Chose: "))
except:
    print("Illegal action, try again.")

if action == 1:
    print("Cryptography:")
    try:
        crypt = int(input("1. SHA256 \n2. SHA384 \n3. SHA224 \n4. SHA512 \n5. SHA1 \n6. MD5 \n7. base64 \n8. Caesar Cipher \n9. Playfair Cipher \n10. ROT13 \n11. ROT47 \n12. Morse Code \n13. Binary \n14. Decimal \n15. Hexadecimal \nSelect a Cryptography Algorithm: "))
    except:
        print("Illegal action, try again.")



    if crypt == 1:
        print("SHA256 Encoding")        
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



    elif crypt == 2:
        print("SHA384 Encoding")        
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



    elif crypt == 3:
        print("SHA224 Encoding")        
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



    elif crypt == 4:
        print("SHA512 Encoding")        
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



    elif crypt == 5:
        print("SHA1 Encoding")        
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



    elif crypt == 6:
        print("MD5 Hash:")
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



    elif crypt == 7:
        try:
            base64 = int(input("base64: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if base64 == 1:
            print("base64 Encryption:")
            import base64
            # Get user input
            message = input("Enter a message to Encode: ")
            # Encode the message in Base64
            encoded_message = base64.b64encode(message.encode('utf-8'))
            print("Encoded message:", encoded_message)

        elif base64 == 2:
            print("base64 Decryption:")
            import base64
            # Get user input
            message = input("Enter a message to Decode: ")
            # Decode the Base64 message
            decoded_message = base64.b64decode(message).decode('utf-8')
            print("Decoded message:", decoded_message)
        else:
            print("Error, Try again.")



    elif crypt == 8:
        try:
            caesar_cipher = int(input("Caesar Cipher: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if caesar_cipher == 1:
            print("Caesar Cipher Encryption:")

            plaintext = input("Enter message to Encrypt: ")
            shift = int(input("Enter shift value: "))
            
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
            print("Encrypted message:", encrypted_message)

        elif caesar_cipher == 2:
            print("Caesar Cipher Decryption:")
            
            ciphertext = input("Enter message to Decrypt: ")
            shift = int(input("Enter shift value: "))
            
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
            print("Decrypted message:", decrypted_message)

        else:
            print("Error, Try again.")



    if crypt == 9:
        try:
            playfair_cipher = int(input("Playfair Cipher: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if playfair_cipher == 1:
            print("Playfair Cipher Encryption:")

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
            print("CipherText:", CipherText)


        elif playfair_cipher == 2:
            print("Playfair Cipher Decryption:")
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
            print("Plaintext: " + plaintext)

        else:
            print("Error, Try again.")



    elif crypt == 10:
        try:
            rot13 = int(input("ROT13: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if rot13 == 1:
            print("ROT13 Encryption:")
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
            message = input("Enter the message to Encrypt: ")
            # Encrypt the message using ROT13
            encrypted_message = encrypt(message)
            print("Encrypted message:", encrypted_message)

        elif rot13 == 2:
            print("ROT13 Decryption:")
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
            encrypted_message = input("Enter the message to Decrypt: ")
            # Decrypt the message using ROT13
            decrypted_message = decrypt(encrypted_message)
            print("Decrypted message:", decrypted_message)


        else:
            print("Error, Try again.")



    elif crypt == 11:
        try:
            rot47 = int(input("ROT47: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if rot47 == 1:
            print("ROT47 Encryption:")
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
            message = input("Enter the message to Encrypt: ")
            # Encrypt the message using ROT47
            encrypted_message = encrypt(message)
            print("Encrypted message:", encrypted_message)

        elif rot47 == 2:
            print("ROT47 Decryption:")
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
            encrypted_message = input("Enter the message to Decrypt: ")
            # Decrypt the message using ROT13
            decrypted_message = decrypt(encrypted_message)
            print("Decrypted message:", decrypted_message)


        else:
            print("Error, Try again.")



    elif crypt == 12:
        try:
            morse_code = int(input("Morse Code: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if morse_code == 1:
            print("Morse Code Encryption:")

        elif morse_code == 2:
            print("Morse Code Decryption:")

        else:
            print("Error, Try again.")



    elif crypt == 13:
        try:
            binary = int(input("Binary Code: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if binary == 1:
            print("Binary Code Encryption:")

        elif binary == 2:
            print("Binary Code Decryption:")

        else:
            print("Error, Try again.")



    elif crypt == 14:
        try:
            decimal = int(input("Decimal Code: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if decimal == 1:
            print("Decimal Code Encryption:")

        elif decimal == 2:
            print("Decimal Code Decryption:")

        else:
            print("Error, Try again.")



    elif crypt == 15:
        try:
            hexadecimal = int(input("Hexadecimal Code: \n1. Encryption \n2. Decryption \nYou Chose: "))
        except:
            print("Illegal action, try again.")
        if hexadecimal == 1:
            print("Hexadecimal Code Encryption:")

        elif hexadecimal == 2:
            print("Hexadecimal Code Decryption:")

        else:
            print("Error, Try again.")



elif action == 2:
    # PIL module is used to extract
    # pixels of image and modify it
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
        a = int(input("Image Stegnography \n1. Encode \n2. Decode \nYou Chose: "))
        if (a == 1):
            encode()

        elif (a == 2):
            print("Decoded Word :  " + decode())
        else:
            raise Exception("Enter correct input")

    # Driver Code
    if __name__ == '__main__' :

        # Calling main function
        main()


else:
    print("Error, Try again.")

