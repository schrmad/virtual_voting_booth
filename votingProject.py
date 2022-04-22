# -*- coding: utf-8 -*-
"""
Created on Sat Feb 26 09:03:03 2022
Final Project: Virtual Election Booth
@author: Thanh Vu and Madeline Schroeder
@author: some code samples from Practical Cryptography in Python (noted in method comments)
@version: 12 March, 2022
Description: This project develops secure election protocol for voting with two central facilities 

Everything needed to run this project is contained in the included Python file.
To run the simulation, compile and run the python file in an environment of
your choice. After Clicking "run," you must type: main() into the console, 
and press enter in order to begin the simulation.

"""
    
# Imports
from random import randint, choice
from cryptography.hazmat.backends import default_backend # RSA and AES
from cryptography.hazmat.primitives.asymmetric import rsa # RSA
from cryptography.hazmat.primitives import hashes # RSA
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding # RSA (kept distinct from AES padding)
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes # AES
from cryptography.hazmat.primitives import padding as aes_padding # AES (kept distinct from RSA padding)
import os # AES

"""
Project-wide variables
    voter_ssn_list  list of encrypted social security numbers
    valnum_list  list of validation numbers
    idNum_list  list of identification numbers
"""
voter_ssn_list = []  # list of encrypted voter's SSN
valnum_list = []  # list of validation numbers assigned to voter
idNum_list = []  # list that of voters' identification number.

"""
genKeyRSA method  randomly generates a public/private key pair to use with RSA
encryption
This method is based on code provided by the PracticaL Cryptography in Python textbook
Code can be found at: https://github.com/Apress/practical-cryptography-in-python/blob/master/src/sign_unencrypted.py
    @return list containing the pair in [public, private] format
"""
def genKeyRSA():
    # Generate private and public keys
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
    )
    
    public_key = private_key.public_key()
    
    # Return keys in a list
    return [public_key, private_key]

"""
sign method  appends an RSA signature to a message, then verifies the signature
genKeyRSA() should be used to generate keys for the parameters
This method is based on code provided by the PracticaL Cryptography in Python textbook
Code can be found at: https://github.com/Apress/practical-cryptography-in-python/blob/master/src/sign_unencrypted.py
    @param msg message to sign
    @param public_key
    @param private_key
    @return the signed message
"""
def sign(msg, public_key, private_key):
    # Convert the message to bytes so it can be signed
    msg = msg.encode()
    
    # Sign the message
    signature = private_key.sign( # Private_key.sign
    msg,
    rsa_padding.PSS(
        mgf=rsa_padding.MGF1(hashes.SHA256()),
        salt_length=rsa_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    # Append the signature to the message
    msg_signed  = msg + signature
    
    # Verify the signature
    verify(signature, msg, public_key)
    return msg_signed

"""
verify method  verifies an RSA signature
This method is based on code provided by the PracticaL Cryptography in Python textbook
Code can be found at: https://github.com/Apress/practical-cryptography-in-python/blob/master/src/sign_unencrypted.py
    @param byte signature  the signature to be verified
    @param byte message  the message that was signed (in its UNSIGNED form)
    @param public_key  the public key used to sign the message
"""
def verify(signature, message, public_key):
    public_key.verify(
    signature,
    message,
    rsa_padding.PSS(
        mgf=rsa_padding.MGF1(hashes.SHA256()),
        salt_length=rsa_padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )
    print("Verify passed! (On failure, throw exception)")
    

"""
encrypt method  encrypts a message using CBC mode of AES
Keys should be generated using the genKeyAES() method
This method is based on code provided by the PracticaL Cryptography in Python textbook
Code can be found at: https://github.com/Apress/practical-cryptography-in-python/blob/master/src/aes_cbc_padding.py
    @param message  the message to be encrypted; it should be a string or be convertable into a string
    @param bytes key  key in bytes format
    @param bytes iv  iv in byte format
    @return  encrypted message in list/bytes format
"""
def encrypt(message, key, iv):
    aesCipher = Cipher(algorithms.AES(key),
                       modes.CBC(iv),
                       backend=default_backend())
    aesEncryptor = aesCipher.encryptor()
    
    # Make a padder/unpadder pair for 128bit block sizes.
    padder = aes_padding.PKCS7(128).padder() 
    
    #pad the message
    plaintexts = str(message).encode()
    plaintexts = [plaintexts]

    # Encrypt the padded message
    ciphertexts = [] # List to store output
    for m in plaintexts:
        padded_message = padder.update(m)
        ciphertexts.append(aesEncryptor.update(padded_message))
    ciphertexts.append(aesEncryptor.update(padder.finalize()))
    
    # Return the encrypted message
    return ciphertexts

"""
decrypt method  decrypts a message using CBC mode of AES
The key and iv values must be the same as those used to encrypt the message
Keys should be generated using the genKeyAES() method
This method is based on code provided by the PracticaL Cryptography in Python textbook
Code can be found at: https://github.com/Apress/practical-cryptography-in-python/blob/master/src/aes_cbc_padding.py
    @param ciphertexts  list of ciphertext info in bytes format (padding and message)
    @param bytes key  key in bytes format
    @param bytes iv  iv in byte format
    @return  decrypted message in string format
"""
def decrypt(ciphertexts, key, iv):
    aesCipher = Cipher(algorithms.AES(key),
                       modes.CBC(iv),
                       backend=default_backend())
    aesDecryptor = aesCipher.decryptor()
    unpadder = aes_padding.PKCS7(128).unpadder()
    
    # Decrypt and unpad the message
    recoveredtexts = []
    for c in ciphertexts:
        padded_message = aesDecryptor.update(c) #Decrypt
        recoveredtexts.append(unpadder.update(padded_message)) # unpad
    recoveredtexts.append(unpadder.finalize())
    
    
    # Decode the message
    decrypted = []
    for r in recoveredtexts:
        m = r.decode()
        decrypted.append(m)
    
    # Return the decrypted message
    return ''.join(decrypted)
    

"""
genKeyAES method  Randomly generates a key and iv value to be used in AES encryption
    @return  list containing the key as the first element and the iv as the second element
"""
def genKeyAES():
    key = os.urandom(32)
    iv = os.urandom(16)
    return [key, iv]



"""
random_N_digits_list method  creates a list of random numbers with desired length
This function is used to generate validation numbers
    @param  int l - prompt to give the length of random number list
    @param  int n -  prompt to give number of digits
    @return a list of L random N-digit numbers
"""
def random_N_digits_list(l, n):
    range_start = 10**(n - 1)
    range_end = (10**n) - 1
    num_list = []
    for i in range(l): # Make l random numbers
        a = randint(range_start, range_end)
        if a not in num_list: # No repeated numbers
            num_list.append(a)
        l -= 1
    return num_list


"""
inputNumber method  prompt user to input a number of a specified length
try until user input is appropriate
    @param  int n - required number of digits
    @return a list of L random N-digit numbers
"""
def inputNumber(message, n):
    while True:
        try:
            userInput = int(input(message)) # Get number from user
            if len(str(userInput)) != n:
                raise ValueError  # this will send it to the print message and back to the input option
            break
        except ValueError:
            print("ERROR:  We need %s digits! Try again." % n)
    return userInput # Return the input


"""
testEncryption method  Verify that a decrypted and original text are the same
    @param msg_original  the original plaintext
    @param msg_decrypted  the plaintext after being encrypted and decrypted
"""
def testEncryption(msg_original, msg_decrypted):
    # Make the decrypted message one string instead of a list
    dec_str = ""
    for c in msg_decrypted:
        dec_str += c
    
    # Test if they're equal
    if (str(msg_original) == str(dec_str)):
        print("Backend: secure transfer successful!")
    else:
        print("Backend: secure transfer failed.")



"""
registerVoter method  register a voter
Voter inputs their SSN and receives a validation number
SSN is signed (to verify) and encrypted before being added to a list so that the same
SSN cannot be used to register multiple times
    @param int num_voters  number of voters to register
    @param list ssnList  List in which to store the social security numbers
"""
def registerVoter(num_voters, ssnList):
    list_ran_num = random_N_digits_list(10, 10)  # list of 10 random 10-digit numbers (for validation numbers)
    while(num_voters > 0):
        # Generate keys for this user
        key = genKeyAES() # AES keys
        rsa_keys = genKeyRSA() # Generate RSA key pair
        try:
            user_SSN = inputNumber("Without starting with 0, your 9-digit social security number: ", 9)
            """
            Backend: send the ssn to the CLA
            """
            ssn_signed = sign(str(user_SSN), rsa_keys[0], rsa_keys[1]) # Sign the ssn
            ssn_encrypted = encrypt(ssn_signed, key[0], key[1]) # Encrypt the ssn to send it
            ssn_decrypted = decrypt(ssn_encrypted, key[0], key[1]) # Decrypt the ssn that was received
            testEncryption(ssn_signed, ssn_decrypted) # Verify successful encryption

            if user_SSN in ssnList: # Make sure SSN is not already used to register
                raise ValueError
        except ValueError:
            print("You are already registered!")
            continue
   
        # Generate a validation number
        a = choice(list_ran_num) # Prepare a validation number from the list
        list_ran_num.remove(a) 
        valnum_list.append(a) # Add validation number to CLA's list
        
        """
        Backend: send the validation number to the user
        """
        a_encrypted = encrypt(a, key[0], key[1]) # Encrypt validation number before sending it to user
        a_decrypted = decrypt(a_encrypted, key[0], key[1]) # Decrypt validation number once the user receives it
        testEncryption(a, a_decrypted) # Verify successful encryption
        
        print("Thank you for submitting SSN. Your validation number: ", a)
        
        # Add data to lists
        ssnList.append(user_SSN) # Add SSN to SSN list
        num_voters -= 1 # Finally, decrease number of voters to register


"""
main() method  runs the voting simulation
Asks voters for their SSN, and gives them a validation number. Voters create an ID number then vote
Results are shown
"""
def main():
    print("\nWelcome to the T & M's Virtual Election Booth")
    print("---------------------------------------------\n\n")
    print("Phase 1: Voting registration")
    
    # Create a 'table' (string) to store the results.
    result_table= ""
    
    registerVoter(3, voter_ssn_list) # Register 3 voters
    
    nominee_1, nominee_2 = "Republican Party", "Democratic Party" # Voting options
    nom_1_vote, nom_2_vote = 0, 0 # Voting counts (start at 0)
    print("\n\n")
    print("The voting session begins now.")
    print("---------------------------------------------")
    
    # Voter creates a message with the validation number they received from the CLA
    # They send this message to the CTF.
    # After all votes have been received, the CTF publishes the outcome,
    # as well as the lists of identification numbers and for whom their owners voted.
    while True:
        if valnum_list == []:
            print("\n\nVoting session over. We are pleased to announce that:")
            if nom_1_vote > nom_2_vote:
                print(nominee_1, "has won")
            elif nom_1_vote < nom_2_vote:
                print(nominee_2, "has won")
            else:
                print("tied!!")
            print(result_table)
            break
    # The CTF checks the validation number against the list it received from the
    # CLA in step 13)
        else:
            for v in valnum_list:
                # Make user enter their validation number
                try:
                    val_ID = inputNumber("Please input your validation number: ", 10)
                    """
                    Backend: send validation number to CTF
                    """
                    temp_AES = genKeyAES() # AES keys
                    temp_RSA = genKeyRSA() # RSA keys
                    val_ID_signed = sign(str(val_ID), temp_RSA[0], temp_RSA[1]) # Sign the validation number
                    val_ID_encrypted = encrypt(val_ID_signed, temp_AES[0], temp_AES[1]) # Encrypt the validation number
                    val_ID_decrypted = decrypt(val_ID_encrypted, temp_AES[0], temp_AES[1]) # Decrypt the validation number
                    testEncryption(val_ID_signed, val_ID_decrypted) # Verify successful encryption          
                    if val_ID not in valnum_list: # CTF checks against list from CLA
                        raise ValueError
                except ValueError:
                    print("That is not a valid validation number, or you have already voted. Please try again.")
                    continue
                
                while True:
                    try:
                        idNum = inputNumber("For ID number, input a 2-digit number from 10 to 99: ", 2) # <-- Validation number first, then ask for ID
                        if idNum in idNum_list:
                            raise ValueError   
                        """
                        Backend: send identification number to CTF
                        """
                        id_signed = sign(str(idNum), temp_RSA[0], temp_RSA[1]) # Sign the id number
                        id_encrypted = encrypt(id_signed, temp_AES[0], temp_AES[1]) # Encrypt the id number
                        id_decrypted = decrypt(id_encrypted, temp_AES[0], temp_AES[1]) # Decrypt the id number
                        testEncryption(id_signed, id_decrypted) # Verify successful encryption
                        
                        idNum_list.append(idNum) # Add the id number to the list of id numbers
                        break
                    except ValueError:
                        print("ID %s already exists, please pick a different one." % idNum)
                        continue
                    """
                    Get vote from user
                    """
                    vote = 0
                while True:
                    try:
                        vote = int(input("[ID %s], please input 1 / 01 for nominee 1 or 2 / 02 for nominee 2: " % idNum))
                        # Sign and encrypt vote (same as for val id?)
                        if vote != 1 and vote != 2:
                            raise ValueError  # this will send it to the print message and back to the input option
                        if vote == 1:
                            choice = nominee_1
                        else:
                            choice = nominee_2
                        result_table = result_table + "ID: " + str(idNum) + " | Vote: " + choice + "\n"
                        
                        """
                        Send vote to the CTF
                        """
                        vote_signed = sign(str(vote), temp_RSA[0], temp_RSA[1]) # Sign the vote
                        vote_encrypted = encrypt(vote_signed, temp_AES[0], temp_AES[1]) # Encrypt the vote
                        vote_decrypted = decrypt(vote_encrypted, temp_AES[0], temp_AES[1]) # Decrypt the vote
                        testEncryption(vote_signed, vote_decrypted) # Verify successful encryption
                        break
                    except ValueError:
                        print("Not a valid opiton. Try again")
                voted_1_id_list = []
                voted_2_id_list = []
                #  If the validation number is there, the CTF
                # crosses it off to prevent someone from voting twice
                valnum_list.remove(val_ID)
               
                # The CTF adds the identification
                # number to the list of people who voted for a particular candidate and adds
                # one to the tally.
                if vote == 1:
                    nom_1_vote += 1
                    print("Thank you [ID %s] for casting vote" % idNum )
                    print("\n---------------------------------------------")
                    voted_1_id_list.append(idNum)
                elif vote == 2:
                    nom_2_vote += 1
                    print("Thank you [ID %s] for casting vote" % idNum )
                    print("\n---------------------------------------------")
                    voted_2_id_list.append(idNum)