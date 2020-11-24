import time
from Cryptodome.PublicKey import RSA
from hashlib import sha512


def generate(bit_size):
    """
        Method generates a RSA key pair with a size of some number of bits

        @param:
            bit_size : the size of the bits. 1024 on Demo page

        @return:
            key_pair : this contains a public and private key
    """
    key_pair = RSA.generate(bit_size)
    return key_pair


def signing(key_pair, data):
    """
        Method signs a message that is entered by a user:
            - encrypts the message by calculating its hash and raising to the power 'd' modulo 'n'

        @param:
            key_pair : the key pair that was generated earlier. Used to create a hash
            data : the data that is being 'sent'

        @return:
            hashed : the hash value of the message digest
            signature : the generated signature
    """
    message_digest = str.encode(data)
    hashed = int.from_bytes(sha512(message_digest).digest(), byteorder='big')
    signature = pow(hashed, key_pair.d, key_pair.n)

    return hashed, signature


def verify(signature, key_pair, new_data):
    """
        Method generates original hash and hash from signature
            - Decrypted by raising signature to the power 'e' modulo 'n'

        @param:
            signature : the signature from the data that was sent through
            key_pair : the key pair that was generated earlier
            new_data : this represents the data that is being checked against the first signature

        @return:
            hashed : the hash of the new data
            hash_from_signature : decrypting of the signature into the hash
    """
    valid_signature = str.encode(new_data)
    hashed = int.from_bytes(sha512(valid_signature).digest(), byteorder='big')
    hash_from_signature = pow(signature, key_pair.e, key_pair.n)
    return hashed, hash_from_signature


def verifier(hashed, hash_from_signature):
    """
        Method verifies whether the original value is equivalent to the new one

        @param:
            hashed : the hash of the new data
            hash_from_signature : the hash of the new signature

        @return:
            Boolean :  True if the original hash matches the new hash, False otherwise
    """
    return hashed == hash_from_signature


def demonstration(data, new_data, bit_size):
    """
        Method gets the key pair, hash of sent and received data and returns whether the signature is valid.

        @param:
            data : the sent data
            new_data : the received data

        @return:
            public_key : the public key in form (n,e)
            private_key : the private key in form (n,d)
            original_hash : the hash of the sent message
            hashed : the hash of the received message
            is_valid : boolean whether the signature was valid or not
            signature : the signature that was generated
    """
    key_pair = generate(bit_size)
    original_hash, signature = signing(key_pair, data)
    hashed, new_signature = verify(signature, key_pair, new_data)
    is_valid = verifier(hashed, new_signature)

    public_key = "(" + str(key_pair.n) + ", " + str(key_pair.e) + ")"
    private_key = "(" + str(key_pair.n) + ", " + str(key_pair.d) + ")"
    if is_valid:
        is_valid = "Valid"
    else:
        is_valid = "Invalid"
    return public_key, private_key, original_hash, hashed, is_valid, signature


def time_difference(first_bit_size, second_bit_size, data, new_data):
    """
        Method gets the time difference between encrypting and decrypting the same data using different bit sizes
            - Called for the Time difference page

        @param:
            first_bit_size : The first bit size
            second_bit_size : The second bit size
            data : The original data sent
            new_data : The received data

        @return:
            difference : the time difference between the first and second run through of presumably different bit sizes
            is_valid : boolean whether the signature is valid or not
            first_run_time : the time it took for the first bit size to run
            second_run_time : the time it took for the second bit size to run
    """
    first_run_time, is_valid = time_difference_helper(first_bit_size, data, new_data)
    second_run_time, is_valid = time_difference_helper(second_bit_size, data, new_data)
    difference_in_time = abs(second_run_time - first_run_time)
    return difference_in_time, is_valid, first_run_time, second_run_time


def time_difference_helper(bit_size, data, new_data):
    """
        Helper method: time_difference(first_bit_size, second_bit_size, data, new_data)
            - gets the time difference between encrypting and decrypting the same data using different bit sizes

        @param:
            bit_size : the bit size that is currently being used
            data : The original data sent
            new_data : The received data

        @return:
            difference : the time difference between the first and second run through of presumably different bit sizes
            is_valid : boolean whether the signature is valid or not
    """
    start = time.time()
    public_key, private_key, original_hash, hashed, is_valid, signature = demonstration(data, new_data, bit_size)
    end = time.time()
    run_time = (end - start)
    return run_time, is_valid


def bit_size_checking(some_bit_size):
    """
        Method to error check the bit sizes to ensure that they are bits that are factors of 1024

        @param:
            some_bit_size : what the user enters as a bit size

        @return:
            True or False :  True if the value is an integer that is a multiple of 1024. False otherwise
    """
    try:
        value = int(some_bit_size)
        if value % 1024 == 0:
            return True
        else:
            return False
    except ValueError or TypeError:
        return False
