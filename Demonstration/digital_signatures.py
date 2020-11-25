"""
    Authors:
        Josh Meritt
        Kira Garguilo
        Eric Simonetti

    Reason:
        SUNY Oswego Class: CSC/MAT 332 - Cryptology

    Project:
        Replicate and show how a digital signature works
"""
# Time is needed for comparing the different bit sizes
import time
# RSA is used to generate the key pair
from Cryptodome.PublicKey import RSA
# sha512 is used to create a hash of the encoded sent data
from hashlib import sha512
# threading is used to have multiple threads to get average time it takes to run for certain bit size
from threading import Thread

# Global bit_size for bit_size for easy change when needed
global bit_size
bit_size = 1024
# Global average_time for average_time will be altered a lot by threads
global average_time
average_time = 0


def generate(comparing):
    """
        Method generates a RSA key pair with a size of some number of bits

        @param:
            comparing : This is conditional on whether it was desired to print out key pairs

        @return:
            key_pair: this contains a public and private key
    """
    if not comparing:
        print("\nGenerating a key_pair of size: \n", bit_size)
    key_pair = RSA.generate(bits=bit_size)
    if not comparing:
        print("\n[Public key]: \n", "(", hex(key_pair.n), ",", hex(key_pair.e), ")")
        print("\n[Private key]: \n", "(", hex(key_pair.n), ",", hex(key_pair.d), ")")
    return key_pair


def signing(key_pair, data):
    """
        Method signs a message that is entered by a user:
            - encrypts the message by calculating its hash and raising to the power 'd' modulo 'n'

        @param:
            key_pair : the key pair that was generated earlier. Used to create a hash
            data : the data that is being 'sent'

        @return:
            signature : the generated signature
    """
    message_digest = str.encode(data)
    hashed = int.from_bytes(sha512(message_digest).digest(), byteorder='big')
    signature = pow(hashed, key_pair.d, key_pair.n)

    return signature


def verify(signature, key_pair, new_data, comparing):
    """
        Method verifies by decrypting the signature by using the public key.
            - Decrypted by raising signature to the power 'e' modulo 'n'
            - Once decrypted, compares the hash from the new data to the hash or the original data.

        @param:
            signature : the signature from the data that was sent through
            key_pair : the key pair that was generated earlier
            new_data : this represents the data that is being checked against the first signature
            comparing : This is conditional on whether it was desired to print out hashes of data

        @return:
            Boolean :  True if the original hash matches the new hash, False otherwise
    """
    valid_signature = str.encode(new_data)
    hashed = int.from_bytes(sha512(valid_signature).digest(), byteorder='big')
    hash_from_signature = pow(signature, key_pair.e, key_pair.n)
    if not comparing:
        print("\n[Hash of sent data]: \n", hash_from_signature)
        print("\n[Hash of received data]: \n", hashed)

    if hashed == hash_from_signature:
        return "[Valid]"
    else:
        return "[Invalid]"


def digital_signature_runner(text, is_valid_input, comparing):
    """
        Method that generates and validates digital signatures

         @param:
            text : the original data
            is_valid_input : the data that might have been altered
            comparing : This is conditional on whether it was desired to print out signature

        @return:
            is_valid : boolean based on whether the signature is valid or not
    """
    generated_key_pair = generate(comparing)
    signature = signing(generated_key_pair, text)
    is_valid = verify(signature, generated_key_pair, is_valid_input, comparing)
    if not comparing:
        print("\n[Signature]: \n", signature, " \n\n[Signature validity]: ", is_valid)
    return is_valid


def compare_bit_sizes(first_bit_size, second_bit_size, text, is_valid_text):
    """
        Method compares two bit sizes and the time it takes to create and verify the signatures of each

        @param:
            first_bit_size : the first bit size that is being compared
            second_bit_size : the second bit size that is being compared
            text : the original data
            is_valid_text : the data that may have been altered

        @print:
            Instead of returning values, this method prints out:
                - first_bit_size with the time it took to run
                - second_bit_size with the time it took to run
                - time difference between the two
    """
    global bit_size
    temp_bit_size = bit_size
    first_run_time, is_valid = comparing_helper(first_bit_size, text, is_valid_text)
    second_run_time, is_valid = comparing_helper(second_bit_size, text, is_valid_text)
    time_difference = abs(first_run_time - second_run_time)

    print("\n [First bit size]:", first_bit_size, " [time]: ", first_run_time)
    print(" [Second bit size]:", second_bit_size, " [time]: ", second_run_time)
    print("\n [Time difference]: ", time_difference, " [Signature validity]:  ", is_valid)
    bit_size = temp_bit_size


def compare_three_bits(first_bit_size, second_bit_size, third_bit_size, text, is_valid_text):
    """
        Method compares three bit sizes and the time it takes to create and verify the signatures of each

        @param:
            first_bit_size : the first bit size that is being compared
            second_bit_size : the second bit size that is being compared
            third_bit_size : the third bit size that is being compared
            text : the original data
            is_valid_text : the data that may have been altered

        @print:
            Instead of returning values, this method prints out:
                - first_bit_size with the time it took to run
                - second_bit_size with the time it took to run
                - third_bit_size with the time it took to run
                - time difference between the two
    """
    global bit_size
    temp_bit_size = bit_size
    first_run_time, is_valid = comparing_helper(first_bit_size, text, is_valid_text)
    second_run_time, is_valid = comparing_helper(second_bit_size, text, is_valid_text)
    third_run_time, is_valid = comparing_helper(third_bit_size, text, is_valid_text)

    print("\n [First bit size]:", first_bit_size, " [time]: ", first_run_time)
    print(" [Second bit size]:", second_bit_size, " [time]: ", second_run_time)
    print(" [Third bit size]:", third_bit_size, " [time]: ", third_run_time)
    print("\n [Signature validity]:  ", is_valid)
    bit_size = temp_bit_size


def comparing_helper(current_bit_size, text, is_valid_text):
    """
        Helper method:
            1. compare_three_bits(first_bit_size, second_bit_size, third_bit_size, text, is_valid_text)
            2. compare_bit_sizes(first_bit_size, second_bit_size, text, is_valid_text)
            - gets timed value of generating and validating digital signatures

        @param:
            current_bit_size : the bit size that is currently being checked
            text : the original data
            is_valid_text : the data that may have been altered

        @return:
            run_time : the time it took for the creation and validation
            is_valid : boolean whether the signature was valid or not
    """
    global bit_size
    bit_size = int(current_bit_size)
    print("\n [Validating] ")
    start = time.time()
    is_valid = digital_signature_runner(text, is_valid_text, True)
    end = time.time()
    run_time = (end - start)
    return run_time, is_valid


def find_average_time(text, is_valid_text):
    """
        Helper method to find average time of certain bit size/byte size of data.
            - Is method call from threading --> updates global variable instead of returning anything

        @param:
            text : The data that was sent
            is_valid_text : The data that was received
    """
    global average_time
    start_time = time.time()
    digital_signature_runner(text, is_valid_text, True)
    end_time = time.time()
    average = (end_time - start_time)
    average_time += average


def threading(text, is_valid_text, num):
    """
        Main method to find average time. Uses Threads to find average time based on:
            - bit size of key pair
            -byte size of data being 'sent'

        Note:
            Since threads are being created and run, the time for each thread may slow down due to computer not being
            strong enough but is still more time efficient, time running wise, to use threads instead of loop

        @param:
            text : The data that was sent
            is_valid_text : The data that was received
            num : the number of threads to be created

        @print:
            - The average time
            - Sent/Received data size in bytes
            - Number of threads created
    """
    global average_time
    average_time = 0
    threads = []
    for n in range(num):
        print("[Validating]\n")
        thread = Thread(target=find_average_time, args=(text, is_valid_text))
        thread.start()
        threads.append(thread)

    for t in threads:
        t.join()

    average_time /= num
    sent_byte_size = len(text.encode('utf-8'))
    received_byte_size = len(is_valid_text.encode('utf-8'))
    print("[Average time] : ", average_time, ' [Sent data size] :', sent_byte_size, ' bytes  [Received data size] : ',
          received_byte_size, ' bytes [Runs] : ', num)


def number_checker():
    """
        Method to error check the number of runs to ensure that it is a number.

        @return:
            value :  The value of the number
    """
    while True:
        num = input("\n@User: Number of runs to average: \n")
        try:
            value = int(num)
            print("\n")
            return value
        except ValueError or TypeError:
            print("[Error] Incorrect type. Try an integer.")


def bit_size_checking(some_bit_size):
    """
        Method to error check the bit sizes to ensure that they are bits that are factors of 1024

        @param:
            some_bit_size : what the user enters as a bit size

        @return:
            Boolean :  True if the value is an integer that is a multiple of 1024. False otherwise
    """
    try:
        value = int(some_bit_size)
        if value % 1024 == 0:
            return True
        else:
            return False
    except ValueError:
        return False


def get_new_bit_size():
    """
        Method to reduce amount of times new bit size is received

        @return:
            new_bit_size : the new bit size that is an integer and multiple of 1024
    """
    while True:
        new_bit_size = input("@User: What is the new bit size?\n")
        if bit_size_checking(new_bit_size):
            return new_bit_size
        else:
            print("\n [Error] Incorrect type. Try an integer that is a multiple of 1024.")


def commands():
    """
        Main method:
            - runs through loop reading users commands
            - calls appropriate methods and error checks based on user command
    """
    print_title()
    command = "-1"
    while command != "--exit":
        command = input("\n\n@User: What would you like to do? --help for options\n")
        if command == "--help":
            print("\n List of commands: \n"
                  "--run : runs the program\n"
                  "--change_bit_size : can change the generated bit size\n"
                  "--compare_bit_size : "
                  "can compare two different bit sizes and time to create and validate signatures for some data\n"

                  "--compare_three_bit_sizes : "
                  "can compare three different bit sizes and time to create and validate signatures for some data \n"
                
                  "--average_time : finds the average time to run based on given number of trials\n"
                  
                  "--exit : exits the program")

        elif command == "--run":
            text = input("@User: Data to be sent: \n")
            is_valid_input = input("\n@User: Data that is received: \n")
            print("\n [Validating] ")
            digital_signature_runner(text, is_valid_input, False)

        elif command == "--change_bit_size":
            print("\n")
            global bit_size
            bit_size = int(get_new_bit_size())
            print("\n [Success] The bit size was changed to: ", bit_size)

        elif command == "--compare_bit_size":
            print("\n [Waiting] First bit size: ")
            first_bit_size = get_new_bit_size()

            print("\n [Waiting] Second bit size: ")
            second_bit_size = get_new_bit_size()

            text = input("\n@User: What is the sent data?\n")
            is_valid_text = input("\n@User: What is the received data?\n")
            compare_bit_sizes(first_bit_size, second_bit_size, text, is_valid_text)

        elif command == "--compare_three_bit_sizes":
            print("\n [Waiting] First bit size: ")
            first_bit_size = get_new_bit_size()

            print("\n [Waiting] Second bit size: ")
            second_bit_size = get_new_bit_size()

            print("\n [Waiting] Third bit size: ")
            third_bit_size = get_new_bit_size()

            text = input("\n@User: What is the sent data?\n")
            is_valid_text = input("\n@User: What is the received data?\n")
            compare_three_bits(first_bit_size, second_bit_size, third_bit_size, text, is_valid_text)

        elif command == "--average_time":
            text = input("@User: Data to be sent: \n")
            is_valid_input = input("\n@User: Data that is received: \n")
            num = number_checker()
            bit_size = int(get_new_bit_size())
            threading(text, is_valid_input, num)

        elif command == "--exit":
            print("\n [Exiting]")

        elif command == "--load_up":
            print_title()

        else:
            print("\n [Error] Did not understand command. --help for options\n")


def print_title():
    print("""
             ____   _         _  _           _ 
            |  _ \ (_)  __ _ (_)| |_   __ _ | |
            | | | || | / _` || || __| / _` || |
            | |_| || || (_| || || |_ | (_| || |
            |____/ |_| \__, ||_| \__| \__,_||_|
                        |___/                   
                                    ,-.
                                   ( O_)
                                  / `-/
                                 /-. /    
            ___---¯¯¯¯¯¯¯¯¯¯¯¯¯¯/   )---____
         /¯¯ __O_--------      /   /----_O__¯¯\\
        | O?¯            \    /-. /         ¯?O | 
        |  '   (_)-*-._  |   /   )           '  |
        |O|       *-._ *-'***( )/             |O|
        | |           *-/*-._* `.             | |
        | |             /     *-.'._          | |
        |O|            /\       /-._*-._      |O|
        |  \          /  ) _,-*/|    *-(_)   /  |
        |   \________/  / /   / |___________/   |
        |           /  / /   /                  |
        |   .------/  / /   /    -----------.   | 
        |O /      /  / /   /    |            \ O|  
        \ '      /  / /   /     |             ' /
         \O\    /  / /   /|     |            /O/
          \ \  /  / /   / |     |           / /
           \O /  / /   /  |     |          /O/
             /  / /   /   |     |           /
            /  / /   /    |     |        O.'
           /  / /   /'.__/       \__.'O_.'
          /  / /   /'._ O         O _.'
         /  |,'   /    '._________.' 
        :   /    /        
        [  /   -'                 
        | /  -'                ~>Digital Signatures<~
        |/,-'           ~~>Created By Josh, Kira and Eric<~~
        '                      
     ____   _                       _                           
    / ___| (_)  __ _  _ __    __ _ | |_  _   _  _ __   ___  ___ 
    \___ \ | | / _` || '_ \  / _` || __|| | | || '__| / _ \/ __|
     ___) || || (_| || | | || (_| || |_ | |_| || |   |  __/\__ \\
    |____/ |_| \__, ||_| |_| \__,_| \__| \__,_||_|    \___||___/
               |___/                                                             
    """)


if __name__ == '__main__':
    commands()
