import itertools
import string

def brute_force_login():
    # Dictionary attack with predefined usernames and passwords
    usernames = ['admin', 'root', 'user', 'test', 'guest', 'applebee', 'ofgirl', 'bigbuffmen', 'alphagamer101',
                 'donaldtrump']
    passwords = ['password', '123456', 'admin', 'qwerty', 'letmein', 'nonosquare']

    # Dictionary attack
    print("Dictionary Attack:")
    for username in usernames:
        for password in passwords:
            # Print the username and password
            print(f"Username: {username}, Password: {password}")

    # Brute-force attack (7 to 12 alphanumeric characters including special characters)
    characters = string.ascii_letters + string.digits + string.punctuation  # Letters, digits, and special characters

    print("\nBrute Force Attack:")
    for length in range(7, 13):  # Length from 7 to 12
        for password_tuple in itertools.product(characters, repeat=length):
            password = ''.join(password_tuple)
            for username in usernames:  # Iterate over usernames again for brute force
                # Print the username and generated password
                print(f"Username: {username}, Password: {password}")

if __name__ == "__main__":
    brute_force_login()
