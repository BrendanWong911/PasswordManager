# Something Awesome Password Manager
# Written by Brendan Wong (z5694763)
# A program to securely store passwords

import base64
from argon2.low_level import hash_secret_raw, Type
import os
from Crypto.Cipher import AES
import pyotp
import qrcode
import pwinput
from timedinput import timedinput
import smtplib
from dotenv import find_dotenv, load_dotenv


def main ():
    command = 0
    while command != 4:
        display_menu()
        command = get_valid_menu_command()
        # User enters login
        if command == 1: 
            login()
        # User creates account
        elif command == 2:
            register_account()
            command = 4
        # User enters info page
        elif command == 3:
            info()
            input("Press Enter to return")
    print("Program Terminated")

# Main helper function to get a valid input
def get_valid_menu_command():
    command = 0
    while command < 1 or command > 4:
        try:
            command = int(input("➤  Select option [1-4]: "))
            if command < 1 or command > 4:
                print("Error: Invalid input")
        except ValueError:
            print("Error: Invalid input")
    return command

# Creates a users account
def register_account():
    username = str(input("Enter Username: "))
    while os.path.exists(username + ".txt"):
        print("Username taken\nPlease choose a different username.")
        username = str(input("Enter Username: "))
    email = str(input("Enter Email Address: "))
    master_password = create_password()

    salt = os.urandom(16)
    data = multi_factor_authentication(username) + '\n' + email + ":off"

    key = argon2_hash(master_password, salt)
    data = data.encode("utf-8")

    #Creates AES 256 GCM cipher
    nonce, ciphertext, tag = create_AES_encryption(key, data)

    store_in_txt(username, salt, nonce, tag, ciphertext)

    print("Account Created")
    input("Enter to exit program")
    os.system("cls")

# Creates AES-256-GCM encryption
def create_AES_encryption(key, data):
    AES_cipher = AES.new(key, AES.MODE_GCM)
    nonce = AES_cipher.nonce
    ciphertext, tag = AES_cipher.encrypt_and_digest(data)
    return nonce, ciphertext, tag

# Creates a multi-factor authentication QR code and returns secret
def multi_factor_authentication(username):
    secret = pyotp.random_base32()
    totp = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="VeryAwesomePasswordManager")
    
    qr = qrcode.QRCode()
    qr.add_data(totp)
    qr.print_ascii(invert=True)
    return secret

# Creates master password
def create_password():
    master_password = pwinput.pwinput(prompt="Create Master Password: ")
    confirm_password = pwinput.pwinput(prompt="Confirm Password: ")
    
    while check_strength(master_password, confirm_password):
        master_password = pwinput.pwinput(prompt="Create Master Password: ")
        confirm_password = pwinput.pwinput(prompt="Confirm Password: ")
    
    return master_password

# Checks if password meets the security requirements
def check_strength(master_password, confirm_password):
    if master_password != confirm_password:
        print("Passwords do not match try again")
        return True
    elif len(master_password) < 12:
        print("Password must be 12 characters long")
        return True
    elif not (includes_upper(master_password) and includes_lower(master_password) and includes_number(master_password) and includes_special_char(master_password)):
        print("Passwords must include a combination of uppercase, lowercase, numbers and special characters")
        return True
    else:
        return False

# Checks if password includes a uppercase value
def includes_upper(master_password):
    for char in master_password:
        if char.isupper():
            return True
    return False

# Checks if password includes a lowercase value
def includes_lower(master_password):
    for char in master_password:
        if char.islower():
            return True
    return False

# Checks if password includes a number value
def includes_number(master_password):
    for char in master_password:
        if char.isdigit():
            return True
    return False

# Checks if password includes a special character value
def includes_special_char(master_password):
    for char in master_password:
        if not char.isdigit() and not char.isalpha():
            return True
    return False


# Creates argon2 hash
def argon2_hash(master_password, salt):
    password = master_password.encode('utf-8')
    raw_hash = hash_secret_raw(
        secret = password,
        salt = salt,
        time_cost = 80,
        memory_cost = 65536,
        parallelism = 4,
        hash_len = 32,
        type=Type.ID
    )
    return raw_hash

# Stores data into txt file
def store_in_txt(username, salt, nonce, tag, ciphertext):
    file = open(username + ".txt", "w")
    salt64 = base64.b64encode(salt)
    nonce64 = base64.b64encode(nonce)
    tag64 = base64.b64encode(tag)
    ciphertext64 = base64.b64encode(ciphertext)

    file.write(salt64.decode('utf-8') + '\n')
    file.write(nonce64.decode('utf-8') + '\n')
    file.write(tag64.decode('utf-8') + '\n')
    file.write(ciphertext64.decode('utf-8') + '\n')
    file.close()

# Processes user login phase
def login():
    user = input("Username: ")
    password = pwinput.pwinput(prompt="Password: ")
    file = user + ".txt"
    while not os.path.exists(file):
        print("Account does not exist")
        user = input("Username: ")
        password = pwinput.pwinput(prompt="Password: ")
        file = user + ".txt"

    salt, nonce, tag, ciphertext = read_txt(file)

    key = argon2_hash(password, salt)
    
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)

    if vertify_user(plaintext, user, tag, cipher):
        plaintext = plaintext.decode('utf-8')
        plaintext = plaintext.split("\n")
        email = plaintext[1]

        account_data = plaintext[2:]
        if account_data[0] != '':
            passwords = read_passwords(account_data)
        else:
            passwords = []
        user_email = email.split(":")[0]
        email_notification_status = email.split(":")[1]
        email_notification(email_notification_status, user_email)
        original = plaintext[:2]
        

        command = 0
        while command != 4:
            display_account_menu()
            command = get_valid_account_command()
            # Get users stored password
            if command == 1:
                if display_passwords(passwords):
                    command = 4
            # Add a password
            elif command == 2:
                command, passwords = add_password(passwords)
                if (command != 4):
                    print("Password added to account")
                    formated = format_secret(passwords, original)
                    nonce, ciphertext, tag = create_AES_encryption(key, formated)
                    store_in_txt(user, salt, nonce, tag, ciphertext)
            # Move user to setting page
            elif command == 3:
                email_notification_status, email, command = setting(email_notification_status, email)
                original[1] = email
                formated = format_secret(passwords, original)
                nonce, ciphertext, tag = create_AES_encryption(key, formated)
                store_in_txt(user, salt, nonce, tag, ciphertext)

# Sends email notification if it is toggled on
def email_notification(email_notification_status, user_email):
    if email_notification_status == "on":
        path = find_dotenv()
        load_dotenv(path)
        EMAIL_APP_PASSWORD = os.getenv("EMAIL_APP_PASSWORD")
        email_user = "awesomepassmanger@gmail.com"
        email_pass = EMAIL_APP_PASSWORD
        message = notification_message(email_user, user_email)

        email_server = smtplib.SMTP("smtp.gmail.com", 587)
        email_server.ehlo()
        email_server.starttls()
        email_server.ehlo()

        email_server.login(email_user, email_pass)
        email_server.sendmail(email_user, user_email, message)
        print("Email has been notified")

# Control user settings
def setting(email_notification_status, email):
    setting_command = 0
    while (setting_command != 2):
        display_account_settings(email_notification_status)
        setting_command = get_valid_setting_command()

        if setting_command == 1:
            email_notification_status, email = toggle_email_notification(email)
        elif setting_command == 4:
            return email_notification_status, email, 4
    return email_notification_status, email, 2


# Get a valid user input for account command
def get_valid_account_command():
    command = 0
    while int(command) < 1 or int(command) > 4:
        try:
            command = timedinput("➤  Select option [1-4]: ", timeout=300, default="timeout")
            if command == "timeout":
                print("User has been inactive for 5 minutes: logged out")
                return 4
            elif int(command) < 1 or int(command) > 4:
                print("Error: Invalid input")
                command = 0
        except:
            print("Error: Invalid input")
            command = 0
    return int(command)

# Get a valid user input for setting command
def get_valid_setting_command():
    command = 0
    while int(command) < 1 or int(command) > 2:
        try:
            command = timedinput("➤  Select option [1-2]: ", timeout=300, default="timeout")
            if command == "timeout":
                print("User has been inactive for 5 minutes: logged out")
                return 3
            elif int(command) < 1 or int(command) > 2:
                print("Error: Invalid input")
                command = 0
        except:
            print("Error: Invalid input")
            command = 0
    return int(command)

# Helper functionn to read TXT file
def read_txt(file):
    file = open(file, "r")
    lines = file.readlines()

    saltb64 = lines[0].strip().encode('utf-8')
    salt = base64.b64decode(saltb64)

    nonceb64 = lines[1].strip().encode('utf-8')
    nonce = base64.b64decode(nonceb64)

    tagb64 = lines[2].strip().encode('utf-8')
    tag = base64.b64decode(tagb64)

    ciphertextb64 = lines[3].strip().encode('utf-8')
    ciphertext = base64.b64decode(ciphertextb64)
    file.close()
    return salt, nonce, tag, ciphertext

# Toggle the email notification system to be on or off
def toggle_email_notification(email):
    email = email.split(":")
    if email[1] == "on":
        email[1] = "off"
    else:
        email[1] = "on"
    email_notification_status = email[1]
    email = email[0] + ':' + email[1]
    return email_notification_status, email

# Checks for correct password and multifactor authentication
def vertify_user(plaintext, user, tag, cipher):
    if vertify_password(cipher, tag):
        plaintext = plaintext.decode('utf-8')
        plaintext = plaintext.split("\n")
        # Uses MFA key and vertify if user input is correct
        mfaid = plaintext[0]
        while not confirmMFA(mfaid):
            print("Incorrect MFA")
        
        print("Access Granted Welcome " + user)
        return True
    else:
        return False

# Checks if tag and password are correct
def vertify_password(cipher, tag):
    try:
        cipher.verify(tag)
        return True
    except ValueError:
        print("Incorrect password or message corrupted")
    return False

# Reads stored passwords
def read_passwords(plaintext):
    passwords = []
    for account in plaintext:
        account = account.split(",")
        passwords.append({"website": account[0], "username": account[1], "password": account[2]})
    return passwords

# Display chosen password
def display_passwords(passwords):
    if passwords == None:
        print("No password stored")
    else:
        account = 0
        while account != len(passwords) + 1:
            display_websites(passwords)
            account = get_valid_account_input(passwords)
            if account == 0:
                return True
            elif account != len(passwords) + 1:
                print("Website: " + passwords[account - 1]["website"])
                print("Username: " + passwords[account - 1]["username"])
                print("Password: " + passwords[account - 1]["password"])
                timedinput("Press Enter to clear", timeout=300)
                os.system("cls")
                account = 0
    return False

# Checks if input for choosing a password is valid
def get_valid_account_input(passwords):
    account = 0
    while account == 0:
        try:
            account = timedinput("Select an account: ", timeout=300, default="timeout")
            if account == "timeout":
                print("User has been inactive for 5 minutes: logged out")
                return 0
            elif int(account) < 1 or int(account) > len(passwords) + 1:
                print("Error: Out of range")
                account = 0
        except ValueError:
                print("Input is not valid")
                account = 0
    return int(account)


# Display all websites stored in the account      
def display_websites(passwords):
    counter = 1
    for password in passwords:
        print("  " + str(counter) + ". " + password["website"])
        counter += 1
    print("  " + str(counter) + ". Exit")

# Creates new password to be stored
def add_password(passwords):
    try:
        website = timedinput("Enter site/app: ", timeout=300)
        username = timedinput("Enter username: ", timeout=300)
        password = timedinput("Enter password: ", timeout=300)
    except:
        print("User has been inactive for 5 minutes: logged out")
        return 4, passwords
    passwords.append({"website": website, "username": username, "password": password})
    print("Added " + website)
    return 2, passwords

# Reformats data to be stored in AES
def format_secret(passwords, original):
    data = original[0] + "\n" + original[1] + "\n"
    if passwords != None:
        for num in range(len(passwords)):
            data += passwords[num]["website"] + "," + passwords[num]["username"] + "," + passwords[num]["password"]
            if (num != len(passwords) - 1):
                data += "\n"
        return data.encode("utf-8")
    return data.encode("utf-8")

# Vertify if MFA is correct
def confirmMFA(secret):
    answer = input("Enter MFA: ")
    totp = pyotp.TOTP(secret)
    totp.verify(answer)
    return totp.verify(answer)

    
# Helper function to display title screen
def display_title():
    print(r" ______  ______  ______  ______  __     __  ______  ______  _____          ")
    print(r"/\  == \/\  __ \/\  ___\/\  ___\/\ \  _ \ \/\  __ \/\  == \/\  __-.        ")
    print(r'\ \  _-/\ \  __ \ \___  \ \___  \ \ \/ ".\ \ \ \/\ \ \  __<\ \ \/\ \       ')
    print(r' \ \_\   \ \_\ \_\/\_____\/\_____\ \__/".~\_\ \_____\ \_\ \_\ \____-       ')
    print(r"   \/_/    \/_/\/_/\/_____/\/_____/\/_/   \/_/\/_____/\/_/ /_/\/____/      ")
    print(r"              __    __  ______  __   __  ______  ______  ______  ______    ")
    print(r'             /\ "-./  \/\  __ \/\ "-.\ \/\  __ \/\  ___\/\  ___\/\  == \   ')
    print(r"             \ \ \-./\ \ \  __ \ \ \-.  \ \  __ \ \ \__ \ \  __\\ \  __<   ")
    print(r'              \ \_\ \ \_\ \_\ \_\ \_\\"\_\ \_\ \_\ \_____\ \_____\ \_\ \_\ ')
    print(r"               \/_/  \/_/\/_/\/_/\/_/ \/_/\/_/\/_/\/_____/\/_____/\/_/ /_/ ")
    print("════════════════════════════════════════════════════════════════════════════")

# Displays menu screen
def display_menu():
    display_title()
    print(" Main Menu:")
    print("  1. Login")
    print("  2. Register")
    print("  3. Info")
    print("  4. Exit")

# Displays account menu screen
def display_account_menu():
    print("___Account___")
    print("  1. Passwords")
    print("  2. Add Password")
    print("  3. Settings")
    print("  4. Sign out")

# Displays account setting screen
def display_account_settings(email):
    print("___Account Settings___")
    print("  1. Email Notification : " + email)
    print("  2. Exit")

# Helper function to creates formated email
def notification_message(email_user, user_email):
    message = f"""\
From: {email_user}
To: {user_email}
Subject: Alert

Your Password Manager account has been signed on
"""
    return message

def info():
    print("Password manager created by Brendan Wong")
    print("Security features include:\n" \
    " Argon2 hashing\n" \
    " AES-256-GCM encryption\n" \
    " Multi-factor authentication\n" \
    " Localised storage\n" \
    " Masked passwords and non-permanent display of passwords\n" \
    " Automated 5-minute account timeout\n" \
    " Master Password strength requirements\n" \
    " Email notification of account access")

main()