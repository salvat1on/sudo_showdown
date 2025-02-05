import os
import sys
import time
import subprocess
import shutil
import random
from getpass import getpass
from pathlib import Path
from pygame import mixer

# Game Constants
TMP_DIR = "/tmp/sudo_showdown"
ASSETS_DIR = "./assets"
MUSIC_FILE = os.path.join(ASSETS_DIR, "background_music.mp3")

# ASCII Art for UI
def display_ascii_art(text):
    border = "=" * (len(text) + 4)
    print(f"\n{border}\n| {text} |\n{border}\n")

# Ensure the game is run with sudo
def check_sudo():
    print("\nWelcome to Sudo Showdown! This game requires sudo privileges to run.")
    time.sleep(1)
    print("Enter your sudo password to proceed.")
    sudo_password = getpass("[sudo] password for {}: ".format(os.getlogin()))
    # Validate sudo password
    result = subprocess.run(["sudo", "-S", "-v"], input=(sudo_password + "\n").encode(), stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if result.returncode != 0:
        print("Incorrect password. Exiting game.")
        display_game_over()
    print("Sudo access verified. Let the game begin!")

# Initialize music
def play_music():
    mixer.init()
    mixer.music.load(MUSIC_FILE)
    mixer.music.play(-1)  # Loop indefinitely

# Display the start screen
def display_start_screen():
    display_ascii_art("Sudo Showdown!")
    print("Loading the start screen...\n")
    time.sleep(2)
    print("Get ready for a CTF like no other!")
    input("Press Enter to begin...")

# Display the game over screen
def display_game_over():
    display_ascii_art("Game Over")
    print("Better luck next time!")
    time.sleep(5)
    sys.exit(0)

# Display the completion screen
def display_completion():
    display_ascii_art("Congratulations")
    print("You've beaten all levels of Sudo Showdown!")
    time.sleep(5)
    sys.exit(0)

# Clean up temporary files and Docker containers
def cleanup(level_name=None):
    """
    Cleans up temporary files and Docker containers from the previous level.
    Args:
        level_name (str, optional): The name of the level to clean up.
    """
    print("Cleaning up environments...")

    # Stop and remove previous level container
    if level_name:
        subprocess.run(["sudo", "docker", "stop", level_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["sudo", "docker", "rm", "-f", level_name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        print(f"Stopped and removed previous level container: {level_name}")

    # Ensure all containers using port 5000 are stopped
    try:
        result = subprocess.run(["sudo", "docker", "ps", "-q", "--filter", "publish=5000"], capture_output=True, text=True)
        if result.stdout.strip():
            container_id = result.stdout.strip()
            subprocess.run(["sudo", "docker", "stop", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run(["sudo", "docker", "rm", "-f", container_id], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(f"Stopped and removed Docker container using port 5000: {container_id}")
    except Exception as e:
        print(f"Could not check for containers using port 5000: {e}")

    # Find and kill any process using port 5000
    try:
        result = subprocess.run(["sudo", "lsof", "-ti:5000"], capture_output=True, text=True)
        if result.stdout.strip():
            pids = result.stdout.strip().split("\n")
            for pid in pids:
                subprocess.run(["sudo", "kill", "-9", pid])
                print(f"Killed process using port 5000 (PID: {pid})")
    except Exception as e:
        print(f"Could not check for processes on port 5000: {e}")

    # Remove temporary files directory if it exists
    if os.path.exists("/tmp/sudo_showdown"):
        shutil.rmtree("/tmp/sudo_showdown")
        print("Removed temporary directory: /tmp/sudo_showdown")

    # Prune unused containers and networks
    subprocess.run(["sudo", "docker", "container", "prune", "-f"], stdout=subprocess.DEVNULL)
    subprocess.run(["sudo", "docker", "network", "prune", "-f"], stdout=subprocess.DEVNULL)
    print("Cleaned up unused Docker containers and networks.")
    
# Correct flags for each level
CORRECT_FLAGS = {
    "level1": "FLAG-{SQLI_SUCCESS}",
    "level2": "FLAG-{COMMAND_INJECTION}",
    "level3": "FLAG-{FILE_INCLUSION}",
    "level4": "FLAG-{PRIVILEGE_ESCALATION}",
    "level5": "FLAG-{BUFFER_OVERFLOW}",
    "level6": "FLAG-{XSS}",
    "level7": "FLAG-{RCE}",
    "level8": "FLAG-{PATH_TRAVERSAL}",
    "level9": "FLAG-{CSRF}",
    "level10": "FLAG-{STEGANOGRAPHY}",
    "level11": "FLAG-{PASSWORD_CRACKING}",
    "level12": "FLAG-{REVERSE_SHELL}",
    "level13": "FLAG-{ROP_EXPLOIT}",
}

# Function to check the player's flag submission
def submit_flag(level_name):
    correct_flag = CORRECT_FLAGS.get(level_name)
    if not correct_flag:
        print(f"Error: No flag for {level_name} found.")
        return False

    # Prompt the player to submit the flag
    print(f"\nSubmit the flag for {level_name}:")
    player_flag = input("Enter your flag: ").strip()

    # Check if the submitted flag is correct
    if player_flag == correct_flag:
        print("Correct! You've completed this level.")
        return True
    else:
        print("Incorrect flag. Try again.")
        return False

# Initialize music
def play_music():
    mixer.init()
    mixer.music.load(MUSIC_FILE)
    mixer.music.play(-1)  # Loop indefinitely

def setup_flask_app(level_name, **kwargs):
    """
    Sets up a Flask web application for a specific level.
    Args:
        level_name (str): The name of the level to set up.
        **kwargs: Flags to enable specific vulnerabilities (e.g., sqli=True, file_inclusion=True).
    """
    # Clean up previous level environment before setting up the new one
    cleanup(level_name)
    
    level_dir = os.path.join(TMP_DIR, level_name)
    os.makedirs(level_dir, exist_ok=True)

    # Generate Flask app code based on the specified vulnerabilities
    app_code = """
from flask import Flask, request, send_from_directory, render_template_string

app = Flask(__name__)

# Vulnerability handlers
"""

    if kwargs.get("sqli"):
        app_code += """
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        if username == "admin" and password == "or true--":
            return "Flag: FLAG-{SQLI_SUCCESS}"
        return "Invalid login. Try again."
    return '''
    <form method="POST">
        <label>Username:</label>
        <input type="text" name="username"><br>
        <label>Password:</label>
        <input type="text" name="password"><br>
        <button type="submit">Login</button>
    </form>
    '''
"""

    if kwargs.get("csrf"):
        app_code += """
@app.route("/transfer", methods=["GET", "POST"])
def transfer():
    # This endpoint is vulnerable to CSRF because it does not validate any CSRF token.
    # A state-changing operation (simulated bank transfer) is performed without proper protection.
    if request.method == "POST":
        amount = request.form.get("amount")
        # If the malicious request transfers exactly "1000000", the flag is revealed.
        if amount == "1000000":
            return "FLAG-{CSRF}"
        return "Transfer of $" + amount + " completed."
    return '''
    <h1>Bank Transfer</h1>
    <form method="POST" action="/transfer">
        <label>Amount:</label>
        <input type="text" name="amount">
        <button type="submit">Transfer</button>
    </form>
    '''
"""

    if kwargs.get("rce"):
        app_code += """
import os

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        command = request.form.get("command", "")
        # If the user requests the flag, return it.
        if command.strip() == "cat /app/flag.txt":
            return "FLAG-{RCE}"
        try:
            output = os.popen(command).read()
        except Exception as e:
            output = f"Error: {str(e)}"
        return f"<h1>Command Output:</h1><pre>{output}</pre>"
    return '''
    <h1>Remote Code Execution Challenge</h1>
    <form method="POST">
        <label>Enter command:</label>
        <input type="text" name="command">
        <button type="submit">Execute</button>
    </form>
    '''
"""

    if kwargs.get("file_inclusion"):
        app_code += """
@app.route("/", methods=["GET"])
def index():
    file = request.args.get("page", "default.txt")  # Default to 'default.txt'
    try:
        # Vulnerable to Local File Inclusion
        # Allow file inclusion of files outside the intended directory
        if file == "flag.txt":
            # Create the flag.txt with the required contents
            with open("/app/files/flag.txt", "w") as flag_file:
                flag_file.write("FLAG-{FILE_INCLUSION}")
        return send_from_directory("/app/files", file)
    except Exception as e:
        return f"Error: {str(e)}"
"""

    if kwargs.get("path_traversal"):
        app_code += """
@app.route("/", methods=["GET"])
def index():
    file = request.args.get("page", "default.txt")  # Default to 'default.txt'
    try:
        # Vulnerable to Path Traversal: no input sanitization allows traversal sequences (../)
        if file == "flag.txt":
            return "FLAG-{PATH_TRAVERSAL}"
        return send_from_directory("/app/files", file)
    except Exception as e:
        return f"Error: {str(e)}"
"""


    if kwargs.get("xss"):
        app_code += """
from flask import session

# Secret key required for session to work
app.secret_key = "super_secret_key"

@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        session["input"] = request.form.get("input", "")

    user_input = session.get("input", request.args.get("input", ""))  # Retrieve input from session or GET request
    
    # Check if the input contains a common XSS payload
    if "<script>" in user_input.lower():
        return "FLAG-{XSS}"

    # Vulnerable to XSS - unsanitized user input is reflected
    return render_template_string('<h1>Welcome to the XSS Challenge</h1><p>{}</p>'.format(user_input))
"""

    if kwargs.get("custom_route"):
        custom_code = kwargs.get("custom_route")
        app_code += f"\n{custom_code}\n"

    app_code += """
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
"""

    # Write the Flask app code to a file
    app_file = os.path.join(level_dir, "app.py")
    with open(app_file, "w") as f:
        f.write(app_code)

    # Prepare additional resources based on vulnerabilities
    if kwargs.get("file_inclusion"):
        files_dir = os.path.join(level_dir, "files")
        os.makedirs(files_dir, exist_ok=True)
        with open(os.path.join(files_dir, "default.txt"), "w") as f:
            f.write("Welcome to the File Inclusion challenge!")
        with open(os.path.join(files_dir, "flag.txt"), "w") as f:
            f.write("FLAG-{FILE_INCLUSION}")

    # Create a Dockerfile to run the Flask app
    dockerfile_content = f"""
FROM python:3.9-slim
WORKDIR /app
COPY . /app
RUN pip install flask
CMD ["python", "app.py"]
"""
    dockerfile_path = os.path.join(level_dir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)

    # Build and run the Docker container
    subprocess.run(["sudo", "docker", "build", "-t", level_name, level_dir])
    subprocess.run(["sudo", "docker", "run", "-d", "-p", "5000:5000", "--name", level_name, level_name])
    print(f"Level {level_name} environment is ready and running at http://localhost:5000")

# Level implementation templates with flag checking
def level_sql_injection():
    print("\nLevel 1: SQL Injection\n")
    print("Description: Bypass the login page of a vulnerable web application.")
    time.sleep(2)
    setup_flask_app("level1", sqli=True)
    print("Challenge: Use SQL injection to log in as admin.")
    
    # Wait for flag submission
    while not submit_flag("level1"):
        pass  # Keep asking until the correct flag is submitted
    
    return True

# Function to set up a vulnerable script for command injection
def setup_vulnerable_script(level_name):
    """
    Sets up a Flask web application with a command injection vulnerability.
    Args:
        level_name (str): The name of the level to set up.
    """
    # Clean up previous level environment before setting up the new one
    cleanup(level_name)

    level_dir = os.path.join(TMP_DIR, level_name)
    os.makedirs(level_dir, exist_ok=True)

    # Vulnerable Flask application allowing command injection
    script_code = """
from flask import Flask, request
import os

app = Flask(__name__)

@app.route("/")
def home():
    return "Command Injection Challenge - Try /ping?host=localhost"

@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host:
        return "No host provided", 400
    output = os.popen(f"ping -c 1 {host}").read()
    if "FLAG-{COMMAND_INJECTION}" in output:
        return "Congratulations! You got the flag: FLAG-{COMMAND_INJECTION}"
    return f"<pre>{output}</pre>"

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
"""
    script_file = os.path.join(level_dir, "app.py")
    with open(script_file, "w") as f:
        f.write(script_code)

    # Create a Dockerfile to run the script
    dockerfile_content = f"""
FROM python:3.9-slim
WORKDIR /app
COPY . /app
RUN pip install flask
CMD ["python", "app.py"]
"""
    dockerfile_path = os.path.join(level_dir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)

    # Create the flag file with the flag content
    flag_file_path = os.path.join(level_dir, "flag.txt")
    with open(flag_file_path, "w") as f:
        f.write("FLAG-{COMMAND_INJECTION}")  # The flag players will need to retrieve

    # Build and run the Docker container
    subprocess.run(["sudo", "docker", "build", "-t", level_name, level_dir])
    subprocess.run(["sudo", "docker", "run", "-d", "-p", "5000:5000", "--name", level_name, level_name])
    print(f"Level {level_name} environment is ready and running at http://localhost:5000")

def level_command_injection():
    print("\nLevel 2: Command Injection\n")
    print("Description: Exploit a Python script to execute arbitrary commands.")
    time.sleep(2)
    setup_vulnerable_script("level2")
    print("Challenge: Inject commands to reveal the flag.")
    
    while not submit_flag("level2"):
        pass  # Keep asking until the correct flag is submitted

    return True

def level_file_inclusion():
    print("\nLevel 3: File Inclusion\n")
    print("Description: Exploit a file inclusion vulnerability to access sensitive files.")
    time.sleep(2)
    setup_flask_app("level3", file_inclusion=True)
    print("Challenge: Use path traversal to read the flag file.")
    
    while not submit_flag("level3"):
        pass  # Keep asking until the correct flag is submitted

    return True

def setup_privilege_escalation_env(level_name):
    """
    Sets up a vulnerable Flask application for privilege escalation in a Dockerized environment.
    Args:
        level_name (str): The name of the level to set up.
    """
    # Clean up previous level environment before setting up the new one
    cleanup(level_name)
    
    level_dir = os.path.join(TMP_DIR, level_name)
    os.makedirs(level_dir, exist_ok=True)

    # Vulnerable Flask application for privilege escalation
    app_code = """
from flask import Flask, request, jsonify

app = Flask(__name__)

# Simulated user database
users = {
    "admin": {"role": "admin", "password": "supersecret"},
    "user": {"role": "user", "password": "password123"}
}

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    
    if username in users and users[username]['password'] == password:
        # Return user role without secure checks
        return jsonify({"message": "Login successful", "role": users[username]['role']})
    else:
        return jsonify({"message": "Invalid credentials"}), 401

@app.route('/admin', methods=['GET'])
def admin_panel():
    # This endpoint improperly trusts user-supplied role
    role = request.args.get('role')
    if role == 'admin':
        return jsonify({"message": "Welcome to the admin panel! flag = FLAG-{PRIVILEGE_ESCALATION}"})
    else:
        return jsonify({"message": "Access denied"}), 403

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
"""
    app_file = os.path.join(level_dir, "app.py")
    with open(app_file, "w") as f:
        f.write(app_code)

    # Dockerfile for the Flask application
    dockerfile_content = f"""
FROM python:3.9-slim
WORKDIR /app
COPY . /app
RUN pip install flask
CMD ["python", "app.py"]
"""
    dockerfile_path = os.path.join(level_dir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)

    # Build and run the Docker container
    subprocess.run(["sudo", "docker", "build", "-t", level_name, level_dir], check=True)
    subprocess.run(["sudo", "docker", "run", "-d", "--rm", "-p", "5000:5000", "--name", level_name, level_name], check=True)

    print(f"Level {level_name} environment is ready. Access it at http://localhost:5000/login.")

def level_privilege_escalation():
    print("\nLevel 4: Privilege Escalation\n")
    print("Description: Exploit a misconfigured system to gain root privileges.")
    time.sleep(2)
    setup_privilege_escalation_env("level4")
    print("Challenge: Escalate privileges to root and read the flag.")
    
    while not submit_flag("level4"):
        pass  # Keep asking until the correct flag is submitted

    return True

def setup_vulnerable_binary(level_name, **kwargs):
    """
    Sets up a vulnerable binary application for exploitation in a Dockerized environment.
    Args:
        level_name (str): The name of the level to set up.
        **kwargs: Flags to enable specific vulnerabilities or customize the binary.
            Examples:
                - format_string: Boolean, includes a format string vulnerability.
                - custom_code: String, custom C code to use for the binary.
    """
    cleanup(level_name)
    
    level_dir = os.path.join(TMP_DIR, level_name)
    os.makedirs(level_dir, exist_ok=True)
    
    # Default C code for a buffer overflow vulnerability with a hidden win() function.
    c_code = """
#include <stdio.h>
#include <string.h>

void win() {
    printf("FLAG-{BUFFER_OVERFLOW}\\n");
}

void vulnerable_function(char *input) {
    char buffer[64];
    strcpy(buffer, input); // Vulnerable: No bounds checking
    printf("You entered: %s\\n", buffer);
}

int main(int argc, char *argv[]) {
    printf("Address of win: %p\\n", win);
    if (argc < 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
"""
    if kwargs.get("format_string"):
        c_code = """
#include <stdio.h>
#include <string.h>

void win() {
    printf("FLAG-{BUFFER_OVERFLOW}\\n");
}

void vulnerable_function(char *input) {
    printf(input); // Vulnerable: Format string attack
    printf("\\n");
}

int main(int argc, char *argv[]) {
    printf("Address of win: %p\\n", win);
    if (argc < 2) {
        printf("Usage: %s <input>\\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
"""
    if kwargs.get("custom_code"):
        c_code = kwargs["custom_code"]
    
    c_file = os.path.join(level_dir, "vuln.c")
    with open(c_file, "w") as f:
        f.write(c_code)
    
    dockerfile_content = f"""
FROM i386/debian:bullseye-slim
RUN apt-get update && apt-get install -y gcc libc6-dev make python3 procps
WORKDIR /app
COPY . /app
RUN gcc -m32 -o vuln vuln.c -fno-stack-protector -z execstack -g -Wl,-Ttext-segment=0x08048000
CMD ["/bin/bash", "-c", "sysctl -w kernel.randomize_va_space=0 && while true; do sleep 3600; done"]
"""
    dockerfile_path = os.path.join(level_dir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)
    
    subprocess.run(["sudo", "docker", "build", "-t", level_name, level_dir], check=True)
    subprocess.run(["sudo", "docker", "run", "-d", "--privileged", "-p", "5000:5000", "--name", level_name, level_name], check=True)
    
    print(f"Level {level_name} environment is ready. The vulnerable binary is running inside the container.")

def level_buffer_overflow():
    print("\nLevel 5: Buffer Overflow\n")
    print("Description: Exploit a vulnerable C program to gain control of execution.")
    time.sleep(2)
    setup_vulnerable_binary("level5")
    print("Challenge: Use buffer overflow techniques to execute your payload.")
    
    while not submit_flag("level5"):
        pass  # Keep asking until the correct flag is submitted

    return True

def level_xss():
    print("\nLevel 6: Cross-Site Scripting (XSS)\n")
    print("Description: Inject malicious JavaScript into a web application.")
    time.sleep(2)
    setup_flask_app("level6", xss=True)
    print("Challenge: Inject JavaScript to steal cookies.")
    
    while not submit_flag("level6"):
        pass  # Keep asking until the correct flag is submitted

    return True

def level_rce():
    print("\nLevel 7: Remote Code Execution (RCE)\n")
    print("Description: Exploit a vulnerable web app to execute commands on the server.")
    time.sleep(2)
    setup_flask_app("level7", rce=True)
    print("Challenge: Execute remote commands to get the flag.")
    
    while not submit_flag("level7"):
        pass  # Keep asking until the correct flag is submitted

    return True

def level_path_traversal():
    print("\nLevel 8: Path Traversal\n")
    print("Description: Exploit a vulnerable web server to access restricted files.")
    time.sleep(2)
    setup_flask_app("level8", path_traversal=True)
    print("Challenge: Use path traversal to read sensitive files.")
    
    while not submit_flag("level8"):
        pass  # Keep asking until the correct flag is submitted

    return True

def level_csrf():
    print("\nLevel 9: Cross-Site Request Forgery (CSRF)\n")
    print("Description: Perform unauthorized actions on a web app.")
    time.sleep(2)
    setup_flask_app("level9", csrf=True)
    print("Challenge: Exploit CSRF to perform an unauthorized action.")
    
    while not submit_flag("level9"):
        pass  # Keep asking until the correct flag is submitted

    return True

def setup_steganography_challenge(level_name):
    """
    Sets up a steganography challenge by embedding hidden data within an image file.
    Args:
        level_name (str): The name of the level to set up.
    """
    # Clean up previous level environment before setting up the new one
    cleanup(level_name)
    
    import base64
    from PIL import Image
    import numpy as np

    level_dir = os.path.join(TMP_DIR, level_name)
    os.makedirs(level_dir, exist_ok=True)

    # Original image creation
    image_width, image_height = 200, 200
    image = Image.new("RGB", (image_width, image_height), color=(255, 255, 255))  # White background
    image_path = os.path.join(level_dir, "original_image.png")
    image.save(image_path)

    # Secret data to embed
    secret_message = "FLAG-{STEGANOGRAPHY}"
    secret_message_encoded = base64.b64encode(secret_message.encode()).decode()  # Encode as base64

    # Embed the secret message into the least significant bits (LSBs) of the image
    image_array = np.array(image)
    flat_image_array = image_array.flatten()
    binary_message = ''.join(format(ord(char), '08b') for char in secret_message_encoded)  # Binary format

    if len(binary_message) > len(flat_image_array):
        raise ValueError("Secret message is too long to embed in the image.")

    # Replace the LSBs of the image with the message
    for i, bit in enumerate(binary_message):
        flat_image_array[i] = (flat_image_array[i] & ~1) | int(bit)

    # Reshape and save the steganographic image
    stego_image_array = flat_image_array.reshape(image_array.shape)
    stego_image = Image.fromarray(stego_image_array.astype('uint8'))
    stego_image_path = os.path.join(level_dir, "stego_image.png")
    stego_image.save(stego_image_path)

    # Create challenge instructions
    instructions = f"""
Welcome to the Steganography Challenge!

Your goal is to extract the hidden data embedded in the provided image.
The steganographic image can be found in the file: stego_image.png

Hint: The secret message is embedded in the least significant bits of the image's pixels. 
Once extracted, decode it from Base64 to reveal the hidden flag.

Good luck!
"""
    instructions_file = os.path.join(level_dir, "instructions.txt")
    with open(instructions_file, "w") as f:
        f.write(instructions)

    print(f"Level {level_name} steganography challenge is set up. Files created:")
    print(f"- {image_path} (original image)")
    print(f"- {stego_image_path} (steganographic image)")
    print(f"- {instructions_file} (challenge instructions)")

def level_steganography():
    print("\nLevel 10: Steganography\n")
    print("Description: Extract hidden data from an image to find the flag.")
    time.sleep(2)
    setup_steganography_challenge("level10")
    print("Challenge: Use steganographic techniques to extract the flag.")
    
    while not submit_flag("level10"):
        pass  # Keep asking until the correct flag is submitted

    return True

def setup_password_cracking_env(level_name):
    """
    Sets up a password cracking environment by creating a password-protected zip file.
    The zip file contains a text file that holds the flag: "FLAG-{PASSWORD_CRACKING}".
    The instructions inform the player to use a tool like rarcrack (or any zip password cracking tool)
    to recover the password and extract the flag.
    
    Args:
        level_name (str): The name of the level to set up.
    """
    # Clean up previous level environment before setting up the new one
    cleanup(level_name)
    
    import os
    import random
    import string
    import subprocess

    level_dir = os.path.join(TMP_DIR, level_name)
    os.makedirs(level_dir, exist_ok=True)

    # Generate a random password (for example, 10 characters long)
    random_password = ''.join(random.choices(string.ascii_letters + string.digits, k=10))

    # Create a text file that holds the flag
    flag = "FLAG-{PASSWORD_CRACKING}"
    flag_file_path = os.path.join(level_dir, "flag.txt")
    with open(flag_file_path, "w") as f:
        f.write(flag)
    
    # Create a zip file that contains the flag file, using the random password.
    # (Note: The built-in zip utility uses weak encryption with the -P option.)
    zip_file_path = os.path.join(level_dir, "flag.zip")
    subprocess.run(["zip", "-P", random_password, "flag.zip", "flag.txt"], cwd=level_dir, check=True)
    
    # Remove the plain flag.txt file so that only the password-protected zip remains.
    os.remove(flag_file_path)
    
    # Create challenge instructions
    instructions = f"""
Welcome to the Password Cracking Challenge!

Your goal is to crack the password protected zip file: flag.zip.
Inside the zip file, there is a text file that contains the flag.

The zip file is protected with a randomly generated password.
You can use tools like rarcrack (or any zip password cracking tool) to recover the password.

Once you have the password, extract the zip file to reveal the flag

Good luck!
"""
    instructions_file = os.path.join(level_dir, "instructions.txt")
    with open(instructions_file, "w") as f:
        f.write(instructions)
    
    print(f"Level {level_name} password cracking environment is set up. Files created:")
    print(f"- Zip file: {zip_file_path}")
    print(f"- Instructions: {instructions_file}")

def level_password_cracking():
    print("\nLevel 11: Password Cracking\n")
    print("Description: Crack a zip file to retrieve the flag.")
    time.sleep(2)
    setup_password_cracking_env("level11")
    print("Challenge: Use tools like John the Ripper to crack the password.")
    
    while not submit_flag("level11"):
        pass  # Keep asking until the correct flag is submitted

    return True

def setup_vulnerable_binary2(level_name, **kwargs):
    """
    Sets up a vulnerable binary application for reverse shell exploitation in a Dockerized environment.
    This binary contains a hidden function reverse_shell() that, when executed, prints the flag
    "FLAG-{REVERSE_SHELL}" and spawns a shell.
    
    Args:
        level_name (str): The name of the level to set up.
        **kwargs: Additional options (currently not used).
    """
    cleanup(level_name)
    
    level_dir = os.path.join(TMP_DIR, level_name)
    os.makedirs(level_dir, exist_ok=True)
    
    # C code for reverse shell vulnerability.
    # Vulnerability: Buffer overflow via strcpy() into a 64-byte buffer.
    # The hidden function reverse_shell() prints the flag and spawns a shell.
    c_code = r"""
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void reverse_shell() {
    printf("FLAG-{REVERSE_SHELL}\n");
    // Spawn a shell (simulate reverse shell)
    system("/bin/sh");
}

void vulnerable_function(char *input) {
    char buffer[64];
    // Vulnerable: No bounds checking.
    strcpy(buffer, input);
    printf("You entered: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    printf("Address of reverse_shell: %p\n", reverse_shell);
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
"""
    c_file = os.path.join(level_dir, "vuln.c")
    with open(c_file, "w") as f:
        f.write(c_code)
    
    dockerfile_content = r"""
FROM i386/debian:bullseye-slim
RUN apt-get update && apt-get install -y gcc libc6-dev make
WORKDIR /app
COPY . /app
RUN gcc -m32 -o vuln vuln.c -fno-stack-protector -z execstack -g -Wl,-Ttext-segment=0x08048000
CMD ["/bin/bash", "-c", "while true; do sleep 3600; done"]
"""
    dockerfile_path = os.path.join(level_dir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)
    
    subprocess.run(["sudo", "docker", "build", "-t", level_name, level_dir], check=True)
    subprocess.run(["sudo", "docker", "run", "-d", "--rm", "--name", level_name, level_name], check=True)
    
    print(f"Level {level_name} environment is ready. The vulnerable binary is running inside the container.")

def level_reverse_shell():
    print("\nLevel 12: Reverse Shell via Binary Exploitation\n")
    print("Description: Exploit a binary to spawn a reverse shell and retrieve the flag.")
    time.sleep(2)
    setup_vulnerable_binary2("level12", reverse_shell=True)
    print("Challenge: Exploit the binary to spawn a reverse shell.")
    
    while not submit_flag("level12"):
        pass  # Keep asking until the correct flag is submitted

    return True

def setup_vulnerable_binary3(level_name, **kwargs):
    """
    Sets up a vulnerable binary application for Return-Oriented Programming (ROP) exploitation
    in a Dockerized environment.
    The binary contains a hidden function 'win()' that prints the flag "FLAG-{ROP_EXPLOIT}".
    The binary is compiled as 32-bit with NX enabled (stack non-executable) and PIE disabled,
    so that addresses are predictable and the exploit must use a ROP chain.
    
    Args:
        level_name (str): The name of the level to set up.
        **kwargs: Additional options (not used currently).
    """
    cleanup(level_name)
    
    import os
    import subprocess
    
    level_dir = os.path.join(TMP_DIR, level_name)
    os.makedirs(level_dir, exist_ok=True)
    
    # C code with a hidden win() function for ROP exploitation.
    # The binary is vulnerable to buffer overflow via strcpy() into a 64-byte buffer.
    # Note: NX is enabled (we do not disable the executable stack), so injected shellcode will not run.
    # The win() function prints the flag "FLAG-{ROP_EXPLOIT}".
    c_code = r"""
#include <stdio.h>
#include <string.h>

void win() {
    printf("FLAG-{ROP_EXPLOIT}\n");
}

void vulnerable_function(char *input) {
    char buffer[64];
    // Vulnerable: No bounds checking.
    strcpy(buffer, input);
    printf("You entered: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    // Print the address of win() so the player knows where to aim their ROP chain.
    printf("Address of win: %p\n", win);
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vulnerable_function(argv[1]);
    return 0;
}
"""
    c_file = os.path.join(level_dir, "vuln.c")
    with open(c_file, "w") as f:
        f.write(c_code)
    
    dockerfile_content = r"""
FROM i386/debian:bullseye-slim
RUN apt-get update && apt-get install -y gcc libc6-dev make
WORKDIR /app
COPY . /app
# Compile as 32-bit with no stack protector, disable PIE so that addresses remain fixed.
# Do not use -z execstack so that NX is enabled.
RUN gcc -m32 -o vuln vuln.c -fno-stack-protector -g -no-pie -Wl,-Ttext-segment=0x08048000
CMD ["/bin/bash", "-c", "while true; do sleep 3600; done"]
"""
    dockerfile_path = os.path.join(level_dir, "Dockerfile")
    with open(dockerfile_path, "w") as f:
        f.write(dockerfile_content)
    
    subprocess.run(["sudo", "docker", "build", "-t", level_name, level_dir], check=True)
    subprocess.run(["sudo", "docker", "run", "-d", "--rm", "--name", level_name, level_name], check=True)
    
    print(f"Level {level_name} environment is ready. The vulnerable binary is running inside the container.")

def level_rop_exploit():
    print("\nLevel 13: Return-Oriented Programming (ROP) Exploitation\n")
    print("Description: Exploit a vulnerable binary using ROP techniques to execute arbitrary code.")
    time.sleep(2)
    setup_vulnerable_binary3("level13", rop_exploit=True)
    print("Challenge: Use ROP gadgets to execute your payload and retrieve the flag.")
    
    while not submit_flag("level13"):
        pass  # Keep asking until the correct flag is submitted

    return True

# Game flow
def main():
    check_sudo()
    play_music()
    display_start_screen()

    # Create temporary directory
    os.makedirs(TMP_DIR, exist_ok=True)

    try:
        # Levels
        levels = [
            level_sql_injection,
            level_command_injection,
            level_file_inclusion,
            level_privilege_escalation,
            level_buffer_overflow,
            level_xss,
            level_rce,
            level_path_traversal,
            level_csrf,
            level_steganography,
            level_password_cracking,
            level_reverse_shell,
            level_rop_exploit,
        ]

        for i, level in enumerate(levels, start=1):
            print(f"\nStarting Level {i}...\n")
            if not level():
                display_game_over()

        display_completion()

    finally:
        # Cleanup on exit
        cleanup()
        mixer.music.stop()

# Run the game
if __name__ == "__main__":
    main()
