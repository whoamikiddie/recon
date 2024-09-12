import logging
import subprocess
import os

# Example function to return a color string (for logging purposes)
def random_color():
    return "\033[92m"  # Green color for the log message (ANSI escape code)

# Example function to send a Telegram notification
def send_telegram_notification(message):
    # Implement your Telegram notification logic here
    # For the purpose of this example, we'll just print the message
    print(f"Telegram notification: {message}")

# Function to run a command with logging and optional notification
def run_command(command, prefix, target, output_file, report_message, notify_telegram):
    try:
        # Execute the command and redirect output to the specified file
        with open(output_file, 'w') as file:
            process = subprocess.Popen(command, shell=True, stdout=file, stderr=subprocess.STDOUT)
            process.wait()

        # Log completion message
        logging.info(f"{prefix} command for {target} completed successfully.")

        # Send a notification if required
        if notify_telegram and report_message:
            send_telegram_notification(report_message)

    except Exception as e:
        logging.error(f"An error occurred while running the command: {e}")

# Function to perform parameter finding
def directory(target, target_dir, notify_telegram):
    logging.info(f"{random_color()}[*] Directory && Content Discovery ")

    target_folder = os.path.join(target_dir, target)
    os.makedirs(target_folder, exist_ok=True)

    output_file = os.path.join(target_folder, f"dirsearch.txt")

    command = (f"dirsearch -u {target} -e conf,config,bak,backup,swp,old,db,sql,asp,aspx,aspx~,asp~,py,py~,rb,rb~,php,php~,bak,bkp,cache,cgi,conf,csv,html,inc,jar,js,json,jsp,jsp~,lock,log,rar,old,sql,sql.gz,http://sql.zip,sql.tar.gz,sql~,swp,swp~,tar,tar.bz2,tar.gz,txt,wadl,zip,.log,.xml,.js,.json -o {output_file}")


    run_command(command, "Dirsearch", target,
                report_message=f"Dirsearch for {target} completed." if notify_telegram else None,
                notify_telegram=notify_telegram)

    logging.info(f"Output file saved to {output_file}")

# Main script execution
if __name__ == "__main__":
    # Set up logging
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    # Define the arguments
    target_dir = '/home/kiddie/Videos'  # Replace with the actual directory path
    target = 'example.com'  # Replace with the actual target
    notify_telegram = True  # Set to True or False based on your preference

    # Call the Parameters function
    directory(target_dir, target, notify_telegram)
