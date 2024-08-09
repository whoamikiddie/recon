#include <iostream>
#include <cstdlib>
#include <pwd.h>
#include <unistd.h>

// Function to execute system commands
void execute_command(const std::string& command) {
    std::system(command.c_str());
}

int main() {
    // Get the current user's home directory
    

    // Colors for terminal output
    const std::string CYAN = "\033[36m";
    const std::string GREEN = "\033[32m";
    const std::string BLUE = "\033[34m";
    const std::string RESET = "\033[0m";

    //banner 

  

std::cout << CYAN << " ######################################################### " << RESET << std::endl;
    std::cout << CYAN << " #                 TOOLS FOR BUG BOUNTY                  # " << RESET << std::endl;
    std::cout << CYAN << " ######################################################### " << RESET << std::endl;

    std::cout << BLUE << R"(
                    ██████╗ ██████╗ ██╗  ██╗
                    ██╔══██╗██╔══██╗██║  ██║
                    ██████╔╝██████╔╝███████║
                    ██╔══██╗██╔══██╗██╔══██║
                    ██████╔╝██████╔╝██║  ██║
                    ╚═════╝ ╚═════╝ ╚═╝  ╚═╝
)" << RESET << std::endl;

    // Inform the user about updates and installations
    std::cout << GREEN << " [+] Updating and installing dependencies " << RESET << std::endl;
    execute_command("sudo apt-get -y update");
    execute_command("sudo apt-get -y upgrade");

    execute_command("sudo add-apt-repository -y ppa:apt-fast/stable < /dev/null");
    execute_command("echo debconf apt-fast/maxdownloads string 16 | sudo debconf-set-selections");
    execute_command("echo debconf apt-fast/dlflag boolean true | sudo debconf-set-selections");
    execute_command("echo debconf apt-fast/aptmanager string apt-get | sudo debconf-set-selections");
    execute_command("sudo apt-get install -y apt-fast");

    execute_command("sudo apt-fast install -y apt-transport-https");
    execute_command("sudo apt-fast install -y libcurl4-openssl-dev");
    execute_command("sudo apt-fast install -y libssl-dev");
    execute_command("sudo apt-fast install -y jq");
    execute_command("sudo apt-fast install -y ruby-full");
    execute_command("sudo apt-fast install -y libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev");
    execute_command("sudo apt-fast install -y build-essential libssl-dev libffi-dev python-dev");
    execute_command("sudo apt-fast install -y python-setuptools");
    execute_command("sudo apt-fast install -y libldns-dev");
    execute_command("sudo apt-fast install -y python3-pip");
    execute_command("sudo apt-fast install -y python-dnspython");

    // Inform the user about tools
    return 0 ;
}