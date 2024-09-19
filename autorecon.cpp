#include <iostream>
#include <fstream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <json/json.h>
#include <ctime>
#include <random>
#include <netdb.h>
#include <cstring>
#include <arpa/inet.h>   
#include <cstdio>
#include <memory>
#include <chrono>
#include <thread>

// color
std::string random_color() {
    return "\033[32m"; 
}
 
 // logs
void log_message(const std::string& message) {
    time_t now = time(0);
    tm* ltm = localtime(&now);
    std::cout << random_color() << "[" << 1900 + ltm->tm_year << "-" 
              << 1 + ltm->tm_mon << "-" << ltm->tm_mday << " "
              << 1 + ltm->tm_hour << ":" << 1 + ltm->tm_min << ":" << 1 + ltm->tm_sec
              << "] - " << message << std::endl;
}

std::string create_target_directory(const std::string& target) {
    std::string base_dir = "target";
    mkdir(base_dir.c_str(), 0777);
    std::string target_dir = base_dir + "/" + target;
    mkdir(target_dir.c_str(), 0777);
    return target_dir;
}

// getting target ip addr
std::string get_ip_address(const std::string& target) {
    struct hostent* host = gethostbyname(target.c_str());
    if (host == nullptr) {
        log_message("Error getting IP address: " + std::string(hstrerror(h_errno)));
        return "";
    }
    struct in_addr* addr = (struct in_addr*)host->h_addr;
    return inet_ntoa(*addr);
}

bool read_config(std::string& bot_token, std::string& chat_id) {
    std::ifstream config_file("config.json");
    if (config_file.is_open()) {
        Json::Value config;
        config_file >> config;
        bot_token = config["bot_token"].asString();
        chat_id = config["chat_id"].asString();
        config_file.close();
        return true;
    }
    return false;
}

void write_config(const std::string& bot_token, const std::string& chat_id) {
    Json::Value config;
    config["bot_token"] = bot_token;
    config["chat_id"] = chat_id;
    std::ofstream config_file("config.json");
    config_file << config;
    config_file.close();
}

// sending msg 
void send_telegram_message(const std::string& bot_token, const std::string& chat_id, const std::string& message) {
    CURL* curl;
    CURLcode res;
    curl = curl_easy_init();
    if (curl) {
        std::string url = "https://api.telegram.org/bot" + bot_token + "/sendMessage";
        std::string data = "chat_id=" + chat_id + "&text=" + message;
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log_message("Error sending Telegram message: " + std::string(curl_easy_strerror(res)));
        }
        curl_easy_cleanup(curl);
    }
}


// making fn for run_command
void run_command(const std::string& command, const std::string& tool_name, const std::string& target, const std::string& output_file) {
    log_message("Running " + tool_name);
    
    std::string cmd = command + " > " + output_file + " 2>/dev/null";
    
    int result = system(cmd.c_str());
    if (result == 0) {
        log_message(tool_name + " completed successfully");
    } else {
        log_message(tool_name + " failed with error");
    }
}


std::string exec_command(const char* cmd) {
    std::array<char, 128> buffer;
    std::string result;
    std::unique_ptr<FILE, decltype(&pclose)> pipe(popen(cmd, "r"), pclose);
    if (!pipe) {
        throw std::runtime_error("popen() failed!");
    }
    while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
        result += buffer.data();
    }
    return result;
}

// detect waf using wafw00f
std::string detect_waf(const std::string& target) {
    std::string command = "wafw00f " + target;
    std::string output = exec_command(command.c_str());

    std::string waf_info = "Unknown";
    if (output.find("is behind") != std::string::npos) {
        size_t pos = output.find("is behind");
        waf_info = output.substr(pos + 10); // Extract the name of the WAF
    }
    return waf_info;
}

// banner

void print_banner(const std::string& target, const std::string& ip_address, const std::string& waf_info) {
    std::string banner[] = {
        "-------------------------------------------------",
        "███████╗ █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗",
        "██╔════╝██╔══██╗████╗  ██║██╔══██╗╚════██╗██╔════╝██╔═████╗████╗  ██║",
        "███████╗███████║██╔██╗ ██║██████╔╝ █████╔╝██║     ██║██╔██║██╔██╗ ██║",
        "╚════██║██╔══██║██║╚██╗██║██╔══██╗ ╚═══██╗██║     ████╔╝██║██║╚██╗██║",
        "███████║██║  ██║██║ ╚████║██║  ██║██████╔╝╚██████╗╚██████╔╝██║ ╚████║",
        "╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
        "-------------------------------------------------"
    };

    for (const std::string& line : banner) {
        std::cout << random_color() << line << std::endl;
        std::this_thread::sleep_for(std::chrono::milliseconds(200)); // Adjust the delay as needed
    }

    std::cout << "Target: " << target << "\n";
    std::cout << "IP Address: " << ip_address << "\n";
    std::cout << "WAF Information: " << waf_info << "\n";
    std::cout << "-------------------------------------------------\n";
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <target>" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    bool notify_telegram = false;

    std::string bot_token, chat_id;
    if (!read_config(bot_token, chat_id)) {
        std::cout << "Enter your Telegram bot token: ";
        std::cin >> bot_token;
        std::cout << "Enter your chat ID: ";
        std::cin >> chat_id;
        write_config(bot_token, chat_id);
    }

    std::string target_dir = create_target_directory(target);
    std::string ip_address = get_ip_address(target);
    if (!ip_address.empty()) {
        std::string waf_info = detect_waf(target);
        print_banner(target, ip_address, waf_info);
    }

    // subfinder for subdomains..
    run_command("subfinder -d " + target, "Subfinder", target, target_dir + "/subfinder.txt");
    
    // assetfinder for subdomains..
    run_command("assetfinder -subs-only " + target, "Assetfinder", target,target_dir + "/assetfinder.txt" );
    std::string sort_command = "cat " + target_dir + "/subfinder.txt " + target_dir + "/assetfinder.txt | sort >> " + target_dir + "/sorted.txt";
    run_command(sort_command, "Sorting Subdomains", target, target_dir + "/sorted.txt");
    return 0;
}
