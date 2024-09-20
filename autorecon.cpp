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
#include <map>
#include <vector>
#include <algorithm>

const std::string GREEN = "\033[32m";
const std::string RESET = "\033[0m";

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

size_t HeaderCallback(char* header, size_t size, size_t nmemb, std::string* userp) {
    userp->append(header, size * nmemb);
    return size * nmemb;
}

// users agents...
std::string get_random_user_agent() {
    std::vector<std::string> user_agents = {
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15",
        "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:93.0) Gecko/20100101 Firefox/93.0"
    };

    static std::random_device rd;
    static std::mt19937 eng(rd());
    std::uniform_int_distribution<> distr(0, user_agents.size() - 1);

    return user_agents[distr(eng)];
}

// sending a request...
std::string sendRequest(const std::string& url, std::string& headers) {
    CURL* curl = curl_easy_init();
    std::string readBuffer;

    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, HeaderCallback);
        curl_easy_setopt(curl, CURLOPT_HEADERDATA, &headers);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);

        std::string user_agent = get_random_user_agent();
        curl_easy_setopt(curl, CURLOPT_USERAGENT, user_agent.c_str());

        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            std::cerr << "cURL error: " << curl_easy_strerror(res) << std::endl;
        }

        curl_easy_cleanup(curl);
    } else {
        std::cerr << "Failed to initialize cURL" << std::endl;
    }
    return readBuffer;
}

// logs...
void log_message(const std::string& message) {
    time_t now = time(0);
    tm* ltm = localtime(&now);
    std::cout << "[" << 1900 + ltm->tm_year << "-" 
              << 1 + ltm->tm_mon << "-" << ltm->tm_mday << " "
              << 1 + ltm->tm_hour << ":" << 1 + ltm->tm_min << ":" << 1 + ltm->tm_sec
              << "] - " << GREEN << message << RESET << std::endl;
}

std::string create_target_directory(const std::string& target) {
    std::string base_dir = "target";
    mkdir(base_dir.c_str(), 0777);
    std::string target_dir = base_dir + "/" + target;
    mkdir(target_dir.c_str(), 0777);
    return target_dir;
}

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

// sending a msg...
void send_telegram_message(const std::string& bot_token, const std::string& chat_id, const std::string& message) {
    CURL* curl = curl_easy_init();
    if (curl) {
        std::string url = "https://api.telegram.org/bot" + bot_token + "/sendMessage";
        std::string data = "chat_id=" + chat_id + "&text=" + curl_easy_escape(curl, message.c_str(), message.length()) + "&parse_mode=Markdown";
        curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        CURLcode res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            log_message("Error sending Telegram message: " + std::string(curl_easy_strerror(res)));
        }
        curl_easy_cleanup(curl);
    }
}
void run_command(const std::string& command, const std::string& tool_name, const std::string& output_file) {
    log_message("Running " + tool_name);
    std::string cmd = command + " > " + output_file + " 2>/dev/null";
    int result = system(cmd.c_str());
    if (result == 0) {
        log_message(GREEN + tool_name + " completed successfully" + RESET);
    } else {
        log_message(GREEN + tool_name + " failed with error" + RESET);
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

// detect the waf using wafw00f...
std::string detect_waf(const std::string& target) {
    std::string command = "wafw00f " + target;
    std::string output = exec_command(command.c_str());

    std::string waf_info = "Unknown";
    if (output.find("is behind") != std::string::npos) {
        size_t pos = output.find("is behind");
        waf_info = output.substr(pos + 10); 
    }
    return waf_info;
}


// banner...
void print_banner(const std::string& target, const std::string& ip_address, const std::string& waf_info) {
    std::string banner[] = {
        "---------------------------------------------------------------------",
        "███████╗ █████╗ ███╗   ██╗██████╗ ██████╗  ██████╗ ██████╗ ███╗   ██╗",
        "██╔════╝██╔══██╗████╗  ██║██╔══██╗╚════██╗██╔════╝██╔═████╗████╗  ██║",
        "███████╗███████║██╔██╗ ██║██████╔╝ █████╔╝██║     ██║██╔██║██╔██╗ ██║",
        "╚════██║██╔══██║██║╚██╗██║██╔═══╝  ╚═══██╗██║     ████╔╝██║██║╚██╗██║",
        "███████║██║  ██║██║ ╚████║██║     ██████╔╝╚██████╗╚██████╔╝██║ ╚████║",
        "╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝     ╚═════╝  ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝",
        "---------------------------------------------------------------------"
    };

    for (const auto& line : banner) {
        std::cout << line << std::endl;
    }

    std::cout << GREEN << "Target: " << RESET << target << std::endl;
    std::cout << GREEN << "IP Address: " << RESET << ip_address << std::endl;
    std::cout << GREEN << "WAF Info: " << RESET << waf_info << std::endl;
}

std::string format_result(const std::string& tool_name, const std::string& result) {
    std::string message = "*[" + tool_name + "]*\n\n";
    message += "```\n" + result + "\n```";
    return message;
}

int main(int argc, char* argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <target>" << std::endl;
        return 1;
    }

    std::string target = argv[1];
    std::string bot_token, chat_id;

    // read and config the token...
    if (!read_config(bot_token, chat_id)) {
        std::cout << GREEN << "Enter your Telegram bot token: " << RESET;
        std::cin >> bot_token;
        std::cout << GREEN << "Enter your chat ID: " << RESET;
        std::cin >> chat_id;
        write_config(bot_token, chat_id);
    }

    // create a dir... 
    std::string target_dir = create_target_directory(target);
    std::string ip_address = get_ip_address(target);
    std::string headers;
    std::string waf_info;

    //  send ip and waf...
    if (!ip_address.empty()) {
        sendRequest("http://" + target, headers);
        waf_info = detect_waf(target);

        std::string initial_message = "*📊 Target Information*\n\n";
        initial_message += "*🔍 Target:* `" + target + "`\n";
        initial_message += "*🌐 IP Address:* `" + ip_address + "`\n";
        initial_message += "*🛡️ WAF Info:* `" + waf_info + "`\n";

        send_telegram_message(bot_token, chat_id, initial_message);
        log_message("Initial information sent to Telegram.");
    }

    std::string tool_message;

    // Whois...
    log_message("Running Whois Lookup... 🔧 ");
    run_command("whois " + target + " | grep -E 'Domain Name|Registry|Registrar|Updated|Creation|Registrant|Name Server|DNSSEC|Status'", "Whois Lookup", target_dir + "/whois.txt");
    tool_message = format_result("🔧 Whois Lookup", exec_command(("cat " + target_dir + "/whois.txt").c_str()));
    send_telegram_message(bot_token, chat_id, tool_message);

    // nslookup...
    log_message("Running NSLookup...🔧");
    run_command("nslookup " + target, "NSLookup", target_dir + "/nslookup.txt");
    tool_message = format_result("🔍NSLookup", exec_command(("cat " + target_dir + "/nslookup.txt").c_str()));
    send_telegram_message(bot_token, chat_id, tool_message);
    
    // cloud-enumeration...
    log_message("Running Cloud-Enum...☁️");
    run_command(("python3 tools/cloud-enum/cloud_enum.py -k " + target + " --quickscan | tee cloud.txt").c_str(), "cloud-enum", target_dir + "/cloud.txt");
    std::string new_tool_message = format_result(" cloud-enum ", exec_command(("cat " + target_dir + "/cloud.txt").c_str()));
    send_telegram_message(bot_token, chat_id, new_tool_message);

    // TheHarvester...
    log_message("Running TheHarvester... 🕵️‍♂️");
    run_command(("python3 ~/tools/theHarvester/theHarvester.py -d " + target + " -b all -l 500 -f theharvester.html > theharvester.txt").c_str(), "TheHarvester", target_dir + "/theharvester.txt");

    log_message("Extracting Users...");
    run_command("awk '/Users/,/IPs/' theharvester.txt | sed -e '1,2d' | head -n -2 | anew -q users.txt", "Extracting Users", target_dir + "/users.txt");
    std::string users_message = format_result("Users found", exec_command(("cat " + target_dir + "/users.txt").c_str()));
    send_telegram_message(bot_token, chat_id, users_message);

    log_message("Extracting IPs...");
    run_command("awk '/IPs/,/Emails/' theharvester.txt | sed -e '1,2d' | head -n -2 | anew -q ips.txt", "Extracting IPs", target_dir + "/ips.txt");
    std::string ips_message = format_result("IP's found", exec_command(("cat " + target_dir + "/ips.txt").c_str()));
    send_telegram_message(bot_token, chat_id, ips_message);

    log_message("Extracting Emails...");
    run_command("awk '/Emails/,/Hosts/' theharvester.txt | sed -e '1,2d' | head -n -2 | anew -q emails.txt", "Extracting Emails", target_dir + "/emails.txt");
    std::string emails_message = format_result("Emails found", exec_command(("cat " + target_dir + "/emails.txt").c_str()));
    send_telegram_message(bot_token, chat_id, emails_message);

    log_message("Extracting Hosts...");
    run_command("awk '/Hosts/,/Trello/' theharvester.txt | sed -e '1,2d' | head -n -2 | anew -q hosts.txt", "Extracting Hosts", target_dir + "/hosts.txt");
    std::string hosts_message = format_result("Hosts found", exec_command(("cat " + target_dir + "/hosts.txt").c_str()));
    send_telegram_message(bot_token, chat_id, hosts_message);




    // subfinder...
    log_message("Running Subfinder...");
    run_command("subfinder -d " + target, "Subfinder", target_dir + "/subfinder.txt");
    tool_message = format_result("🔑 Subfinder", exec_command(("cat " + target_dir + "/subfinder.txt").c_str()));
    send_telegram_message(bot_token, chat_id, tool_message);

    // assetfinder..
    log_message("Running Assetfinder...");
    run_command("assetfinder -subs-only " + target, "Assetfinder", target_dir + "/assetfinder.txt");
    tool_message = format_result("📦  Assetfinder", exec_command(("cat " + target_dir + "/assetfinder.txt").c_str()));
    send_telegram_message(bot_token, chat_id, tool_message);

    // sorting a subdomains...
    log_message("Sorting Subdomains...");
    run_command("cat " + target_dir + "/subfinder.txt " + target_dir + "/assetfinder.txt | sort | uniq > " + target_dir + "/sorted.txt", "Sorting Subdomains", target_dir + "/sorted.txt");
    tool_message = format_result("📊 Sorted Subdomains", exec_command(("cat " + target_dir + "/sorted.txt").c_str()));
    send_telegram_message(bot_token, chat_id, tool_message);

    log_message("All tool results sent to Telegram.");
    return 0;
}