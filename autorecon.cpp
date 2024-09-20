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
#include <random>

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

size_t HeaderCallback(char* header, size_t size, size_t nmemb, std::string* userp) {
    userp->append(header, size * nmemb);
    return size * nmemb;
}

std::string get_random_user_agent() {
    std::vector<std::string> user_agents = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0.1 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 10; SM-G975F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Mobile Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:92.0) Gecko/20100101 Firefox/92.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/93.0.4577.82 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:93.0) Gecko/20100101 Firefox/93.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:90.0) Gecko/20100101 Firefox/90.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 10; Mobile; rv:91.0) Gecko/91.0 Firefox/91.0",
    "Mozilla/5.0 (Android 11; Mobile; rv:93.0) Gecko/93.0 Firefox/93.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/94.0.992.31",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; AS; rv:11.0) like Gecko"
};
    static std::random_device rd; 
    static std::mt19937 eng(rd()); 
    std::uniform_int_distribution<> distr(0, user_agents.size() - 1);

    return user_agents[distr(eng)];
}

// send a request msg..
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
        
        // Set a random user agent for the request
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



bool toLowerCaseAndFind(const std::string& str, const std::string& pattern) {
    return std::search(str.begin(), str.end(), 
                       pattern.begin(), pattern.end(),
                       [](char a, char b) { return std::tolower(a) == std::tolower(b); }) != str.end();
}
 
// waf signature for waf detection..
std::string isWAFDetected(const std::string& headers) {
    const std::map<std::string, std::vector<std::string>> WAF_SIGNATURES = {
        {"Cloudflare", {"cf-ray", "cloudflare", "cf-request-id", "cf-cache-status"}},
        {"Akamai", {"akamai", "akamai-ghost", "akamai-x-cache", "x-akamai-request-id"}},
        {"Sucuri", {"x-sucuri-id", "sucuri", "x-sucuri-cache"}},
        {"ModSecurity", {"mod_security", "modsecurity", "x-modsecurity-id", "x-mod-sec-rule"}},
        {"Barracuda", {"barra", "x-barracuda", "bnmsg"}},
        {"Imperva", {"x-cdn", "imperva", "incapsula", "x-iinfo", "x-cdn-forward"}},
        {"F5 Big-IP ASM", {"x-waf-status", "f5", "x-waf-mode", "x-asm-ver"}},
        {"DenyAll", {"denyall", "sessioncookie"}},
        {"FortiWeb", {"fortiwafsid", "x-fw-debug"}},
        {"Jiasule", {"jsluid", "jiasule"}},
        {"AWS WAF", {"awswaf", "x-amzn-requestid", "x-amzn-trace-id"}},
        {"StackPath", {"stackpath", "x-sp-url", "x-sp-waf"}},
        {"BlazingFast", {"blazingfast", "x-bf-cache-status", "bf"}},
        {"NSFocus", {"nsfocus", "nswaf", "nsfocuswaf"}},
        {"Edgecast", {"ecdf", "x-ec-custom-error"}},
        {"Alibaba Cloud WAF", {"ali-cdn", "alibaba"}},
        {"AppTrana", {"apptrana", "x-wf-sid"}},
        {"Radware", {"x-rdwr", "rdwr"}},
        {"SafeDog", {"safedog", "x-sd-id"}},
        {"Comodo WAF", {"x-cwaf", "comodo"}},
        {"Yundun", {"yundun", "yunsuo"}},
        {"Qiniu", {"qiniu", "x-qiniu"}},
        {"NetScaler", {"netscaler", "x-nsprotect"}},
        {"Securi", {"x-sucuri-id", "sucuri", "x-sucuri-cache"}},
        {"Reblaze", {"x-reblaze-protection", "reblaze"}},
        {"Microsoft Azure WAF", {"azure", "x-mswaf", "x-azure-ref"}},
        {"NAXSI", {"x-naxsi-sig"}},
        {"Wallarm", {"x-wallarm-waf-check", "wallarm"}}
    };

    for (const auto& [waf, signatures] : WAF_SIGNATURES) {
        for (const auto& signature : signatures) {
            if (toLowerCaseAndFind(headers, signature)) {
                return waf;
            }
        }
    }
    return "None";
}

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


// create a dir for targets..
std::string create_target_directory(const std::string& target) {
    std::string base_dir = "target";
    mkdir(base_dir.c_str(), 0777);
    std::string target_dir = base_dir + "/" + target;
    mkdir(target_dir.c_str(), 0777);
    return target_dir;
}


// getting a target ip addr..
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

// sending a msg..
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

// run command fn for exec the shell commands..
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

// banner..
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

// main fn..
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
        std::string headers;
        sendRequest("http://" + target, headers);
        std::string waf_info = isWAFDetected(headers);
        print_banner(target, ip_address, waf_info);
    }

    // whois lookup..
    std::string whois_command = "whois " + target + " | grep -E 'Domain Name|Registry|Registrar|Updated|Creation|Registrant|Name Server|DNSSEC|Status' > " + target_dir + "/whois.txt";
    run_command(whois_command, "Whois Lookup", target, target_dir + "/whois.txt");
   
    // nslookup..
    std::string nslookup_command = "nslookup " + target + " > " + target_dir + "/nslookup.txt";
    run_command(nslookup_command, "NSLookup", target, target_dir + "/nslookup.txt");

    // reverse lookup.. 
    std::string reverselookup_command = 
    "whois " + target + " | grep \"Registrant Email\" | egrep -ho \"[[:graph:]]+@[[:graph:]]+\" | "
    "xargs -I {} curl -s -A \"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/45.0.2454.85 Safari/537.36\" "
    "\"https://viewdns.info/reversewhois/?q={}\" | "
    "sed 's/<[^>]*>//g' | "  
    "grep -Po \"[-a-zA-Z0-9@:%._\\+~#=]{1,256}\\.[a-zA-Z0-9()]{1,6}\\b([-a-zA-Z0-9()@:%_\\+.~#?&//=]*)\" | "
    "tail -n +4 | head -n -1 > " + target_dir + "/reverselookup.txt";

    run_command(reverselookup_command, "Reverse Lookup", target, target_dir + "/reverselookup.txt");

    // subfinder for subdomains..
    run_command("subfinder -d " + target, "Subfinder", target, target_dir + "/subfinder.txt");
    
    // assetfinder for subdomains..
    run_command("assetfinder -subs-only " + target, "Assetfinder", target,target_dir + "/assetfinder.txt" );

    // sorting subdomains..
    std::string sort_command = "cat " + target_dir + "/subfinder.txt " + target_dir + "/assetfinder.txt | sort >> " + target_dir + "/sorted.txt";
    run_command(sort_command, "Sorting Subdomains", target, target_dir + "/sorted.txt");
    
    return 0;
}
