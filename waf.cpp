#include <iostream>
#include <curl/curl.h>
#include <string>
#include <map>
#include <vector>
#include <algorithm>

size_t WriteCallback(void* contents, size_t size, size_t nmemb, std::string* userp) {
    userp->append(static_cast<char*>(contents), size * nmemb);
    return size * nmemb;
}

size_t HeaderCallback(char* header, size_t size, size_t nmemb, std::string* userp) {
    userp->append(header, size * nmemb);
    return size * nmemb;
}

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

std::string runWafw00f(const std::string& url) {
    std::string command = "wafw00f " + url + " 2>&1";
    char buffer[128];
    std::string result;

    FILE* pipe = popen(command.c_str(), "r");
    if (!pipe) {
        std::cerr << "Failed to run wafw00f command" << std::endl;
        return "";
    }

    while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
        result += buffer;
    }
    pclose(pipe);
    return result;
}

int main() {
    std::string url;
    std::string headers;

    std::cout << "Enter the URL or domain to test (e.g., http://example.com): ";
    std::getline(std::cin, url);

    sendRequest(url, headers); 
    std::string detectedWAF = isWAFDetected(headers);
    
   /// to display the waf
    if (detectedWAF != "None") {
        std::cout << "WAF is: " << detectedWAF << std::endl;
    } else {
        std::cout << "No WAF Detected. Running wafw00f for further checks...\n";
        std::string wafw00fResult = runWafw00f(url);
        std::cout << "wafw00f Result:\n" << wafw00fResult << std::endl;
    }

    return 0;
}
