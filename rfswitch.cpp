/*
 * Copyright (c) 2025 Ogun Akgun, Wind River Systems, Inc.
 *
 * The right to copy, distribute, modify, or otherwise make use
 * of this software may be licensed only pursuant to the terms
 * of an applicable Wind River license agreement.
 * compile it g++ -o rfswitch rfswitch1.cpp -lssh
 */

#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <stdexcept>
#include <algorithm>
#include <fstream>
#include <sstream>
#include <libssh/libssh.h>

// Application configuration structure
struct Config {
    std::string host_ip;
    std::string hostname;
    std::string username;
    std::string password;
    std::map<int, int> gpio_map;
};

// Helper function to trim whitespace from a string
std::string trim(const std::string& s) {
    size_t first = s.find_first_not_of(" \t\n\r");
    if (std::string::npos == first) return "";
    size_t last = s.find_last_not_of(" \t\n\r");
    return s.substr(first, (last - first + 1));
}

/**
 * @brief Loads application settings from a configuration file.
 * @param filename The path to the configuration file.
 * @return A Config struct populated with settings.
 */
Config load_configuration(const std::string& filename) {
    std::ifstream file(filename);
    if (!file.is_open()) {
        throw std::runtime_error("Could not open configuration file: " + filename);
    }

    Config config;
    std::map<std::string, std::string> config_map;
    std::string line;

    while (std::getline(file, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            config_map[trim(key)] = trim(value);
        }
    }

    try {
        config.host_ip = config_map.at("HOST_IP");
        config.hostname = config_map.at("HOSTNAME");
        config.username = config_map.at("USERNAME");
        config.password = config_map.at("PASSWORD");

        // Parse the GPIO_MAP string
        std::string gpio_map_str = config_map.at("GPIO_MAP");
        std::stringstream ss(gpio_map_str);
        std::string segment;
        while(std::getline(ss, segment, ',')) {
            std::stringstream pair_ss(segment);
            std::string key_str, val_str;
            if(std::getline(pair_ss, key_str, ':') && std::getline(pair_ss, val_str)) {
                config.gpio_map[std::stoi(trim(key_str))] = std::stoi(trim(val_str));
            } else {
                 throw std::runtime_error("Invalid GPIO_MAP entry: " + segment);
            }
        }

    } catch (const std::out_of_range& e) {
        throw std::runtime_error(std::string("Missing required key in configuration file: ") + e.what());
    } catch (const std::invalid_argument& e) {
        throw std::runtime_error(std::string("Invalid number format in GPIO_MAP: ") + e.what());
    }

    return config;
}

/**
 * @brief Manages an SSH connection to execute commands efficiently.
 */
class SshController {
public:
    SshController(const Config& config)
        : config_(config), session_(nullptr) {}

    ~SshController() {
        disconnect();
    }

    void connect() {
        session_ = ssh_new();
        if (!session_) throw std::runtime_error("Failed to create SSH session.");

        ssh_options_set(session_, SSH_OPTIONS_HOST, config_.host_ip.c_str());
        ssh_options_set(session_, SSH_OPTIONS_USER, config_.username.c_str());

        if (ssh_connect(session_) != SSH_OK) {
            std::string error_msg = "Error connecting to host: " + std::string(ssh_get_error(session_));
            disconnect();
            throw std::runtime_error(error_msg);
        }

        if (ssh_userauth_password(session_, nullptr, config_.password.c_str()) != SSH_AUTH_SUCCESS) {
            disconnect();
            throw std::runtime_error("Authentication failed.");
        }
        std::cout << "Copyright (c) 2025 Ogun Akgun, Wind River Systems, Inc."<< std::endl;
        std::cout << "Successfully logged into " << config_.hostname << "." << std::endl;
    }

    std::string execute_command_with_output(const std::string& cmd) {
        if (!session_) throw std::runtime_error("Not connected.");

        ssh_channel channel = ssh_channel_new(session_);
        if (!channel) throw std::runtime_error("Failed to create SSH channel.");

        if (ssh_channel_open_session(channel) != SSH_OK) {
            ssh_channel_free(channel);
            throw std::runtime_error("Failed to open SSH session channel.");
        }

        if (ssh_channel_request_exec(channel, cmd.c_str()) != SSH_OK) {
            ssh_channel_close(channel);
            ssh_channel_free(channel);
            throw std::runtime_error("Failed to execute command.");
        }

        char buffer[256];
        std::string output;
        int nbytes;
        while ((nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0)) > 0) {
            output.append(buffer, nbytes);
        }

        ssh_channel_send_eof(channel);
        ssh_channel_close(channel);
        ssh_channel_free(channel);

        return trim(output);
    }

    void execute_command(const std::string& cmd) {
        // Execute and ignore the output.
        execute_command_with_output(cmd);
    }

private:
    Config config_;
    ssh_session session_;

    void disconnect() {
        if (session_) {
            ssh_disconnect(session_);
            ssh_free(session_);
            session_ = nullptr;
        }
    }
};

void usage(const std::string& script_name) {
    std::cout << "Copyright (c) 2025 Ogun Akgun, Wind River Systems, Inc."<< std::endl;
    std::cerr << script_name << " <switch_number> <command> [<args>]" << std::endl;
    std::cerr << "Commands:" << std::endl;
    std::cerr << "  on [off]     - Turn input 1 on and input 2 off (default)." << std::endl;
    std::cerr << "  off [on/off] - Turn input 1 off and optionally set input 2." << std::endl;
    std::cerr << "  query        - Check the current status of the port." << std::endl;
    std::cerr << "\n*** Note: both inputs CANNOT be on simultaneously. ***" << std::endl;
    exit(1);
}

int validate_and_get_gpio_value(std::string state, const std::string& state_name, const std::string& script_name) {
    std::transform(state.begin(), state.end(), state.begin(), ::tolower);
    if (state == "on") return 1;
    if (state == "off") return 0;

    std::cerr << "Error: Invalid state for " << state_name << ": '" << state << "'. Must be 'on' or 'off'." << std::endl;
    usage(script_name);
    return -1;
}

int main(int argc, char* argv[]) {
    std::string script_name = argv[0];

    if (argc < 3) {
        usage(script_name);
    }

    Config config;
    try {
        config = load_configuration("switch_control.conf");
    } catch (const std::runtime_error& e) {
        std::cerr << "Configuration Error: " << e.what() << std::endl;
        return 1;
    }

    int switch_num;
    try {
        switch_num = std::stoi(argv[1]);
    } catch (const std::exception& e) {
        std::cerr << "Error: Invalid switch number '" << argv[1] << "'." << std::endl;
        usage(script_name);
    }

    if (config.gpio_map.find(switch_num) == config.gpio_map.end()) {
        std::cerr << "Error: Invalid switch number '" << switch_num << "'. Not found in configuration." << std::endl;
        usage(script_name);
    }

    int target_gpio = config.gpio_map.at(switch_num);
    std::string action = argv[2];
    std::transform(action.begin(), action.end(), action.begin(), ::tolower);

    try {
        SshController ssh(config);
        ssh.connect();

        // Handle Port Query
        if (action == "query") {
            if (argc != 3) usage(script_name);

            std::string gpio_path = "/sys/class/gpio/gpio" + std::to_string(target_gpio);
            std::string check_cmd = "if [ -f " + gpio_path + "/value" + " ]; then cat " + gpio_path + "/value; else echo missing; fi";
            std::string result = ssh.execute_command_with_output(check_cmd);

            if (result == "1") {
                std::cout << "Port " << switch_num << " is currently on." << std::endl;
            } else if (result == "0") {
                std::cout << "Port " << switch_num << " is currently off." << std::endl;
            } else if (result.find("missing") != std::string::npos) {
                std::cout << "Port " << switch_num << " is not configured (GPIO not exported or readable)." << std::endl;
            } else {
                std::cerr << "Could not determine port status. Raw output: '" << result << "'" << std::endl;
            }
        // Handle Port Set (on/off)
        } else {
            if (argc > 4) usage(script_name);

            std::string input1_state = argv[2];
            std::string input2_state = (argc == 4) ? argv[3] : "off";

            int io1_value = validate_and_get_gpio_value(input1_state, "input 1", script_name);
            int io2_value = validate_and_get_gpio_value(input2_state, "input 2", script_name);

            if (io1_value == 1 && io2_value == 1) {
                std::cerr << "Error: Both inputs cannot be 'on' simultaneously." << std::endl;
                usage(script_name);
            }

            std::string gpio_dir_path = "/sys/class/gpio/gpio" + std::to_string(target_gpio);
            std::string command =
                "if [ ! -d " + gpio_dir_path + " ]; then "
                "echo " + std::to_string(target_gpio) + " > /sys/class/gpio/export; "
                "fi; "
                "echo out > " + gpio_dir_path + "/direction; "
                "echo " + std::to_string(io1_value) + " > " + gpio_dir_path + "/value";

            std::cout << "Configuring GPIO" << target_gpio << "..." << std::endl;
            ssh.execute_command(command);

            std::cout << "\nConfiguration complete. Port " << switch_num << " set to " << input1_state << "." << std::endl;
        }

    } catch (const std::runtime_error& e) {
        std::cerr << "An error occurred: " << e.what() << std::endl;
        return 1;
    }

    return 0;
}