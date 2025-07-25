/*
VERSION
1.2
# Fixed Mac address line
# Added Slot x Port x to NIC Name
1.3
# Find right number of CPU
1.4
# fixed disk sizes
1.41
# Added --o out_file to store output into a file
1.45
# BMC IP/ Credentials can be assigned form command line
1.46
Fixed output file bug, ipv6 ip bug and bmc bug
1.47
Excluded virtual interfaces

Copywright by Ogun Akgun, Windriver.
ogun.akgun@windriver.com
Compile  g++ -o system_info_collector system_info_collector.cpp
  ./system_info_collector \
  --hostname "server01" \
  --lab_location "YOW-Lab" \
  --dev_function "WRCP-Controller" \
  --description "YOW-WRCP-DC-001 SC1 Central Controller" \
  --tags "yow,ctrl-0" \
  --site "YOW 425 Legget" \
  --rack "YOW Storage A1-0" \
  --face "front" \
  --position "10" \
  --status "active" \
  --cluster "YOW-WRCP-DC-001 SC1" \
  --tenant "YOW-WRCP-DC-001" \
  --vendorOrderNumber "VO123456" \
  --PONumber "PO789012" \
  --warranty "2025-12-31"
  --o <output.txt>

*/
#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <cstdlib>
#include <cstring>
#include <unistd.h>
#include <iomanip>
#include <cmath>
#include <sys/utsname.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <iomanip>
#include <cmath>
const std::string VERSION = "V1.47";

class SystemInfoCollector {
private:
    std::map<std::string, std::string> cmdLineArgs;
    std::map<std::string, std::string> systemInfo;
    std::vector<std::string> diskInfo;
    std::vector<std::map<std::string, std::string>> interfaceInfo;
    std::string netboxUrl = "https://yow-netbox.wrs.com"; // Default URL
    std::string netboxToken;
    std::string outputFile;
    std::string bmcIpv4;
    std::string bmcIpv6;
    std::string bmcGatewayIpv4;
    std::string bmcGatewayIpv6;

public:
    // Constructor to initialize default values
    SystemInfoCollector() = default;

    std::string getNetboxUrl() const { return netboxUrl; }
    std::string getNetboxToken() const { return netboxToken; }

    void parseCmdLineArgs(int argc, char* argv[]) {
        for (int i = 1; i < argc; i += 2) {
            if (i + 1 < argc) {
                std::string key = argv[i];
                std::string value = argv[i + 1];

                // Remove leading dashes
                if (key.substr(0, 2) == "--") {
                    key = key.substr(2);
                } else if (key.substr(0, 1) == "-") {
                    key = key.substr(1);
                }

            if (key == "netboxUrl") {
                netboxUrl = value;
            } else if (key == "netboxToken") {
                netboxToken = value;
            } else if (key == "o") {
                outputFile = value;
            } else if (key == "bmcip") {
                configureBmcNetwork(value);
            } else {
                cmdLineArgs[key] = value;
            }
        }
    }
}

    std::string executeCommand(const std::string& command) {
        FILE* pipe = popen(command.c_str(), "r");
        if (!pipe) return "";

        char buffer[128];
        std::string result = "";
        while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
            result += buffer;
        }
        pclose(pipe);

        // Remove trailing newline
        if (!result.empty() && result.back() == '\n') {
            result.pop_back();
        }

        return result;
    }

    void collectSystemInfo() {
        // BIOS Version
        systemInfo["bios_version"] = executeCommand("sudo dmidecode -s bios-version 2>/dev/null || echo 'Unknown'");

        // Serial Number
        systemInfo["serial_number"] = executeCommand("sudo dmidecode -s system-serial-number 2>/dev/null || echo 'Unknown'");

        // System Manufacturer
        systemInfo["manufacturer"] = executeCommand("sudo dmidecode -s system-manufacturer 2>/dev/null || echo 'Unknown'");
        std::string manufacturer = systemInfo["manufacturer"];
        std::string manufacturerLower;
        for(char c : manufacturer) {
            manufacturerLower += std::tolower(c);
        }
        if(manufacturerLower.find("dell") != std::string::npos) {
            systemInfo["manufacturer"] = "Dell";
            systemInfo["bmc_type"]= "iDRAC8";
        } else if(manufacturerLower.find("hp") != std::string::npos) {
            systemInfo["manufacturer"] = "HPE";
            systemInfo["bmc_type"]= "iLO5";
        } else if(manufacturerLower.find("intel") != std::string::npos) {
            systemInfo["manufacturer"] = "Intel";
            systemInfo["bmc_type"]= "BMC";
        }




        // System Product Name
        systemInfo["product_name"] = executeCommand("sudo dmidecode -s system-product-name 2>/dev/null || echo 'Unknown'");

        // BMC Firmware Version (IPMI)
        systemInfo["bmc_firmware"] = executeCommand("sudo ipmitool mc info 2>/dev/null | grep 'Firmware Revision' | cut -d':' -f2 | tr -d ' ' || echo 'Unknown'");

        // BMC Type
        //systemInfo["bmc_type"] = executeCommand("sudo ipmitool mc info 2>/dev/null | grep 'Device ID' | cut -d':' -f2 | tr -d ' ' || echo 'IPMI'");

        // CPU Model
        systemInfo["cpu_model"] = executeCommand(
            "lscpu | grep '^Model name:' | cut -d':' -f2 | sed 's/^[ \\t]*//' || echo 'Unknown'");

        // Number of CPUs

        systemInfo["cpu_count"] = executeCommand(
            "grep '^physical id' /proc/cpuinfo | awk '{print $4}' | sort -un | tail -1 | awk '{print $1+1}' || echo '1'");

        // Number of cores
        systemInfo["cpu_cores"] = executeCommand("lscpu | grep 'Core(s) per socket' | cut -d':' -f2 | tr -d ' ' || echo '1'");

        // RAM amount
        std::string ramBytes = executeCommand("lsmem -b --summary=only | sed -ne '/online/s/.* //p' || echo 'Unknown'");
        if (ramBytes != "Unknown") {
            unsigned long long bytes = std::stoull(ramBytes);
            unsigned long long gb = bytes / (1024*1024*1024);
            std::stringstream ss;
            ss << gb << "GB";
            systemInfo["ram_amount"] = ss.str();
        } else {
            systemInfo["ram_amount"] = ramBytes;
        }

        // GPU Info
        //systemInfo["gpu_info"] = executeCommand("lspci | grep -i vga | head -1 | cut -d':' -f3 | sed 's/^[ \\t]*//' || echo 'Unknown'");
        systemInfo["gpu_info"] = "";
        // Collect disk information (up to 12 disks)
        collectDiskInfo();

        // Collect network interface information
        collectNetworkInterfaces();
    }

    void collectDiskInfo() {

        std::string diskCommand =
                "lsblk -d -o NAME,SIZE | grep -E 'nvme|sd' | grep -v 'sr[0-9]' | head -12";
        std::string diskOutput = executeCommand(diskCommand);

        std::istringstream iss(diskOutput);
        std::string line;
        int diskIndex = 0;

        while (std::getline(iss, line) && diskIndex < 12) {
            if (!line.empty()) {
                std::istringstream lineStream(line);
                std::string name, size;
                lineStream >> name >> size;

                if (name.find("sr") == 0) {
                    continue;
                }

                // Parse and format size
                double sizeValue = std::stod(size.substr(0, size.length() - 1));
                char unit = size.back();

                // Convert all sizes to GB first
                if (unit == 'T') {
                    sizeValue *= 1024;
                } else if (unit == 'M') {
                    sizeValue /= 1024;
                }
                sizeValue *= 1.074; // Adjust for actual size

                // Round to nearest 0.1
                sizeValue = std::round(sizeValue * 10) / 10;

                std::stringstream ss;
                if (sizeValue >= 1024) {
                    ss << std::fixed << std::setprecision(1) << (sizeValue / 1024) << "Tb";
                } else {
                    ss << static_cast<int>(std::round(sizeValue)) << "Gb";
                }
                diskInfo.push_back(ss.str());
            }
            diskIndex++;
        }

        // Fill remaining disk slots with empty values
        while (diskInfo.size() < 12) {
            diskInfo.push_back("");
        }
    }

            std::string getSlotNumber(const std::string& pci_bus_id) {

        if (pci_bus_id == "Unknown" || pci_bus_id.empty()) {
            return "";
        }

        std::string cmd = "sudo dmidecode -t slot | grep -B4 '" + pci_bus_id + "' | grep 'ID:' | cut -d':' -f2 | tr -d ' ' || echo ''";
        return executeCommand(cmd);
            }

            void collectNetworkInterfaces() {
        // Get network interface information

        std::string interfaceList = executeCommand("ip link show | grep -v 'cali\\|bond\\|docker\\|lo\\|@\\|vir\\|br\\|rt' | grep '^[0-9]' | cut -d':' -f2 | tr -d ' ' | sort");

        std::istringstream iss(interfaceList);
        std::string interfaceName;

        // First collect BMC interface info
        std::string bmcLanOutput = executeCommand("sudo ipmitool lan print 1 2>/dev/null");
        if (!bmcLanOutput.empty()) {
            std::map<std::string, std::string> bmcInfo;
            bmcInfo["name"] = "bmc";
            bmcInfo["label"] = systemInfo["bmc_type"];
            bmcInfo["type"] = "1000base-t";
            bmcInfo["description"] = "BMC Management Interface";
            bmcInfo["enabled"] = "true";
            bmcInfo["tags"] = "ipmi-network";
            bmcInfo["mode"] = "access";
            bmcInfo["firmware_version"] = systemInfo["bmc_firmware"];
            bmcInfo["pci_bus_id"] = "0000:00:00.0";

            // Extract MAC address from ipmitool output
            size_t macPos = bmcLanOutput.find("MAC Address");
            if (macPos != std::string::npos) {
                std::string macLine = bmcLanOutput.substr(macPos, bmcLanOutput.find('\n', macPos) - macPos);
                size_t colonPos = macLine.find(':');
                if (colonPos != std::string::npos) {
                    bmcInfo["mac_address"] = macLine.substr(colonPos + 1);
                } else {
                    bmcInfo["mac_address"] = "Unknown";
                }
            } else {
                bmcInfo["mac_address"] = "Unknown";
            }

            interfaceInfo.push_back(bmcInfo);
        }

        while (std::getline(iss, interfaceName)) {
            // Skip loopback and virtual interfaces


            if (interfaceName != "lo" &&
                interfaceName.substr(0, 4) != "bond" &&
                interfaceName.substr(0, 3) != "gpd" &&
                interfaceName.substr(0, 3) != "tun") {
                std::map<std::string, std::string> ifaceInfo;

                ifaceInfo["name"] = interfaceName;
                ifaceInfo["label"] = interfaceName;

                // Get interface supported link modes
                std::string modesCmd = "ethtool " + interfaceName + " 2>/dev/null | grep -A10 'Supported link modes:' || echo 'Unknown'";
                std::string modes = executeCommand(modesCmd);
                std::string mediaCmd = "ethtool " + interfaceName + " 2>/dev/null | grep -i 'Supported ports:' || echo 'Unknown'";
                std::string media = executeCommand(mediaCmd);

                if (modes.find("400000base") != std::string::npos) {
                    ifaceInfo["type"] = "400gbase-x-cfp2";
                } else if (modes.find("200000base") != std::string::npos) {
                    ifaceInfo["type"] = "200gbase-x-cfp2";
                } else if (modes.find("100000base") != std::string::npos) {
                    ifaceInfo["type"] = "100gbase-x-cfp";
                } else if (modes.find("25000base") != std::string::npos) {
                    ifaceInfo["type"] = "25gbase-x-sfp28";
                } else if (modes.find("10000base") != std::string::npos) {
                    if (media.find("FIBRE") != std::string::npos || media.find("TP") == std::string::npos) {
                        ifaceInfo["type"] = "10gbase-x-sfpp";
                    } else {
                        ifaceInfo["type"] = "10gbase-t";
                    }
                } else if (modes.find("1000base") != std::string::npos) {
                    ifaceInfo["type"] = "1000base-t";
                } else {
                    // Fallback to driver name if link mode detection fails
                    std::string typeCmd = "ethtool -i " + interfaceName + " 2>/dev/null | grep 'driver:' | cut -d':' -f2 | tr -d ' ' || echo 'Unknown'";
                    ifaceInfo["type"] = executeCommand(typeCmd);
                }

                // Get MAC address
                std::string macCmd = "cat /sys/class/net/" + interfaceName + "/address 2>/dev/null || echo 'Unknown'";
                ifaceInfo["mac_address"] = executeCommand(macCmd);

                // Get PCI Bus ID
                std::string pciCmd = "readlink /sys/class/net/" + interfaceName + "/device 2>/dev/null | rev | cut -d'/' -f1 | rev || echo 'Unknown'";
                ifaceInfo["pci_bus_id"] = executeCommand(pciCmd);

                // Create normalized PCI bus ID for slot lookup
                std::string normalizedPciBusId = ifaceInfo["pci_bus_id"];
                if (normalizedPciBusId != "Unknown" && normalizedPciBusId.length() >= 12) {
                    size_t lastDotPos = normalizedPciBusId.find_last_of('.');
                    if (lastDotPos != std::string::npos) {
                        normalizedPciBusId = normalizedPciBusId.substr(0, lastDotPos + 1) + "0";
                    }
                }

                // Get slot number and construct interface name
                std::string slotNum = getSlotNumber(normalizedPciBusId);

                if (!slotNum.empty()) {
                    // Extract port number from last digit of PCI bus id
                    size_t lastDotPos = ifaceInfo["pci_bus_id"].find_last_of('.');
                    std::string portNum = ifaceInfo["pci_bus_id"].substr(lastDotPos + 1);
                    int portNumInt = std::stoi(portNum) + 1;
                    ifaceInfo["name"] = "s" + slotNum + "p" + std::to_string(portNumInt);
                }

                // Check if PCI devices exist
                bool has_01_00 = !executeCommand("lspci -s 01:00.0 2>/dev/null").empty();
                bool has_04_00 = !executeCommand("lspci -s 04:00.0 2>/dev/null").empty();

                static std::map<std::string, int> pciToSlot;
                if (has_01_00) {
                    pciToSlot = {
                        {"0000:01:00.0", 1},
                        {"0000:04:00.0", 2},
                        {"0000:31:00.0", 3}
                    };
                } else if (has_04_00) {
                    pciToSlot = {
                        {"0000:04:00.0", 1},
                        {"0000:31:00.0", 2}
                    };
                } else {
                    pciToSlot = {
                        {"0000:31:00.0", 1}
                    };
                }

                if (pciToSlot.find(normalizedPciBusId) != pciToSlot.end()) {
                    size_t lastDotPos = ifaceInfo["pci_bus_id"].find_last_of('.');
                    std::string portNum = ifaceInfo["pci_bus_id"].substr(lastDotPos + 1);
                    int portNumInt = std::stoi(portNum) + 1;
                    ifaceInfo["name"] = "e" + std::to_string(pciToSlot[normalizedPciBusId]) + "p" + std::to_string(portNumInt);
                }


                // Get firmware version
                std::string fwCmd = "ethtool -i " + interfaceName + " 2>/dev/null | grep 'firmware-version:' | cut -d':' -f2 | tr -d ' ' || echo 'Unknown'";
                std::string fwVer = fwCmd.empty() ? "Unknown" : executeCommand(fwCmd);
                // Replace commas with spaces
                size_t pos;
                while ((pos = fwVer.find(',')) != std::string::npos) {
                    fwVer.replace(pos, 1, " ");
                }
                ifaceInfo["firmware_version"] = fwVer;

                // Check if interface is enabled
                std::string enabledCmd = "cat /sys/class/net/" + interfaceName + "/operstate 2>/dev/null || echo 'unknown'";
                std::string operState = executeCommand(enabledCmd);
                ifaceInfo["enabled"] = (operState == "up") ? "true" : "false";

                // Set default values

                // Get network card name from lspci
                std::string cardName;
                if (ifaceInfo["pci_bus_id"] != "Unknown") {
                    std::string lspciCmd = "lspci -s " + ifaceInfo["pci_bus_id"] + " | cut -d':' -f3- | sed 's/^[ \\t]*//' || echo 'Unknown'";
                    cardName = executeCommand(lspciCmd);
                    // Remove text in parentheses including parentheses
                    size_t start = cardName.find('(');
                    while (start != std::string::npos) {
                        size_t end = cardName.find(')', start);
                        if (end != std::string::npos) {
                            cardName.erase(start, end - start + 1);
                        }
                        start = cardName.find('(');
                    }
                } else {
                    cardName = "Generic";
                }

                // Extract slot and port numbers from interface name if available
                std::string description = cardName;
                if (!ifaceInfo["name"].empty()) {
                    if (ifaceInfo["name"][0] == 's') {
                        size_t pPos = ifaceInfo["name"].find('p');
                        if (pPos != std::string::npos) {
                            std::string slotNum = ifaceInfo["name"].substr(1, pPos - 1);
                            std::string portNum = ifaceInfo["name"].substr(pPos + 1);
                            description +="Slot " + slotNum + " Port " + portNum;
                        }
                    }
                    if (ifaceInfo["name"][0] == 'e') {
                        size_t pPos = ifaceInfo["name"].find('p');
                        if (pPos != std::string::npos) {
                            std::string slotNum = ifaceInfo["name"].substr(1, pPos - 1);
                            std::string portNum = ifaceInfo["name"].substr(pPos + 1);
                            description +=" Port " + portNum;
                        }
                    }
                }
                ifaceInfo["description"] = description;

                if (ifaceInfo["name"] == "bmc") {
                    ifaceInfo["tags"] = "ipmi-network";
                } else {
                    ifaceInfo["tags"] = "";
                }

                if (!ifaceInfo["name"].empty() && ifaceInfo["name"][0] == 's') {
                    ifaceInfo["mode"] = "tagged";
                } else {
                    ifaceInfo["mode"] = "access";
                }

                interfaceInfo.push_back(ifaceInfo);
            }
        }
    }

    bool checkDeviceExists(const std::string &serial) {
        std::string cmd = "curl -s -X GET " + netboxUrl + "/api/dcim/devices/?serial=" + serial +
                          " -H \"Authorization: Token " + netboxToken + "\"";
        std::string response = executeCommand(cmd);
        return response.find("\"count\":0") == std::string::npos;
    }

    std::string getDeviceName(const std::string &serial) {
        std::string cmd = "curl -s -X GET " + netboxUrl + "/api/dcim/devices/?serial=" + serial +
                          " -H \"Authorization: Token " + netboxToken +
                          "\" | grep -o '\"name\":\"[^\"]*\"' | cut -d'\"' -f4";
        return executeCommand(cmd);
    }

    void generateDeviceOutput() {
        std::ofstream outFile;
        if (!outputFile.empty()) {
            std::string currentPath = "./";
            std::string fullPath = currentPath + outputFile;
            outFile.open(fullPath, std::ios::trunc);
        }

        if (netboxToken.empty()) {
            std::cout << "Warning: NetBox token not provided. Proceeding with CSV output only." << std::endl;
            if (!outputFile.empty()) {
                outFile << "Warning: NetBox token not provided. Proceeding with CSV output only." << std::endl;
            }
        } else {
            bool deviceExists = checkDeviceExists(systemInfo["serial_number"]);

            if (deviceExists) {
                std::string existingDevice = getDeviceName(systemInfo["serial_number"]);
                std::cout << "Device with serial number " << systemInfo["serial_number"]
                        << " already exists as " << existingDevice << std::endl;
                std::cout << "Do you want to update this device? (y/n): ";
                std::string response;
                std::getline(std::cin, response);
                if (response != "y" && response != "Y") {
                    std::cout << "Device update cancelled." << std::endl;
                    return;
                }
            }
        }

        std::cout << "\nDevice Information Output:" << std::endl;
        std::cout << "\nDevices DEVICES >Devices" << std::endl;
        std::cout <<
                "name,location,role,description,tags,device_type,manufacturer,serial,asset_tag,site,rack,face,position,status,cluster,tenant,cf_BIOS_Version,cf_BMC_Firmware_Version,cf_BMC_Type,cf_processor_model,cf_processor_numbers,cf_processor_cores,cf_GPU,cf_Memory,cf_Disk_0,cf_Disk_1,cf_Disk_2,cf_Disk_3,cf_Disk_4,cf_Disk_5,cf_Disk_6,cf_Disk_7,cf_Disk_8,cf_Disk_9,cf_Disk_10,cf_Disk_11,cf_vendorOrderNumber,cf_PONumber,cf_warrantiedUntil"
                << std::endl;
        if (!outputFile.empty()) {
            outFile << "\nDevice Information Output:" << std::endl;
            outFile << "\nDevices DEVICES >Devices" << std::endl;
            outFile <<
                    "name,location,role,description,tags,device_type,manufacturer,serial,asset_tag,site,rack,face,position,status,cluster,tenant,cf_BIOS_Version,cf_BMC_Firmware_Version,cf_BMC_Type,cf_processor_model,cf_processor_numbers,cf_processor_cores,cf_GPU,cf_Memory,cf_Disk_0,cf_Disk_1,cf_Disk_2,cf_Disk_3,cf_Disk_4,cf_Disk_5,cf_Disk_6,cf_Disk_7,cf_Disk_8,cf_Disk_9,cf_Disk_10,cf_Disk_11,cf_vendorOrderNumber,cf_PONumber,cf_warrantiedUntil"
                    << std::endl;
        }

        // Output device information
        std::string deviceInfo = cmdLineArgs["hostname"] + "," +
                                 cmdLineArgs["lab_location"] + "," +
                                 cmdLineArgs["dev_function"] + "," +
                                 cmdLineArgs["description"] + "," +
                                 "\"" + cmdLineArgs["tags"] + "\"" + "," +
                                 systemInfo["product_name"] + "," +
                                 systemInfo["manufacturer"] + "," +
                                 systemInfo["serial_number"] + "," +
                                 "," + // asset_tag
                                 cmdLineArgs["site"] + "," +
                                 cmdLineArgs["rack"] + "," +
                                 cmdLineArgs["face"] + "," +
                                 cmdLineArgs["position"] + "," +
                                 cmdLineArgs["status"] + "," +
                                 cmdLineArgs["cluster"] + "," +
                                 cmdLineArgs["tenant"] + "," +
                                 systemInfo["bios_version"] + "," +
                                 systemInfo["bmc_firmware"] + "," +
                                 systemInfo["bmc_type"] + "," +
                                 systemInfo["cpu_model"] + "," +
                                 systemInfo["cpu_count"] + "," +
                                 systemInfo["cpu_cores"] + "," +
                                 systemInfo["gpu_info"] + "," +
                                 systemInfo["ram_amount"];

        std::cout << deviceInfo;
        if (!outputFile.empty()) {
            outFile << deviceInfo;
        }

        // Output disk information
        for (size_t i = 0; i < 12; i++) {
            std::cout << ",";
            if (!outputFile.empty()) {
                outFile << ",";}
            if (i < diskInfo.size()) {
                std::cout << diskInfo[i];
            if (!outputFile.empty()) {
                    outFile << diskInfo[i];
                }
            }
        }

        std::cout << "," << cmdLineArgs["vendorOrderNumber"]
                << "," << cmdLineArgs["PONumber"]
                << "," << cmdLineArgs["warranty"] << std::endl;
            if (!outputFile.empty()) {
                outFile << "," << cmdLineArgs["vendorOrderNumber"]
                << "," << cmdLineArgs["PONumber"]
                << "," << cmdLineArgs["warranty"] << std::endl;
            }
    }


    void configureBmcNetwork(const std::string &ipv4) {
        bmcIpv4 = ipv4;

        // Parse IPv4 address and calculate gateway
        size_t slashPos = ipv4.find('/');
        std::string ipAddr = ipv4.substr(0, slashPos);
        std::string subnet = ipv4.substr(slashPos + 1);

        // Calculate gateway as first address in subnet
        std::vector<std::string> octets;
        std::stringstream ss(ipAddr);
        std::string octet;
        while (std::getline(ss, octet, '.')) {
            octets.push_back(octet);
        }

        bmcGatewayIpv4 = octets[0] + "." + octets[1] + "." + octets[2] + ".1";

        // Generate IPv6 address
        int thirdOctet = std::stoi(octets[2]);
        int fourthOctet = std::stoi(octets[3]);
        std::stringstream ipv6ss;
        ipv6ss << "2620:10a:a001:aa"
                << std::hex << std::setw(2) << std::setfill('0') << thirdOctet
                << "::" << std::dec << fourthOctet;
        bmcIpv6 = ipv6ss.str();
        bmcGatewayIpv6 = "2620:10a:a001:aa00::1";

        // Configure BMC network
        std::string setIpv4Cmd = "ipmitool lan set 1 ipaddr " + ipAddr;
        std::string setNetmaskCmd = "ipmitool lan set 1 netmask 255.255.255.0";
        std::string setGatewayCmd = "ipmitool lan set 1 defgw ipaddr " + bmcGatewayIpv4;
        std::string setUserCmd = "ipmitool user set name 2 sysadmin";
        std::string setPassCmd = "ipmitool user set password 2 Li69nux*";
        std::string setIpv6Cmd = "ipmitool lan6 set 1 static_addr " + bmcIpv6;
        std::string setIpv6GwCmd = "ipmitool lan6 set 1 static_gw " + bmcGatewayIpv6;
/*
        executeCommand(setIpv4Cmd);
        executeCommand(setNetmaskCmd);
        executeCommand(setGatewayCmd);
        executeCommand(setUserCmd);
        executeCommand(setPassCmd);
        executeCommand(setIpv6Cmd);
        executeCommand(setIpv6GwCmd);
  */

    }

    void generateInterfaceOutput() {
        std::cout << "\nInterface Information Output:" << std::endl;
        std::ofstream outFile;
        if (!outputFile.empty()) {
            std::string currentPath = "./";
            std::string fullPath = currentPath + outputFile;
            outFile.open(fullPath, std::ios::app);
        }

        std::cout << "\nDEVICE COMPONENTS > Interfaces" << std::endl;
        if (!outputFile.empty()) {
            outFile << "\nDEVICE COMPONENTS > Interfaces" << std::endl;
        }
        std::cout << "device,name,label,type,description,enabled,tags,mode,cf_nic_firmware_version,cf_PCI_Bus_ID" <<
                std::endl;
        if (!outputFile.empty()) {
            outFile << "device,name,label,type,description,enabled,tags,mode,cf_nic_firmware_version,cf_PCI_Bus_ID" <<
                    std::endl;
        }

        for (const auto &iface: interfaceInfo) {
            std::string interfaceInfo = cmdLineArgs["hostname"] + "," +
                                        iface.at("name") + "," +
                                        iface.at("label") + "," +
                                        iface.at("type") + "," +
                                        iface.at("description") + "," +
                                        iface.at("enabled") + "," +
                                        iface.at("tags") + "," +
                                        iface.at("mode") + "," +
                                        iface.at("firmware_version") + "," +
                                        iface.at("pci_bus_id");

                                  std::cout << interfaceInfo << std::endl;
            if (!outputFile.empty()) {
                outFile << interfaceInfo << std::endl;
            }
            // << iface.at("mac_address") << std::endl;
        }
        std::cout << "\nADDRESSING > MAC Addresses" << std::endl;
        std::cout << "device,interface,mac_address,is_primary" << std::endl;
        if (!outputFile.empty()) {
            outFile << "\nADDRESSING > MAC Addresses" << std::endl;
            outFile << "device,interface,mac_address,is_primary" << std::endl;
        }
        for (const auto &iface: interfaceInfo) {
            std::string macInfo = cmdLineArgs["hostname"] + "," +
                                  iface.at("name") + "," +
                                  iface.at("mac_address") + "," +
                                  "true";

            std::cout << macInfo << std::endl;
            if (!outputFile.empty()) {
                outFile << macInfo << std::endl;
            }

        }
        if (!bmcIpv4.empty()) {
            std::cout << "\nADDRESSING > IP Addresses" << std::endl;
            std::cout << "address,status,dns_name,description,tags,tenant,device,interface,is_primary,is_oob" <<
                    std::endl;

            if (!outputFile.empty()) {
                outFile << "\nADDRESSING > IP Addresses" << std::endl;
                outFile << "address,status,dns_name,description,tags,tenant,device,interface,is_primary,is_oob" <<
                        std::endl;
            }

            // IPv4 address
            std::string ipv4Line = bmcIpv4 + ",active," +
                                   cmdLineArgs["hostname"] + "-bmc.wrs.com," +
                                   cmdLineArgs["hostname"] + " IPMI,ipmi-network," +
                                   cmdLineArgs["tenant"] + "," +
                                   cmdLineArgs["hostname"] + ",bmc,false,true";

            std::cout << ipv4Line << std::endl;
            if (!outputFile.empty()) {
                outFile << ipv4Line << std::endl;
            }

            // IPv6 address
            std::string ipv6Line = bmcIpv6 + "/64,active," +
                                   cmdLineArgs["hostname"] + "-bmc.yow.lab.wrs.com," +
                                   cmdLineArgs["hostname"] + " IPMI,ipmi-network," +
                                   cmdLineArgs["tenant"] + "," +
                                   cmdLineArgs["hostname"] + ",bmc,false,false";

            std::cout << ipv6Line << std::endl;
            if (!outputFile.empty()) {
                outFile << ipv6Line << std::endl;
            }
        }

    }

    void printUsage() {
        std::cout << "System Info Collector " << VERSION << std::endl;
        std::cout << "Copywright (c) Ogun Akgun, Windriver. " << std::endl;
        std::cout << "Usage: sudo ./system_info_collector [OPTIONS]" << std::endl;
        std::cout << "Options:" << std::endl;
        std::cout << "  --netboxUrl <url>                     NetBox URL (default: https://yow-netbox.wrs.com)" << std::endl;
        std::cout << "  --netboxToken <token>                 NetBox authentication token" << std::endl;
        std::cout << "  --hostname <hostname>                 System hostname eg: yow-r760-001" << std::endl;
        std::cout << "  --lab_location <location>             Lab location eg:YOW-Lab" << std::endl;
        std::cout << "  --dev_function <function>             Device function/role eg: WRCP-Controller, WRCP-Compute , or from https://yow-netbox.wrs.com/dcim/device-roles/ " << std::endl;
        std::cout << "  --description <description>           Device description eg: YOW-WRCP-DC-001 CENTRAL CTRL0" << std::endl;
        std::cout << "  --tags <tags>                         Device tags eg: aio-dx,controller-0,yow any combinations of slug in https://yow-netbox.wrs.com/extras/tags/"  << std::endl;
        std::cout << "  --site <site>                         Site information eg: YOW 425 Legget or any location in https://yow-netbox.wrs.com/dcim/sites/" << std::endl;
        std::cout << "  --rack <rack>                         Rack information eg: 425Legget-A7 or full list is in https://yow-netbox.wrs.com/dcim/racks/" << std::endl;
        std::cout << "  --face <face>                         Rack face eg:Front or Rear" << std::endl;
        std::cout << "  --position <position>                 Rack position eg: 10" << std::endl;
        std::cout << "  --status <status>                     Device status eg:active , Planned , Staged " << std::endl;
        std::cout << "  --cluster <cluster>                   Cluster information eg: YOW-WRCP-DC-001 CENTRAL"<< std::endl;
        std::cout << "  --tenant <tenant>                     Tenant information eg:YOW-WRCP-DC-001" << std::endl;
        std::cout << "  --vendorOrderNumber <order_number>    Vendor order number " << std::endl;
        std::cout << "  --PONumber <po_number>                Purchase order number " << std::endl;
        std::cout << "  --warranty <warranty_date>            Warranty expiration date eg:2025-11-22" << std::endl;
        std::cout << "  --bmcip <ipv4_address>                BMC IPv4 address in format 10.10.10.10/24" << std::endl;
        std::cout << "  --o <output_file>                     Write output to specified file" << std::endl;

        //std::cout << "   example usage" << std::endl;
        //std::cout << "  --hostname yow-r630-255 --lab_location YOW-Lab --dev_function WRCP-Compute --description ""YOW-WRCP-DC-032 SC3 COMP0"" --tags comp-15.comp-65 --site ""YOW 425 Legget"" --rack ""425 Legget-A14"" --face front --position 18 --status active --cluster ""YOW-WRCP-DC-032 SC3"" --tenant YOW-WRCP-DC-032 --vendorOrderNumber 9999999 --PONumber 1111111 --warranty 2025-10-25 --bmcip 10.64.10.4/1 --o yow-r630-255.txt" << std::endl;
        //std::cout << "  example usage" << std::endl;
        //std::cout << "  ./systemInfo --hostname yow-r630-255 --lab_location YOW-Lab --dev_function WRCP-Compute --description "YOW-WRCP-DC-032 SC3 COMP0" --tags comp-15.comp-65 --site "YOW 425 Legget" --rack "425 Legget-A14" --face front --position 18 --status active --cluster "YOW-WRCP-DC-032 SC3" --tenant YOW-WRCP-DC-032 --vendorOrderNumber 9999999 --PONumber 1111111 --warranty 2025-10-25 --bmcip 10.64.10.4/1 --o yow-r630-255.txt" << std::endl;

    }
};

int main(int argc, char* argv[]) {
    SystemInfoCollector collector;

    if (argc < 2) {
        collector.printUsage();
        return 1;
    }

    // Parse command line arguments
    collector.parseCmdLineArgs(argc, argv);

    // Collect system information
    std::cout << "Collecting system information..." << std::endl;
    collector.collectSystemInfo();

    // Generate outputs
    collector.generateDeviceOutput();
    collector.generateInterfaceOutput();

    return 0;
}//
// Created by root on 7/24/25.
//
