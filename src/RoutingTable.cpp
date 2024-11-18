#include "RoutingTable.h"
#include "IRoutingTable.h"

#include <arpa/inet.h>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <spdlog/spdlog.h>

RoutingTable::RoutingTable(const std::filesystem::path& routingTablePath) {
    if (!std::filesystem::exists(routingTablePath)) {
        throw std::runtime_error("Routing table file does not exist");
    }

    std::ifstream file(routingTablePath);
    if (!file.is_open()) {
        throw std::runtime_error("Failed to open routing table file");
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) {
            continue;
        }

        std::istringstream iss(line);
        std::string dest, gateway, mask, iface;
        iss >> dest >> gateway >> mask >> iface;

        uint32_t dest_ip, gateway_ip, subnet_mask;

        if (inet_pton(AF_INET, dest.c_str(), &dest_ip) != 1 ||
            inet_pton(AF_INET, gateway.c_str(), &gateway_ip) != 1 ||
            inet_pton(AF_INET, mask.c_str(), &subnet_mask) != 1) {
            spdlog::error("Invalid IP address format in routing table file: {}", line);
            throw std::runtime_error("Invalid IP address format in routing table file");
            }

        routingEntries.push_back({dest_ip, gateway_ip, subnet_mask, iface});
    }
}

std::optional<RoutingEntry> RoutingTable::getRoutingEntry(ip_addr ip) {
    // TODO: Your code below
    RoutingEntry* bestMatch = nullptr;
    int longestMatch = -1;
    for (auto& entry : routingEntries) {
        uint32_t maskedIP = ip & entry.mask;
        uint32_t maskedDest = entry.dest & entry.mask;

        if (maskedIP == maskedDest) {
            int matchLength = __builtin_popcount(entry.mask);

            if (matchLength > longestMatch) {
                longestMatch = matchLength;
                bestMatch = &entry;
            }
        }
    }

    if (bestMatch) {
        return *bestMatch;
    } else {
        return std::nullopt;
    }
}

RoutingInterface RoutingTable::getRoutingInterface(const std::string& iface) {
    return routingInterfaces.at(iface);
}

void RoutingTable::setRoutingInterface(const std::string& iface, const mac_addr& mac, const ip_addr& ip) {
    routingInterfaces[iface] = {iface, mac, ip};
}

const std::unordered_map<std::string, RoutingInterface>& RoutingTable::getRoutingInterfaces() const
{
    return routingInterfaces;
}
