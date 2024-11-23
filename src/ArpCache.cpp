#include "ArpCache.h"

#include <chrono>
#include <cstdint>
#include <thread>
#include <cstring>
#include <spdlog/spdlog.h>

#include "IArpCache.h"
#include "IRoutingTable.h"
#include "RouterTypes.h"
#include "protocol.h"
#include "utils.h"

ArpCache::ArpCache(std::chrono::milliseconds timeout, std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable)
: timeout(timeout)
, packetSender(std::move(packetSender))
, routingTable(std::move(routingTable)) {
    thread = std::make_unique<std::thread>(&ArpCache::loop, this);
}

ArpCache::~ArpCache() {
    shutdown = true;
    if (thread && thread->joinable()) {
        thread->join();
    }
}

void ArpCache::loop() {
    while (!shutdown) {
        tick();
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

Packet ArpCache::createARPReqPacket(uint32_t tip, std::string& iface) {
    mac_addr broadcast = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    RoutingInterface sourceIface = routingTable->getRoutingInterface(iface);

    sr_arp_hdr arpHdr;
    arpHdr.ar_hrd = htons(arp_hrd_ethernet);
    arpHdr.ar_pro = htons(ethertype_ip);
    arpHdr.ar_hln = 6;
    arpHdr.ar_pln = 4;
    arpHdr.ar_op = htons(arp_op_request);
    memcpy(arpHdr.ar_sha, sourceIface.mac.data(), sizeof(mac_addr));
    arpHdr.ar_sip = htonl(sourceIface.ip);
    memcpy(arpHdr.ar_tha, broadcast.data(), ETHER_ADDR_LEN);
    arpHdr.ar_tip = htonl(tip);

    sr_ethernet_hdr etherHdr;
    memcpy(etherHdr.ether_dhost, broadcast.data(), ETHER_ADDR_LEN);
    memcpy(etherHdr.ether_shost, arpHdr.ar_sha, 6);
    etherHdr.ether_type = htons(ethertype_arp);

    Packet packet;
    uint8_t* etherHdrPtr = reinterpret_cast<uint8_t*>(&etherHdr);
    packet.insert(packet.end(), etherHdrPtr, etherHdrPtr + sizeof(sr_ethernet_hdr));

    uint8_t* arpHdrPtr = reinterpret_cast<uint8_t*>(&arpHdr);
    packet.insert(packet.end(), arpHdrPtr, arpHdrPtr + sizeof(sr_arp_hdr));

    return packet;
}

void ArpCache::tick() {
    std::unique_lock lock(mutex);
    // TODO: Your code here
    for (auto& [ip, request] : requests) {
        if (std::chrono::steady_clock::now() - request.lastSent >= std::chrono::seconds(1) &&
        request.timesSent < 7 && !entries.contains(request.ip)) {
            spdlog::info("Retrying ARP request for IP={}", inet_ntoa({ip}));
            std::optional<RoutingEntry> rEntry = routingTable->getRoutingEntry(request.ip);
            Packet arpReqPacket = createARPReqPacket(request.ip, rEntry->iface);
            packetSender->sendPacket(arpReqPacket, rEntry->iface);
        }
    }

    // TODO: Your code should end here

    // Remove entries that have been in the cache for too long
    std::erase_if(entries, [this](const auto& entry) {
        return std::chrono::steady_clock::now() - entry.second.timeAdded >= timeout;
    });
}

void ArpCache::addEntry(uint32_t ip, const mac_addr& mac) {
    std::unique_lock lock(mutex);

    // TODO: Your code below
    ArpEntry newEntry = {ip, mac, std::chrono::steady_clock::now()};
    entries[ip] = newEntry;

}

std::optional<mac_addr> ArpCache::getEntry(uint32_t ip) {
    std::unique_lock lock(mutex);

    // TODO: Your code below
    if (entries.contains(ip)) {
        return entries[ip].mac;
    }
    return std::nullopt; // Placeholder
}

void ArpCache::queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) {
    std::unique_lock lock(mutex);

    // TODO: Your code below
    AwaitingPacket newPacket = {packet, iface};
    requests[ip].awaitingPackets.push_back(newPacket);

}