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
    arpHdr.ar_pro = htons(ethertype_arp);
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

void ArpCache::sendQueuedPackets(uint32_t ip) {
    std::list<AwaitingPacket>& awaitingPacketsList = requests[ip].awaitingPackets;
    std::optional<RoutingEntry> rEntry = routingTable->getRoutingEntry(ip);
    std::string ifaceOut = rEntry->iface;

    if (!rEntry) {
        for (auto& awaitingPacket : awaitingPacketsList) {
            packetSender->sendPacket(awaitingPacket.packet, ifaceOut);
        }
    }
}

void ArpCache::sendICMP31(ArpRequest arpReq) {

    for (auto& [awaitingPacket, iface] : arpReq.awaitingPackets) {

        auto* etherHeaderIn = reinterpret_cast<sr_ethernet_hdr_t*>(awaitingPacket.data());
        auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(awaitingPacket.data() + sizeof(sr_ethernet_hdr));

        sr_icmp_t3_hdr icmpHeaderOut;
        icmpHeaderOut.icmp_type = 3;
        icmpHeaderOut.icmp_code = 1;
        icmpHeaderOut.icmp_sum = htons(0);
        icmpHeaderOut.unused = htons(0);
        icmpHeaderOut.next_mtu = htons(0);
        // uint16_t icmp_data_size = sizeof(sr_ip_hdr) + ;
        // Create a buffer for the outgoing ICMP packet (header + payload)
        std::vector<uint8_t> icmpPacketBuffer(sizeof(sr_icmp_t3_hdr));

        // Copy ICMP header into the outgoing packet buffer
        memcpy(icmpPacketBuffer.data(), &icmpHeaderOut, sizeof(sr_icmp_t3_hdr));

        // Copy full ip header, then 8 bytes of ip payload, from the incoming packet for ICMP data
        memcpy(icmpHeaderOut.data, &ipHeader, sizeof(sr_ip_hdr_t));
        uint8_t* ipPayloadStart = awaitingPacket.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
        memcpy(icmpHeaderOut.data + sizeof(sr_ip_hdr), ipPayloadStart, 8); 
    

        // checksum for the outgoing ICMP message
        icmpHeaderOut.icmp_sum = htons(cksum(icmpPacketBuffer.data(), icmpPacketBuffer.size()));
        memcpy(icmpPacketBuffer.data(), &icmpHeaderOut, sizeof(sr_icmp_t3_hdr)); // Update the checksum in the header

        bool srcIPoverride = true;

        // outgoing IP header
        sr_ip_hdr ipHeaderOut;
        ipHeaderOut.ip_v = 4;
        ipHeaderOut.ip_hl = 5;
        ipHeaderOut.ip_tos = ipHeader->ip_tos;
        ipHeaderOut.ip_len = htons(sizeof(sr_ip_hdr_t) + icmpPacketBuffer.size());
        ipHeaderOut.ip_id = 0;
        ipHeaderOut.ip_off = 0;
        ipHeaderOut.ip_ttl = 64;
        ipHeaderOut.ip_p = 1;
        ipHeaderOut.ip_sum = 0;
        ipHeaderOut.ip_src = ipHeader->ip_dst; 
        ipHeaderOut.ip_dst = ipHeader->ip_src;

        if (srcIPoverride) {
            ipHeaderOut.ip_src = htonl(routingTable->getRoutingInterface(iface).ip);
        }

        // Compute the checksum for the outgoing IP header
        ipHeaderOut.ip_sum = htons(cksum(&ipHeaderOut, sizeof(sr_ip_hdr_t)));

        // Create the outgoing Ethernet header
        sr_ethernet_hdr_t etherHeaderOut;
        etherHeaderOut.ether_type = htons(ethertype_ip);
        memcpy(etherHeaderOut.ether_dhost, etherHeaderIn->ether_shost, ETHER_ADDR_LEN);
        memcpy(etherHeaderOut.ether_shost, etherHeaderIn->ether_dhost, ETHER_ADDR_LEN);

        Packet outPacket;
        outPacket.resize(sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr) + icmpPacketBuffer.size());

        // Copy Ethernet, IP, and ICMP data into outPacket
        memcpy(outPacket.data(), &etherHeaderOut, sizeof(sr_ethernet_hdr));
        memcpy(outPacket.data() + sizeof(sr_ethernet_hdr), &ipHeaderOut, sizeof(sr_ip_hdr));
        memcpy(outPacket.data() + sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr), icmpPacketBuffer.data(), icmpPacketBuffer.size());

        packetSender->sendPacket(outPacket, iface);
    }
}

void ArpCache::tick() { // ip forwarding mechanism adds to the "requests" variable, arp reply 
                        // handler section adds to the "entries" variable | both are in StaticRouter.cpp
    std::unique_lock lock(mutex);
    // TODO: Your code here
    for (auto& [ip, request] : requests) {
        if (((std::chrono::steady_clock::now() - request.lastSent) >= std::chrono::seconds(1)) &&
        (request.timesSent < 7) && (!entries.contains(request.ip))) {
            spdlog::info("Retrying ARP request for IP={}", inet_ntoa({ip}));
            std::optional<RoutingEntry> rEntry = routingTable->getRoutingEntry(request.ip);
            Packet arpReqPacket = createARPReqPacket(ip, rEntry->iface);
            packetSender->sendPacket(arpReqPacket, rEntry->iface);
            request.lastSent = std::chrono::steady_clock::now();
            request.timesSent++;
        } else if (request.timesSent == 7 && !entries.contains(request.ip)) {
            sendICMP31(request);
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
    sendQueuedPackets(ip);
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