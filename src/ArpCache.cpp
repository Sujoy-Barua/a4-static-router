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

Packet ArpCache::createARPReqPacket(uint32_t tip, std::string& ifaceOut) {
    mac_addr empty = {0x0, 0x0, 0x0, 0x0, 0x0, 0x0};
    mac_addr broadcast = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    RoutingInterface outgoingIface = routingTable->getRoutingInterface(ifaceOut);

    sr_arp_hdr arpReq;
    arpReq.ar_hrd = htons(arp_hrd_ethernet);
    arpReq.ar_pro = htons(ethertype_ip);
    arpReq.ar_hln = 6;
    arpReq.ar_pln = 4;
    arpReq.ar_op = htons(arp_op_request);
    memcpy(arpReq.ar_sha, outgoingIface.mac.data(), sizeof(mac_addr));
    arpReq.ar_sip = outgoingIface.ip;
    memcpy(arpReq.ar_tha, empty.data(), ETHER_ADDR_LEN);
    arpReq.ar_tip = tip;

    sr_ethernet_hdr etherHdr;
    memcpy(etherHdr.ether_dhost, broadcast.data(), ETHER_ADDR_LEN);
    memcpy(etherHdr.ether_shost, arpReq.ar_sha, 6);
    etherHdr.ether_type = htons(ethertype_arp);

    Packet packet;
    uint8_t* etherHdrPtr = reinterpret_cast<uint8_t*>(&etherHdr);
    packet.insert(packet.end(), etherHdrPtr, etherHdrPtr + sizeof(sr_ethernet_hdr));

    uint8_t* arpReqPtr = reinterpret_cast<uint8_t*>(&arpReq);
    packet.insert(packet.end(), arpReqPtr, arpReqPtr + sizeof(sr_arp_hdr));

    return packet;
}

void ArpCache::sendQueuedPackets(uint32_t ip, const mac_addr& destMac) {
    std::list<AwaitingPacket>& awaitingPacketsList = requests[ip].awaitingPackets;
    std::optional<RoutingEntry> rEntry = routingTable->getRoutingEntry(ip);

    if (!rEntry) {
        spdlog::error("No routing entry for IP: {}", ip);
        return;
    }

    std::string ifaceOut = rEntry->iface;

    for (auto& awaitingPacket : awaitingPacketsList) {
        uint8_t* ether_dhost_ptr = reinterpret_cast<uint8_t*>(awaitingPacket.packet.data());
        uint8_t* ether_shost_ptr = reinterpret_cast<uint8_t*>(awaitingPacket.packet.data() + ETHER_ADDR_LEN);
        auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(awaitingPacket.packet.data() + sizeof(sr_ethernet_hdr_t));

        ipHeader->ip_ttl -= 1;
        ipHeader->ip_sum = 0;
        // recompute ip checksum over modified header
        ipHeader->ip_sum = cksum(ipHeader, sizeof(sr_ip_hdr));

        memcpy(ether_dhost_ptr, destMac.data(), ETHER_ADDR_LEN);
        memcpy(ether_shost_ptr, routingTable->getRoutingInterface(ifaceOut).mac.data(), ETHER_ADDR_LEN);
        packetSender->sendPacket(awaitingPacket.packet, ifaceOut);
    }
}

void ArpCache::sendICMP31(ArpRequest arpReq) {

    for (auto it = arpReq.awaitingPackets.begin(); it != arpReq.awaitingPackets.end(); ++it) {

        auto& awaitingPacket = it->packet;
        auto& ifaceIn = it->iface;

        auto* etherHeaderIn = reinterpret_cast<sr_ethernet_hdr_t*>(awaitingPacket.data());
        auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(awaitingPacket.data() + sizeof(sr_ethernet_hdr));

        sr_icmp_t3_hdr icmpHeaderOut;
        icmpHeaderOut.icmp_type = 3;
        icmpHeaderOut.icmp_code = 1;
        icmpHeaderOut.icmp_sum = htons(0);
        icmpHeaderOut.unused = htons(0);
        icmpHeaderOut.next_mtu = htons(1500);

        // Copy full ip header, then 8 bytes of ip payload, from the incoming packet for ICMP data
        uint8_t* ipPayloadStart = awaitingPacket.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
        memcpy(icmpHeaderOut.data, ipHeader, sizeof(sr_ip_hdr_t));
        memcpy(icmpHeaderOut.data + sizeof(sr_ip_hdr_t), ipPayloadStart, 8);

        // checksum for the outgoing ICMP message
        icmpHeaderOut.icmp_sum = cksum(&icmpHeaderOut, sizeof(sr_icmp_t3_hdr));

        bool srcIPoverride = true;

        // outgoing IP header
        sr_ip_hdr ipHeaderOut;
        ipHeaderOut.ip_v = 4;
        ipHeaderOut.ip_hl = 5;
        ipHeaderOut.ip_tos = ipHeader->ip_tos;
        ipHeaderOut.ip_len = htons(sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr));
        ipHeaderOut.ip_id = 0;
        ipHeaderOut.ip_off = 0;
        ipHeaderOut.ip_ttl = 64;
        ipHeaderOut.ip_p = 1;
        ipHeaderOut.ip_sum = 0;
        ipHeaderOut.ip_src = ipHeader->ip_dst; 
        ipHeaderOut.ip_dst = ipHeader->ip_src;

        if (srcIPoverride) {
            ipHeaderOut.ip_src = routingTable->getRoutingInterface(ifaceIn).ip;
        }

        // Compute the checksum for the outgoing IP header
        ipHeaderOut.ip_sum = cksum(&ipHeaderOut, sizeof(sr_ip_hdr_t));

        // Create the outgoing Ethernet header
        sr_ethernet_hdr_t etherHeaderOut;
        etherHeaderOut.ether_type = htons(ethertype_ip);
        memcpy(etherHeaderOut.ether_dhost, etherHeaderIn->ether_shost, ETHER_ADDR_LEN);
        memcpy(etherHeaderOut.ether_shost, routingTable->getRoutingInterface(ifaceIn).mac.data(), ETHER_ADDR_LEN);

        Packet outPacket;
        outPacket.resize(sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr) + sizeof(sr_icmp_t3_hdr));

        // Copy Ethernet, IP, and ICMP data into outPacket
        memcpy(outPacket.data(), &etherHeaderOut, sizeof(sr_ethernet_hdr));
        memcpy(outPacket.data() + sizeof(sr_ethernet_hdr), &ipHeaderOut, sizeof(sr_ip_hdr));
        memcpy(outPacket.data() + sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr), &icmpHeaderOut, sizeof(sr_icmp_t3_hdr));

        packetSender->sendPacket(outPacket, ifaceIn);
    }
}

void ArpCache::tick() { // ip forwarding mechanism adds to the "requests" variable, arp reply 
                        // handler section adds to the "entries" variable | both are in StaticRouter.cpp
    std::unique_lock lock(mutex);
    // TODO: Your code here
    for (auto it = requests.begin(); it != requests.end(); ) {
        auto& request = it->second;
        if (((std::chrono::steady_clock::now() - request.lastSent) >= std::chrono::seconds(1)) &&
        (request.timesSent < 7) && (!entries.contains(request.ip))) {
            spdlog::info("Retrying ARP request for IP={}", inet_ntoa({request.ip}));
            std::string ifaceOut = (routingTable->getRoutingEntry(request.ip))->iface;
            Packet arpReqPacket = createARPReqPacket(request.ip, ifaceOut);
            packetSender->sendPacket(arpReqPacket, ifaceOut);
            request.lastSent = std::chrono::steady_clock::now();
            request.timesSent++;
            ++it;
        } else if ((request.timesSent == 7) && (!entries.contains(request.ip))) {
            sendICMP31(request);
            it = requests.erase(it);
        } else {
            ++it;
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
    if (requests.contains(ip)) {
        if (requests[ip].timesSent > 0) {
            ArpEntry newEntry = {ip, mac, std::chrono::steady_clock::now()};
            entries[ip] = newEntry;
            sendQueuedPackets(ip, mac);
            requests.erase(ip);
        } else {
            return;
        }
    } else {
        return;
    }
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
    if (!requests.contains(ip)) {
        ArpRequest newRequest = {ip, std::chrono::steady_clock::now(), 1};
        requests[ip] = newRequest;
        requests[ip].awaitingPackets.push_back(newPacket);
        std::string ifaceOut = (routingTable->getRoutingEntry(ip))->iface;
        Packet arpReqPacket = createARPReqPacket(ip, ifaceOut);
        packetSender->sendPacket(arpReqPacket, ifaceOut);
    } else {
        auto& request = requests[ip];
        request.awaitingPackets.push_back(newPacket);
        if (((std::chrono::steady_clock::now() - request.lastSent) >= std::chrono::seconds(1)) &&
        (request.timesSent < 7) && (!entries.contains(request.ip))) {
            spdlog::info("Retrying ARP request for IP={}", inet_ntoa({request.ip}));
            std::string ifaceOut = (routingTable->getRoutingEntry(request.ip))->iface;
            Packet arpReqPacket = createARPReqPacket(request.ip, ifaceOut);
            packetSender->sendPacket(arpReqPacket, ifaceOut);
            request.lastSent = std::chrono::steady_clock::now();
            request.timesSent++;
        }
    }
}