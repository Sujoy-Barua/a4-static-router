#include "StaticRouter.h"

#include <cstdint>
#include <netinet/in.h>
#include <optional>
#include <spdlog/spdlog.h>
#include <cstring>
#include <sys/types.h>
#include <vector>

#include "IRoutingTable.h"
#include "RouterTypes.h"
#include "protocol.h"
#include "utils.h"

StaticRouter::StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                           std::shared_ptr<IPacketSender> packetSender)
    : routingTable(routingTable)
      , packetSender(packetSender)
      , arpCache(std::move(arpCache))
{}

mac_addr StaticRouter::toMacAddr(const unsigned char* macArray) {
    mac_addr mac;
    std::copy(macArray, macArray + 6, mac.begin());
    return mac;
}

void StaticRouter::forwardIPpacket(Packet packet, sr_ethernet_hdr_t& etherHeaderIn, sr_ip_hdr_t& ipHeader, std::string& iface, mac_addr& destMac) {
    sr_ethernet_hdr etherHeaderOut;
    etherHeaderOut.ether_type = htons(ethertype_ip);
    memcpy(etherHeaderOut.ether_dhost, destMac.data(), ETHER_ADDR_LEN);
    memcpy(etherHeaderOut.ether_shost, routingTable->getRoutingInterface(iface).mac.data(), ETHER_ADDR_LEN);

    // outgoing IP header
    sr_ip_hdr ipHeaderOut;
    memcpy(&ipHeaderOut, &ipHeader, sizeof(sr_ip_hdr));
    ipHeaderOut.ip_ttl = ipHeader.ip_ttl - 1;
    ipHeaderOut.ip_sum = 0;
    ipHeaderOut.ip_sum = htons(cksum(&ipHeaderOut, sizeof(sr_ip_hdr)));

    Packet outPacket;
    outPacket.resize(sizeof(sr_ethernet_hdr) + ntohs(ipHeader.ip_len));

    // Copy Ethernet, IP, and ICMP data into outPacket
    memcpy(outPacket.data(), &etherHeaderOut, sizeof(sr_ethernet_hdr));
    memcpy(outPacket.data() + sizeof(sr_ethernet_hdr), &ipHeaderOut, sizeof(sr_ip_hdr));
    memcpy(outPacket.data() + sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr), &ipHeaderOut, (ntohs(ipHeader.ip_len) - sizeof(sr_ip_hdr)));

    packetSender->sendPacket(outPacket, iface);
    
}

void StaticRouter::prepAndSendPacket(std::string& iface, sr_ip_hdr_t& ipHeader, sr_ethernet_hdr_t& etherHeaderIn, std::vector<uint8_t>& icmpPacketBuffer, bool srcIPoverride) {

    // outgoing IP header
    sr_ip_hdr ipHeaderOut;
    ipHeaderOut.ip_v = 4;
    ipHeaderOut.ip_hl = 5;
    ipHeaderOut.ip_tos = ipHeader.ip_tos;
    ipHeaderOut.ip_len = htons(sizeof(sr_ip_hdr_t) + icmpPacketBuffer.size());
    ipHeaderOut.ip_id = 0;
    ipHeaderOut.ip_off = 0;
    ipHeaderOut.ip_ttl = 64;
    ipHeaderOut.ip_p = 1;
    ipHeaderOut.ip_sum = 0;
    ipHeaderOut.ip_src = ipHeader.ip_dst; 
    ipHeaderOut.ip_dst = ipHeader.ip_src;

    if (srcIPoverride) {
        ipHeaderOut.ip_src = htonl(routingTable->getRoutingInterface(iface).ip);
    }

    // Compute the checksum for the outgoing IP header
    ipHeaderOut.ip_sum = htons(cksum(&ipHeaderOut, sizeof(sr_ip_hdr_t)));

    // Create the outgoing Ethernet header
    sr_ethernet_hdr etherHeaderOut;
    etherHeaderOut.ether_type = htons(ethertype_ip);
    memcpy(etherHeaderOut.ether_dhost, etherHeaderIn.ether_shost, ETHER_ADDR_LEN);
    memcpy(etherHeaderOut.ether_shost, etherHeaderIn.ether_dhost, ETHER_ADDR_LEN);

    Packet outPacket;
    outPacket.resize(sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr) + icmpPacketBuffer.size());

    // Copy Ethernet, IP, and ICMP data into outPacket
    memcpy(outPacket.data(), &etherHeaderOut, sizeof(sr_ethernet_hdr));
    memcpy(outPacket.data() + sizeof(sr_ethernet_hdr), &ipHeaderOut, sizeof(sr_ip_hdr));
    memcpy(outPacket.data() + sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr), icmpPacketBuffer.data(), icmpPacketBuffer.size());

    packetSender->sendPacket(outPacket, iface);
}

void StaticRouter::handleICMPechoPacket(Packet& packet, std::string& iface, sr_ethernet_hdr_t& etherHeaderIn, sr_ip_hdr_t& ipHeader) {

    auto* icmpHeader = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    if (ntohs(icmpHeader->icmp_type) != 8) {
        return;
    }

    // code to check icmp checksum
    uint16_t receivedICMPsum = icmpHeader->icmp_sum;
    icmpHeader->icmp_sum = 0;
    if (cksum(icmpHeader, (ntohs(ipHeader.ip_len) - sizeof(sr_ip_hdr_t))) != receivedICMPsum) {
        spdlog::error("Invalid ICMP checksum.");
        return;
    }
    icmpHeader->icmp_sum = receivedICMPsum; // Restore original value

    sr_icmp_hdr icmpHeaderOut;
    icmpHeaderOut.icmp_type = htons(0);
    icmpHeaderOut.icmp_code = htons(0);
    icmpHeaderOut.icmp_sum = htons(0);
    uint16_t icmp_data_size = ntohs(ipHeader.ip_len) - (sizeof(sr_icmp_hdr) + sizeof(sr_ip_hdr));
    // Create a buffer for the outgoing ICMP packet (header + payload)
    std::vector<uint8_t> icmpPacketBuffer(sizeof(sr_icmp_hdr_t) + icmp_data_size);

    // Copy ICMP header into the outgoing packet buffer
    memcpy(icmpPacketBuffer.data(), &icmpHeaderOut, sizeof(sr_icmp_hdr_t));

    // Copy the payload (data beyond the ICMP header) from the incoming packet
    uint8_t* icmpIncomingPayload = reinterpret_cast<uint8_t*>(icmpHeader) + sizeof(sr_icmp_hdr_t);
    memcpy(icmpPacketBuffer.data() + sizeof(sr_icmp_hdr_t), icmpIncomingPayload, icmp_data_size);

    // checksum for the outgoing ICMP message
    icmpHeaderOut.icmp_sum = htons(cksum(icmpPacketBuffer.data(), icmpPacketBuffer.size()));
    memcpy(icmpPacketBuffer.data(), &icmpHeaderOut, sizeof(sr_icmp_hdr_t)); // Update the checksum in the header

    prepAndSendPacket(iface, ipHeader, etherHeaderIn, icmpPacketBuffer, false);
}

void StaticRouter::handleICMPmsgPacket(Packet& packet, std::string& iface, sr_ethernet_hdr_t& etherHeaderIn, sr_ip_hdr_t& ipHeader, uint8_t type, uint8_t code) {

    sr_icmp_t3_hdr icmpHeaderOut;
    icmpHeaderOut.icmp_type = type;
    icmpHeaderOut.icmp_code = code;
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
    uint8_t* ipPayloadStart = packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    memcpy(icmpHeaderOut.data + sizeof(sr_ip_hdr), ipPayloadStart, 8); 
 

    // checksum for the outgoing ICMP message
    icmpHeaderOut.icmp_sum = htons(cksum(icmpPacketBuffer.data(), icmpPacketBuffer.size()));
    memcpy(icmpPacketBuffer.data(), &icmpHeaderOut, sizeof(sr_icmp_t3_hdr)); // Update the checksum in the header

    bool srcIPoverride = false;

    if (type == 3 && (code == 0 || code == 1)) {
        srcIPoverride = true;
    }

    prepAndSendPacket(iface, ipHeader, etherHeaderIn, icmpPacketBuffer, srcIPoverride);
}


void StaticRouter::handleARPpacket(Packet& packet, std::string& iface, sr_ethernet_hdr_t& inEthrHdr) {
    auto* arpHeader = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    // implement request and response function according to ar_op value
    if ((ntohs(arpHeader->ar_op) == arp_op_request) && (routingTable->getRoutingInterface(iface).ip == arpHeader->ar_tip)) {
        // code for arp request
        sr_arp_hdr arpReply;
        arpReply.ar_hrd = htons(arp_hrd_ethernet);
        arpReply.ar_pro = htons(ethertype_arp);
        arpReply.ar_hln = 6;
        arpReply.ar_pln = 4;
        arpReply.ar_op = htons(arp_op_reply);
        memcpy(arpReply.ar_sha, routingTable->getRoutingInterface(iface).mac.data(), sizeof(mac_addr));
        arpReply.ar_sip = arpHeader->ar_tip;
        memcpy(arpReply.ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
        arpReply.ar_tip = arpHeader->ar_sip;
        
        sr_ethernet_hdr outEtherHdr;
        outEtherHdr.ether_type = htons(ethertype_arp);
        memcpy(outEtherHdr.ether_dhost, inEthrHdr.ether_shost, ETHER_ADDR_LEN);
        memcpy(outEtherHdr.ether_shost, arpReply.ar_sha, ETHER_ADDR_LEN);
        
        Packet outPacket;
        uint8_t* etherHdrPtr = reinterpret_cast<uint8_t*>(&outEtherHdr);
        outPacket.insert(outPacket.end(), etherHdrPtr, etherHdrPtr + sizeof(sr_ethernet_hdr));

        uint8_t* arpHdrPtr = reinterpret_cast<uint8_t*>(&arpReply);
        outPacket.insert(outPacket.end(), arpHdrPtr, arpHdrPtr + sizeof(sr_arp_hdr));

        packetSender->sendPacket(outPacket, iface);

    } else if ((arpHeader->ar_op == arp_op_reply) && (routingTable->getRoutingInterface(iface).ip == arpHeader->ar_tip)) {
        // code for arp reply
        arpCache->addEntry(arpHeader->ar_sip, toMacAddr(arpHeader->ar_sha));
    }
}

void StaticRouter::handleIPpacket(Packet& packet, std::string& iface, sr_ethernet_hdr_t& etherHeaderIn) {
    auto* ipHeader = reinterpret_cast<sr_ip_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));

    // code to check ipHeader checksum
    uint16_t receivedIPsum = ipHeader->ip_sum;
    ipHeader->ip_sum = 0;
    if (cksum(ipHeader, sizeof(sr_ip_hdr)) != receivedIPsum) {
        spdlog::error("Invalid IP checksum.");
        return;
    }
    ipHeader->ip_sum = receivedIPsum; // Restore original value

    bool forMyself = false;

    // implement necessary functions to ultimately forward packet to destination
    std::unordered_map<std::string, RoutingInterface> interfaces = routingTable->getRoutingInterfaces();
    for (auto& [interfaceName, interface] : interfaces) {
        if (interface.ip == ipHeader->ip_dst) {
            forMyself = true;
            // check if ICMP, or TCP / UPD payload, // else, ignore packet
            if (ntohs(ipHeader->ip_p) == IPPROTO_ICMP) {
                handleICMPechoPacket(packet, iface, etherHeaderIn, *ipHeader);
            } else if ((ntohs(ipHeader->ip_p) == IPPROTO_TCP) || (ntohs(ipHeader->ip_p) == IPPROTO_UDP)) {
                handleICMPmsgPacket(packet, iface, etherHeaderIn, *ipHeader, 3, 3);
            } else {
                return;
            }

            break;
            
        }
    }

    if (forMyself == false) {

        if (ntohs(ipHeader->ip_ttl) > 1) {
            uint32_t destIp = ntohl(ipHeader->ip_dst);
            auto routingEntry = routingTable->getRoutingEntry(destIp);
            if (!routingEntry) { 
                handleICMPmsgPacket(packet, iface, etherHeaderIn, *ipHeader, 3, 0);
                return;
            }

            // check for Checksum validity
            ipHeader->ip_sum = 0;
            if (ipHeader->ip_sum != cksum(ipHeader, sizeof(sr_ip_hdr))) {
                spdlog::error("Invalid IP checksum.");
                return;
            }
            // decrement TTL by 1
            ipHeader->ip_ttl = htons(ntohs(ipHeader->ip_ttl) - 1);
            // recompute packet checksum for modified header
            ipHeader->ip_sum = htons(cksum(&ipHeader, sizeof(sr_ip_hdr)));
            // find longest matching prefix with packet's dst ip
            std::optional<mac_addr> destMac =arpCache->getEntry(routingEntry->dest);
            if (destMac) {
                forwardIPpacket(packet, etherHeaderIn, *ipHeader, iface, destMac.value());
            } else {
                arpCache->queuePacket(ipHeader->ip_dst, packet, iface);
            }
            // check ARP cache for the next-hop MAC:
                // if it's there, send it to the MAC,   
                // else send an ARP request for the next-hop IP 
                    // (if one hasn't been sent within the last second), 
                    // and add the packet to the queue of packets waiting on this ARP request

        } else if (ntohs(ipHeader->ip_ttl) == 1) {
            handleICMPmsgPacket(packet, iface, etherHeaderIn, *ipHeader, 11, 0);
            return;
        } else if (ntohs(ipHeader->ip_ttl) == 0) {
            return;
        }
    }
}

void StaticRouter::handlePacket(std::vector<uint8_t> packet, std::string iface)
{
    std::unique_lock lock(mutex);

    if (packet.size() < sizeof(sr_ethernet_hdr_t))
    {
        spdlog::error("Packet is too small to contain an Ethernet header.");
        return;
    }

    // TODO: Your code below
    auto* etherHeader = reinterpret_cast<sr_ethernet_hdr_t*>(packet.data());
    uint16_t etherType = ntohs(etherHeader->ether_type);
    if (etherType == ethertype_arp) {
        handleARPpacket(packet, iface, *etherHeader);
    } else if (etherType == ethertype_ip) {
        handleIPpacket(packet, iface, *etherHeader);
    } else {
        spdlog::warn("Unsupported EtherType: {:#06x}", etherType);
    }
}