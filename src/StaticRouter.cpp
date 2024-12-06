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

void StaticRouter::forwardOrQueueIPpacket(Packet packet, sr_ethernet_hdr_t& etherHeaderIn, sr_ip_hdr_t& ipHeader, std::string& ifaceIn) {

    auto dstRoutingEntry = routingTable->getRoutingEntry(ipHeader.ip_dst);
    if (!dstRoutingEntry) { 
        handleICMPmsgPacket(packet, ifaceIn, etherHeaderIn, ipHeader, 3, 0);
        return;
    }

    std::optional<mac_addr> destMac = arpCache->getEntry(dstRoutingEntry->dest);
    std::string& ifaceOut = dstRoutingEntry->iface;

    sr_ethernet_hdr etherHeaderOut;
    etherHeaderOut.ether_type = htons(ethertype_ip);
    if (destMac) {
        memcpy(etherHeaderOut.ether_dhost, destMac.value().data(), ETHER_ADDR_LEN);
        memcpy(etherHeaderOut.ether_shost, routingTable->getRoutingInterface(ifaceOut).mac.data(), ETHER_ADDR_LEN);
    } else {
        memcpy(etherHeaderOut.ether_dhost, etherHeaderIn.ether_dhost, ETHER_ADDR_LEN);
        memcpy(etherHeaderOut.ether_shost, etherHeaderIn.ether_shost, ETHER_ADDR_LEN);
    }
 
    // outgoing IP header
    sr_ip_hdr ipHeaderOut;
    memcpy(&ipHeaderOut, &ipHeader, sizeof(sr_ip_hdr));
    // decrement ttl by 1
    if (destMac) {
        ipHeaderOut.ip_ttl = ipHeader.ip_ttl - 1;
        ipHeaderOut.ip_sum = 0;
        // recompute ip checksum over modified header
        ipHeaderOut.ip_sum = cksum(&ipHeaderOut, sizeof(sr_ip_hdr));
    }


    Packet outPacket;
    outPacket.resize(sizeof(sr_ethernet_hdr) + ntohs(ipHeader.ip_len));

    // Copy Ethernet, IP, and ICMP data into outPacket
    memcpy(outPacket.data(), &etherHeaderOut, sizeof(sr_ethernet_hdr));
    memcpy(outPacket.data() + sizeof(sr_ethernet_hdr), &ipHeaderOut, sizeof(sr_ip_hdr));
    memcpy(outPacket.data() + sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr), packet.data()
                 + sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr), (ntohs(ipHeader.ip_len) - sizeof(sr_ip_hdr)));

    if (destMac) {
        packetSender->sendPacket(outPacket, ifaceOut);
    } else {
        arpCache->queuePacket(ipHeader.ip_dst, outPacket, ifaceIn);
    }
    
}

void StaticRouter::prepAndSendPacket(std::string& ifaceIn, sr_ip_hdr_t& ipHeader, sr_ethernet_hdr_t& etherHeaderIn, 
                                        std::vector<uint8_t>& icmpPacketBuffer, bool srcIPoverride) {

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
        ipHeaderOut.ip_src = routingTable->getRoutingInterface(ifaceIn).ip;
    }

    // Compute the checksum for the outgoing IP header
    ipHeaderOut.ip_sum = cksum(&ipHeaderOut, sizeof(sr_ip_hdr_t));

    // Create the outgoing Ethernet header
    sr_ethernet_hdr etherHeaderOut;
    etherHeaderOut.ether_type = htons(ethertype_ip);
    memcpy(etherHeaderOut.ether_dhost, etherHeaderIn.ether_shost, ETHER_ADDR_LEN);
    memcpy(etherHeaderOut.ether_shost, routingTable->getRoutingInterface(ifaceIn).mac.data(), ETHER_ADDR_LEN);

    Packet outPacket;
    outPacket.resize(sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr) + icmpPacketBuffer.size());

    // Copy Ethernet, IP, and ICMP data into outPacket
    memcpy(outPacket.data(), &etherHeaderOut, sizeof(sr_ethernet_hdr));
    memcpy(outPacket.data() + sizeof(sr_ethernet_hdr), &ipHeaderOut, sizeof(sr_ip_hdr));
    memcpy(outPacket.data() + sizeof(sr_ethernet_hdr) + sizeof(sr_ip_hdr), icmpPacketBuffer.data(), icmpPacketBuffer.size());

    packetSender->sendPacket(outPacket, ifaceIn);
}

void StaticRouter::handleICMPechoPacket(Packet& packet, std::string& ifaceIn, sr_ethernet_hdr_t& etherHeaderIn, sr_ip_hdr_t& ipHeader) {

    auto* icmpHeader = reinterpret_cast<sr_icmp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    if ((icmpHeader->icmp_type) != 8) {
        spdlog::error("Invalid ICMP Type. Not Type 8 as expected.");
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
    icmpHeaderOut.icmp_type = 0;
    icmpHeaderOut.icmp_code = 0;
    icmpHeaderOut.icmp_sum = htons(0);
    uint16_t icmp_data_size = ntohs(ipHeader.ip_len) - (sizeof(sr_ip_hdr) + sizeof(sr_icmp_hdr));
    // Create a buffer for the outgoing ICMP packet (header + payload)
    std::vector<uint8_t> icmpPacketBuffer(sizeof(sr_icmp_hdr_t) + icmp_data_size);

    // Copy ICMP header into the outgoing packet buffer
    memcpy(icmpPacketBuffer.data(), &icmpHeaderOut, sizeof(sr_icmp_hdr_t));

    // Copy the payload (data beyond the ICMP header) from the incoming packet
    uint8_t* incomingICMPpayload = reinterpret_cast<uint8_t*>(icmpHeader) + sizeof(sr_icmp_hdr_t);
    memcpy(icmpPacketBuffer.data() + sizeof(sr_icmp_hdr_t), incomingICMPpayload, icmp_data_size);

    // checksum for the outgoing ICMP message
    icmpHeaderOut.icmp_sum = cksum(icmpPacketBuffer.data(), icmpPacketBuffer.size());
    memcpy(icmpPacketBuffer.data(), &icmpHeaderOut, sizeof(sr_icmp_hdr_t)); // Update the checksum in the header

    prepAndSendPacket(ifaceIn, ipHeader, etherHeaderIn, icmpPacketBuffer, false);
}

void StaticRouter::handleICMPmsgPacket(Packet& packet, std::string& ifaceIn, sr_ethernet_hdr_t& etherHeaderIn,
                                        sr_ip_hdr_t& ipHeader, uint8_t type, uint8_t code) {

    sr_icmp_t3_hdr icmpHeaderOut;
    icmpHeaderOut.icmp_type = type;
    icmpHeaderOut.icmp_code = code;
    icmpHeaderOut.icmp_sum = htons(0);
    icmpHeaderOut.unused = htons(0);
    icmpHeaderOut.next_mtu = htons(1500);
    // uint16_t icmp_data_size = sizeof(sr_ip_hdr) + ;
    // Create a buffer for the outgoing ICMP packet (header + payload)

    // Copy full ip header, then 8 bytes of ip payload, from the incoming packet for ICMP data
    memcpy(icmpHeaderOut.data, &ipHeader, sizeof(sr_ip_hdr_t));
    uint8_t* ipPayloadStart = packet.data() + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t);
    memcpy(icmpHeaderOut.data + sizeof(sr_ip_hdr), ipPayloadStart, 8); 

    // checksum for the outgoing ICMP message
    icmpHeaderOut.icmp_sum = cksum(&icmpHeaderOut, sizeof(sr_icmp_t3_hdr));
    
    // add the whole ICMP to a buffer
    std::vector<uint8_t> icmpPacketBuffer(sizeof(sr_icmp_t3_hdr));
    memcpy(icmpPacketBuffer.data(), &icmpHeaderOut, sizeof(sr_icmp_t3_hdr)); 

    bool srcIPoverride = false;

    if ((type == 3 && (code == 0 || code == 1)) || type == 11) {
        srcIPoverride = true;
    }

    prepAndSendPacket(ifaceIn, ipHeader, etherHeaderIn, icmpPacketBuffer, srcIPoverride);
}


void StaticRouter::handleARPpacket(Packet& packet, std::string& ifaceIn, sr_ethernet_hdr_t& inEthrHdr) {
    auto* arpHeader = reinterpret_cast<sr_arp_hdr_t*>(packet.data() + sizeof(sr_ethernet_hdr_t));
    // implement request and response function according to ar_op value
    if ((ntohs(arpHeader->ar_op) == arp_op_request) && (routingTable->getRoutingInterface(ifaceIn).ip == arpHeader->ar_tip)) {
        // code for arp request
        sr_arp_hdr arpReply;
        arpReply.ar_hrd = htons(arp_hrd_ethernet);
        arpReply.ar_pro = htons(ethertype_ip);
        arpReply.ar_hln = 6;
        arpReply.ar_pln = 4;
        arpReply.ar_op = htons(arp_op_reply);
        memcpy(arpReply.ar_sha, routingTable->getRoutingInterface(ifaceIn).mac.data(), sizeof(mac_addr));
        arpReply.ar_sip = arpHeader->ar_tip;
        memcpy(arpReply.ar_tha, arpHeader->ar_sha, ETHER_ADDR_LEN);
        arpReply.ar_tip = arpHeader->ar_sip;
        
        sr_ethernet_hdr etherHeaderOut;
        etherHeaderOut.ether_type = htons(ethertype_arp);
        memcpy(etherHeaderOut.ether_dhost, inEthrHdr.ether_shost, ETHER_ADDR_LEN);
        memcpy(etherHeaderOut.ether_shost, arpReply.ar_sha, ETHER_ADDR_LEN);
        
        Packet outPacket;
        uint8_t* etherHdrPtr = reinterpret_cast<uint8_t*>(&etherHeaderOut);
        outPacket.insert(outPacket.end(), etherHdrPtr, etherHdrPtr + sizeof(sr_ethernet_hdr));

        uint8_t* arpRepPtr = reinterpret_cast<uint8_t*>(&arpReply);
        outPacket.insert(outPacket.end(), arpRepPtr, arpRepPtr + sizeof(sr_arp_hdr));

        packetSender->sendPacket(outPacket, ifaceIn);

    } else if ((ntohs(arpHeader->ar_op) == arp_op_reply) 
                && (routingTable->getRoutingInterface(ifaceIn).ip == arpHeader->ar_tip)) {
        // code to handle arp reply
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

    auto& interfaces = routingTable->getRoutingInterfaces();
    for (auto& [interfaceName, interface] : interfaces) {
        if (interface.ip == ipHeader->ip_dst) {
            forMyself = true;
            // check if ICMP, or TCP / UPD payload, // else, ignore packet
            if (ipHeader->ip_p == IPPROTO_ICMP) {
                handleICMPechoPacket(packet, iface, etherHeaderIn, *ipHeader);
            } else if ((ipHeader->ip_p == IPPROTO_TCP) || (ipHeader->ip_p == IPPROTO_UDP)) {
                handleICMPmsgPacket(packet, iface, etherHeaderIn, *ipHeader, 3, 3);
            } else {
                return;
            }

            break;
            
        }
    }

    if (forMyself == false) {

        if (ipHeader->ip_ttl > 1) {
            forwardOrQueueIPpacket(packet, etherHeaderIn, *ipHeader, iface);

        } else if ((ipHeader->ip_ttl) == 1) {

            handleICMPmsgPacket(packet, iface, etherHeaderIn, *ipHeader, 11, 0);

            return;

        } else if ((ipHeader->ip_ttl) == 0) {

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