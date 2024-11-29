#ifndef STATICROUTER_H
#define STATICROUTER_H
#include <vector>
#include <memory>
#include <mutex>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "IRoutingTable.h"
#include "RouterTypes.h"
#include "protocol.h"


class StaticRouter {
public:
    StaticRouter(std::unique_ptr<IArpCache> arpCache, std::shared_ptr<IRoutingTable> routingTable,
                 std::shared_ptr<IPacketSender> packetSender);

    /**
     * @brief Handles an incoming packet, telling the switch to send out the necessary packets.
     * @param packet The incoming packet.
     * @param iface The interface on which the packet was received.
     */
    void handlePacket(std::vector<uint8_t> packet, std::string iface);

private:
    std::mutex mutex;

    std::shared_ptr<IRoutingTable> routingTable;
    std::shared_ptr<IPacketSender> packetSender;

    std::unique_ptr<IArpCache> arpCache;

    void handleARPpacket(Packet& packet, std::string& iface, sr_ethernet_hdr_t& inEthrHdr);
    void handleIPpacket(Packet& packet, std::string& iface, sr_ethernet_hdr_t& etherHeaderIn);
    void handleICMPechoPacket(Packet& packet, std::string& iface, sr_ethernet_hdr_t& etherHeaderIn, sr_ip_hdr_t& ipHeader);
    void handleICMPmsgPacket(Packet& packet, std::string& iface, sr_ethernet_hdr_t& etherHeaderIn, sr_ip_hdr_t& ipHeader, uint8_t type, uint8_t code);
    void prepAndSendPacket(std::string& iface, sr_ip_hdr_t& ipHeader, sr_ethernet_hdr_t& etherHeaderIn, std::vector<uint8_t>& icmpPacketBuffer, bool srcIPoverride);
    void forwardIPpacket(Packet packet, sr_ethernet_hdr_t& etherHeaderIn, sr_ip_hdr_t& ipHeader, std::string& iface, mac_addr& destMac);

    mac_addr toMacAddr(const unsigned char* macArray);
};


#endif //STATICROUTER_H
