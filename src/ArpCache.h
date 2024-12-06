#ifndef ARPCACHE_H
#define ARPCACHE_H

#include <cstdint>
#include <vector>
#include <array>
#include <chrono>
#include <set>
#include <unordered_map>
#include <thread>
#include <optional>
#include <memory>
#include <mutex>

#include "IArpCache.h"
#include "IPacketSender.h"
#include "RouterTypes.h"
#include "IRoutingTable.h"
#include "protocol.h"

class ArpCache : public IArpCache {
public:
    ArpCache(std::chrono::milliseconds timeout,
        std::shared_ptr<IPacketSender> packetSender, std::shared_ptr<IRoutingTable> routingTable);

    ~ArpCache() override;

    void tick();

    void addEntry(uint32_t ip, const mac_addr& mac) override;

    std::optional<mac_addr> getEntry(uint32_t ip) override;

    void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) override;

private:
    void loop();

    std::chrono::milliseconds timeout;

    std::mutex mutex;
    std::unique_ptr<std::thread> thread;
    std::atomic<bool> shutdown = false;

    std::shared_ptr<IPacketSender> packetSender;
    std::shared_ptr<IRoutingTable> routingTable;

    std::unordered_map<ip_addr, ArpEntry> entries;
    std::unordered_map<ip_addr, ArpRequest> requests;

    Packet createARPReqPacket(uint32_t tip, std::string& iface);
    void sendQueuedPackets(uint32_t ip, const mac_addr& mac);
    void sendICMP31(ArpRequest arpReq);
};



#endif //ARPCACHE_H
