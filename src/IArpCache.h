#ifndef IARPCACHE_H
#define IARPCACHE_H
#include <list>
#include <string>
#include <optional>

#include "RouterTypes.h"

struct ArpEntry
{
    uint32_t ip; /**< IP address of the entry. */
    mac_addr mac; /**< MAC address corresponding to the IP. */
    std::chrono::time_point<std::chrono::steady_clock> timeAdded; /**< Time when the entry was added. */
};

struct AwaitingPacket
{
    Packet packet; /**< Packet that is awaiting the ARP response. */
    std::string iface; /**< Interface on which the packet came in */
};

struct ArpRequest
{
    uint32_t ip; /**< IP address for which the ARP request is being sent. */
    std::chrono::time_point<std::chrono::steady_clock> lastSent; /**< Time when the request was last sent.*/
    uint32_t timesSent; /**< Number of times the request has been sent. */

    std::list<AwaitingPacket> awaitingPackets; /**< Packets that are waiting for this ARP request to complete. */
};

class IArpCache {
public:
    virtual ~IArpCache() = default;

    /**
     * @brief Adds an entry to the ARP cache with the given IP and MAC address.
     * @param ip The IP address of the entry.
     * @param mac The MAC address of the entry.
     */
    virtual void addEntry(uint32_t ip, const mac_addr& mac) = 0;

    /**
     * @brief Retrieves the MAC address corresponding to the given IP address if it exists in the cache.
     * @param ip The IP address to look up.
     * @return The MAC address corresponding to the IP address, if it exists in the cache.
     */
    virtual std::optional<mac_addr> getEntry(uint32_t ip) = 0;

    /**
     * @brief Queues a packet to be sent once the MAC address for the given IP address is resolved.
     * @param ip The IP address to which the packet should be sent.
     * @param packet The packet to send.
     * @param iface The interface on which to send the packet.
     */
    virtual void queuePacket(uint32_t ip, const Packet& packet, const std::string& iface) = 0;
};

#endif //IARPCACHE_H
