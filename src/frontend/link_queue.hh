/* -*-mode:c++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#ifndef LINK_QUEUE_HH
#define LINK_QUEUE_HH

#include <queue>
#include <cstdint>
#include <string>
#include <fstream>
#include <memory>

#include <poll.h>

#include "file_descriptor.hh"
#include "binned_livegraph.hh"
#include "abstract_packet_queue.hh"

struct TransitPacket {
    TransitPacket(uint64_t exit_time, std::string contents)
        : exit_time(exit_time),
          contents(move(contents)) {
    };
    uint64_t exit_time;
    std::string contents;
};

class TransitPacketCompare {
  public:
    bool operator() (const TransitPacket& p1, const TransitPacket& p2) {
        return p1.exit_time > p2.exit_time;
    }
};

struct LinkQueueAction {
    LinkQueueAction(double bw, double delay_ms, double loss_rate)
        : bw(bw),
          delay_ms(delay_ms),
          loss_rate(loss_rate) {

    }
    double bw;
    double delay_ms;
    double loss_rate;
};


class LinkQueue
{
private:
    const static unsigned int PACKET_SIZE = 1504; /* default max TUN payload size */

    unsigned int next_delivery_;
    std::vector<uint64_t> schedule_;
    uint64_t base_timestamp_;
    mutable uint64_t bandwidth_history;

    bool is_adversary_;
    double cur_bw_;
    uint64_t cur_delay_ms_;
    double cur_loss_rate_;
    uint64_t packets_this_departure_time_;
    uint64_t prev_departure_time_;
    uint64_t next_possible_departure_time_;

    long lcm;
    long total_bandwidth_cycles;
    long total_delivery_cycles;

    uint64_t packets_ingress_;
    uint64_t bytes_ingress_;
    uint64_t packets_egress_;
    uint64_t bytes_egress_;
    uint64_t packet_drops_;
    uint64_t bytes_drops_;
    uint64_t total_delay_;
    uint64_t mi_start_time_;
    uint64_t mi_start_queue_size_;
    uint64_t mi_dur_;

    std::queue<LinkQueueAction> actions_;
    bool got_valid_action_;

    struct pollfd poll_fds_[1];

    std::unique_ptr<AbstractPacketQueue> packet_queue_;
    QueuedPacket packet_in_transit_;
    unsigned int packet_in_transit_bytes_left_;

    std::priority_queue<TransitPacket, std::vector<TransitPacket>, TransitPacketCompare> transit_queue_;

    std::ofstream adversary_data_out_;

    std::unique_ptr<std::ofstream> log_;
    std::unique_ptr<BinnedLiveGraph> throughput_graph_;
    std::unique_ptr<BinnedLiveGraph> delay_graph_;

    bool repeat_;
    bool finished_;

    uint64_t next_delivery_time( void ) const;

    void use_a_delivery_opportunity( void );

    void record_arrival( const uint64_t arrival_time, const size_t pkt_size );
    void record_drop( const uint64_t time, const size_t pkts_dropped, const size_t bytes_dropped );
    void record_departure_opportunity( void );
    void record_departure( const uint64_t departure_time, const QueuedPacket & packet );
    uint64_t get_departure_time(uint64_t delivery_time);

    void rationalize( const uint64_t now );
    void dequeue_packet( void );

    int read_next_action();

public:
    LinkQueue( const std::string & link_name, const std::string & filename, const std::string & logfile,
               const bool repeat, const bool graph_throughput, const bool graph_delay,
               std::unique_ptr<AbstractPacketQueue> && packet_queue,
               const std::string & command_line );

    void read_packet( const std::string & contents );

    void write_packets( FileDescriptor & fd );

    unsigned int wait_time( void );

    bool pending_output( void ) const;

    bool finished( void ) const { return finished_; }
};

#endif /* LINK_QUEUE_HH */
