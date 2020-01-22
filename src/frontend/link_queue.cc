/* -*-mode:c++; tab-width: 4; indent-tabs-mode: nil; c-basic-offset: 4 -*- */

#include <limits>
#include <cassert>
#include <random>

#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <math.h>

#include "link_queue.hh"
#include "timestamp.hh"
#include "util.hh"
#include "ezio.hh"
#include "abstract_packet_queue.hh"

using namespace std;

LinkQueue::LinkQueue( const string & link_name, const string & filename, const string & logfile,
                      const bool repeat, const bool graph_throughput, const bool graph_delay,
                      unique_ptr<AbstractPacketQueue> && packet_queue,
                      const string & command_line )
    : next_delivery_( 0 ),
      schedule_(),
      base_timestamp_( timestamp() ),
      bandwidth_history(0),
      is_adversary_(false),
      cur_bw_(12000000.0),
      cur_delay_ms_(10.0),
      cur_loss_rate_(0.0),
      packets_this_departure_time_(0),
      prev_departure_time_(0),
      next_possible_departure_time_(0),
      lcm(0),
      total_bandwidth_cycles(1),
      total_delivery_cycles(1),
      packets_ingress_(0),
      bytes_ingress_(0),
      packets_egress_(0),
      bytes_egress_(0),
      packet_drops_(0),
      bytes_drops_(0),
      total_delay_(0),
      mi_start_time_(timestamp()),
      mi_start_queue_size_(0),
      mi_dur_(30),
      actions_(),
      got_valid_action_(false),
      packet_queue_( move( packet_queue ) ),
      packet_in_transit_( "", 0 ),
      packet_in_transit_bytes_left_( 0 ),
      transit_queue_(),
      adversary_data_out_(),
      log_(),
      throughput_graph_( nullptr ),
      delay_graph_( nullptr ),
      repeat_( repeat ),
      finished_( false )
{
    assert_not_root();
    
    if (filename.find("adv", 0) == 0) {
        is_adversary_ = true;
        std::string obs_filename = std::string("/tmp/adversary_pipes/").append(filename).append("_obs");
        std::string ac_filename = std::string("/tmp/adversary_pipes/").append(filename).append("_actions");
        adversary_data_out_.open(obs_filename);
        poll_fds_[0].fd = open(ac_filename.c_str(), O_RDONLY | O_NONBLOCK);
        poll_fds_[0].events = POLLIN;
    } else {
        /* open filename and load schedule */
        ifstream trace_file( filename );

        if ( not trace_file.good() ) {
            throw runtime_error( filename + ": error opening for reading" );
        }

        string line;

        while ( trace_file.good() and getline( trace_file, line ) ) {
            if ( line.empty() ) {
                throw runtime_error( filename + ": invalid empty line" );
            }

            const uint64_t ms = myatoi( line );

            if ( not schedule_.empty() ) {
                if ( ms < schedule_.back() ) {
                    throw runtime_error( filename + ": timestamps must be monotonically nondecreasing" );
                }
            }

            schedule_.emplace_back( ms );
        }

        if ( schedule_.empty() ) {
            throw runtime_error( filename + ": no valid timestamps found" );
        }

        if ( schedule_.back() == 0 ) {
            throw runtime_error( filename + ": trace must last for a nonzero amount of time" );
        }
    }

    /* open logfile if called for */
    if ( not logfile.empty() ) {
        log_.reset( new ofstream( logfile ) );
        if ( not log_->good() ) {
            throw runtime_error( logfile + ": error opening for writing" );
        }

        *log_ << "# mahimahi mm-link (" << link_name << ") [" << filename << "] > " << logfile << endl;
        *log_ << "# command line: " << command_line << endl;
        *log_ << "# queue: " << packet_queue_->to_string() << endl;
        *log_ << "# init timestamp: " << initial_timestamp() << endl;
        *log_ << "# base timestamp: " << base_timestamp_ << endl;
        const char * prefix = getenv( "MAHIMAHI_SHELL_PREFIX" );
        if ( prefix ) {
            *log_ << "# mahimahi config: " << prefix << endl;
        }
    }

    /* create graphs if called for */
    if ( graph_throughput ) {
        throughput_graph_.reset( new BinnedLiveGraph( link_name + " [" + filename + "]",
                                                      { make_tuple( 1.0, 0.0, 0.0, 0.25, true ),
                                                        make_tuple( 0.0, 0.0, 0.4, 1.0, false ),
                                                        make_tuple( 1.0, 0.0, 0.0, 0.5, false ) },
                                                      "throughput (Mbps)",
                                                      8.0 / 1000000.0,
                                                      true,
                                                      500,
                                                      [] ( int, int & x ) { x = 0; } ) );
    }

    if ( graph_delay ) {
        delay_graph_.reset( new BinnedLiveGraph( link_name + " delay [" + filename + "]",
                                                 { make_tuple( 0.0, 0.25, 0.0, 1.0, false ) },
                                                 "queueing delay (ms)",
                                                 1, false, 250,
                                                 [] ( int, int & x ) { x = -1; } ) );
    }
}

void LinkQueue::record_arrival( const uint64_t arrival_time, const size_t pkt_size )
{
    /* log it */
    if ( log_ ) {
        *log_ << arrival_time << " + " << pkt_size << endl;
    }

    /* meter it */
    if ( throughput_graph_ ) {
        throughput_graph_->add_value_now( 1, pkt_size );
    }

    bytes_ingress_ += pkt_size;
    packets_ingress_ += 1;
}

void LinkQueue::record_drop( const uint64_t time, const size_t pkts_dropped, const size_t bytes_dropped)
{
    packet_drops_ += 1;
    bytes_drops_ += bytes_dropped;

    /* log it */
    if ( log_ ) {
        *log_ << time << " d " << pkts_dropped << " " << bytes_dropped << endl;
    }
}

void LinkQueue::record_departure_opportunity( void )
{
    /* log the delivery opportunity */
    if ( log_ ) {
        *log_ << next_delivery_time() << " # " << PACKET_SIZE << endl;
    }

    /* meter the delivery opportunity */
    if ( throughput_graph_ ) {
        throughput_graph_->add_value_now( 0, PACKET_SIZE );
    }    
}

void LinkQueue::record_departure( const uint64_t departure_time, const QueuedPacket & packet )
{
    /* log the delivery */
    if ( log_ ) {
        *log_ << departure_time << " - " << packet.contents.size()
              << " " << departure_time - packet.arrival_time << endl;
    }

    /* meter the delivery */
    if ( throughput_graph_ ) {
        throughput_graph_->add_value_now( 2, packet.contents.size() );
    }

    if ( delay_graph_ ) {
        delay_graph_->set_max_value_now( 0, departure_time - packet.arrival_time );
    }    

    bytes_egress_ += packet.contents.size();
    packets_egress_ += 1;
}

void LinkQueue::read_packet( const string & contents )
{
    const uint64_t now = timestamp();
    static std::default_random_engine generator;
    static std::uniform_real_distribution<double> distro(0.0,1.0);

    if ( contents.size() > PACKET_SIZE ) {
        throw runtime_error( "packet size is greater than maximum" );
    }

    rationalize( now );

    record_arrival( now, contents.size() );

    if (distro(generator) <= cur_loss_rate_) {
        record_drop( now, 1, contents.size() );
        return;
    }

    unsigned int bytes_before = packet_queue_->size_bytes();
    unsigned int packets_before = packet_queue_->size_packets();

    packet_queue_->enqueue( QueuedPacket( contents, now ) );

    assert( packet_queue_->size_packets() <= packets_before + 1 );
    assert( packet_queue_->size_bytes() <= bytes_before + contents.size() );
    
    unsigned int missing_packets = packets_before + 1 - packet_queue_->size_packets();
    unsigned int missing_bytes = bytes_before + contents.size() - packet_queue_->size_bytes();
    if ( missing_packets > 0 || missing_bytes > 0 ) {
        record_drop( now, missing_packets, missing_bytes );
    }
}

uint64_t LinkQueue::next_delivery_time( void ) const
{
    if ( finished_ ) {
        return -1;
    } else {
        if (is_adversary_) {
            return base_timestamp_ + bandwidth_history;
        } else {
            return schedule_.at( next_delivery_ ) + base_timestamp_;
        }
    }
}

int LinkQueue::read_next_action() {
    int ret = poll(poll_fds_, 1, 0);
    if (!(ret == 1 && (poll_fds_[0].revents & POLLIN))) {
        return -1;
    }

    static char buf[1024];
    int result = read(poll_fds_[0].fd, buf, 1024);
	assert(result > 0);
    char* end = &(buf[0]);
	double action_bw = strtod(buf, &end);
	end++;
	double action_delay = strtod(end, &end);
    end++;
    double action_loss_rate = strtod(end, &end);
    LinkQueueAction lqa(action_bw, action_delay, action_loss_rate);
    actions_.push(lqa);

    return 0;
}

void LinkQueue::use_a_delivery_opportunity( void )
{
    record_departure_opportunity();

    if (is_adversary_) {
        // stay "silent" for ```total_bandwidth_cycles - total_delivery_cycles``` milliseconds
        // then send each millesecond for ```total_delivery_cycles```
        
        if (next_delivery_ < total_bandwidth_cycles - total_delivery_cycles) { 
            next_delivery_ = total_bandwidth_cycles - total_delivery_cycles; 
            bandwidth_history += total_bandwidth_cycles - total_delivery_cycles; 
        } 
        
        bandwidth_history++;
        
        next_delivery_ = (next_delivery_ + 1) % total_bandwidth_cycles; 
    } else {
        next_delivery_ = (next_delivery_ + 1) % schedule_.size();

        /* wraparound */
        if ( next_delivery_ == 0 ) {
            if ( repeat_ ) {
                base_timestamp_ += schedule_.back();
            } else {
                finished_ = true;
            }
        }
    }
}

/* emulate the link up to the given timestamp */
/* this function should be called before enqueueing any packets and before
   calculating the wait_time until the next event */
void LinkQueue::rationalize( const uint64_t now )
{

    if (is_adversary_) {

        mi_start_queue_size_ = packet_queue_->size_bytes();

        if (read_next_action() == 0) {
            adversary_data_out_
                << mi_start_time_ << ","
                << now << ","
                << cur_bw_ << ","
                << cur_delay_ms_ << ","
                << cur_loss_rate_ << ","
                << bytes_ingress_ << ","
                << packets_ingress_ << ","
                << bytes_egress_ << ","
                << packets_egress_ << ","
                << packet_drops_ << ","
                << bytes_drops_ << ","
                << total_delay_ << ","
                << mi_start_queue_size_ << ","
                << packet_queue_->size_bytes() << std::endl;

            mi_start_time_ = now;
            packets_ingress_ = 0;
            bytes_ingress_ = 0;
            packets_egress_ = 0;
            bytes_egress_ = 0;
            packet_drops_ = 0;
            bytes_drops_ = 0;
            total_delay_ = 0;
        }

        if (!actions_.empty()) {
            LinkQueueAction lqa = actions_.front();
            actions_.pop();
            // round up the bandwidth up to 1 digit (in Mbps)
            cur_bw_ = (floorf(lqa.bw * 10) / 10) * 1000000.0;
            cur_delay_ms_ = (int)lqa.delay_ms;
            cur_loss_rate_ = lqa.loss_rate;

            // Used for bandwidths that are not multiples of 12.
            // For example, for 8 Mbps, LCM(12, 8)=24. So we need to have 24/12=2 deliveries out of 24/8=3.
            lcm = std::lcm(12000000, (int64_t) round(cur_bw_));
            total_delivery_cycles = lcm / 12000000;
            total_bandwidth_cycles = lcm / (int64_t) round(cur_bw_);
        }
    }

    while ( next_delivery_time() <= now ) {
        const uint64_t this_delivery_time = next_delivery_time();

        /* burn a delivery opportunity */
        unsigned int bytes_left_in_this_delivery = PACKET_SIZE;
        use_a_delivery_opportunity();

        while ( bytes_left_in_this_delivery > 0 ) {
            if ( not packet_in_transit_bytes_left_ ) {
                if ( packet_queue_->empty() ) {
                    break;
                }
                packet_in_transit_ = packet_queue_->dequeue();
                packet_in_transit_bytes_left_ = packet_in_transit_.contents.size();
            }
            
            if (packet_in_transit_.arrival_time > this_delivery_time) {
                std::cerr << "Delivery time: " << this_delivery_time << std::endl;
                std::cerr << "Arrival time: " << packet_in_transit_.arrival_time << std::endl;
            }
            assert( packet_in_transit_.arrival_time <= this_delivery_time );
            assert( packet_in_transit_bytes_left_ <= PACKET_SIZE );
            assert( packet_in_transit_bytes_left_ > 0 );
            assert( packet_in_transit_bytes_left_ <= packet_in_transit_.contents.size() );

            /* how many bytes of the delivery opportunity can we use? */
            const unsigned int amount_to_send = min( bytes_left_in_this_delivery,
                                                     packet_in_transit_bytes_left_ );

            /* send that many bytes */
            packet_in_transit_bytes_left_ -= amount_to_send;
            bytes_left_in_this_delivery -= amount_to_send;

            /* has the packet been fully sent? */
            if ( packet_in_transit_bytes_left_ == 0 ) {
                const uint64_t departure_time = get_departure_time(this_delivery_time);
                record_departure(departure_time, packet_in_transit_);

                total_delay_ += departure_time - packet_in_transit_.arrival_time;

                /* this packet is ready to go */
                TransitPacket tp(departure_time, 
                    packet_in_transit_.contents);
                transit_queue_.push(tp);
            }
        }
    }
}

uint64_t LinkQueue::get_departure_time(uint64_t delivery_time) {
    if (!is_adversary_) {
        return delivery_time;
    }
    
    uint64_t departure_time = delivery_time + cur_delay_ms_;

    if (departure_time < prev_departure_time_) {
        departure_time = prev_departure_time_;
    } else {
        prev_departure_time_ = departure_time;
    }

    return departure_time;
}

void LinkQueue::write_packets( FileDescriptor & fd )
{
    while(!transit_queue_.empty()
        && transit_queue_.top().exit_time <= timestamp()) {
        fd.write(transit_queue_.top().contents);
        transit_queue_.pop();
    }
    /*
    while ( not output_queue_.empty() ) {
        fd.write( output_queue_.front() );
        output_queue_.pop();
    }
    */
}

unsigned int LinkQueue::wait_time( void )
{
    const auto now = timestamp();

    rationalize( now );

    if ( next_delivery_time() <= now ) {
        return 0;
    } else {
        return next_delivery_time() - now;
    }
}

bool LinkQueue::pending_output( void ) const
{
    if (transit_queue_.empty()) {
        return false;
    }
    if (is_adversary_) {
        return transit_queue_.top().exit_time <= timestamp();
    } else {
        return true;
    }
}
