#ifndef FUZZFACE_HPP
#define FUZZFACE_HPP

#include <string>

#include <boost/asio.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/io_service.hpp>
#include <boost/filesystem.hpp>
#include <boost/cstdint.hpp>

#include "modifier/randomizer.hpp"

class FuzzFace
{
public:

    FuzzFace();
    ~FuzzFace();
    
    void processFiles(const std::string& p_rootDirectory);
    
    void connect(const boost::asio::ip::address& p_serverAddress,
                 boost::uint16_t p_serverPort);

private:
    /*
        Reads in the PCAP global header and tries to verify that
        the file is little endian pcap with ethernet link type.
        
        \return true iff the file is little endian pcap with enet link type
    */
    bool validateGlobalHeader(std::ifstream& p_fileStream, 
                              boost::filesystem::recursive_directory_iterator& p_iter,
                              char* p_readBuffer);
private:

    // Modifies the packet data we give it
    modifier::Randomizer m_randomizer;
    
    // The io handles for our socket
    boost::asio::io_service m_ioHandler;
    
    // The socket we'll send reformated data out on
    boost::asio::ip::tcp::socket m_socketOutput;
};

#endif /* FUZZFACE_HPP */
