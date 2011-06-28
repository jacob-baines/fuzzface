#include <arpa/inet.h>
#include <fstream>
#include <string>
#include <cstdio>
#include <ctime>
#include <iostream>
#include <boost/lexical_cast.hpp>
#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/io_service.hpp>
#include "modifier/randomizer.hpp"

static char readBuffer[65356] = {0};

int main(int argc, char* argv[])
{
    if (argc < 2 || argc > 3)
    {
        std::cout << "You aren't doing it right." << std::endl;
        return 0;
    }
    
    std::string rootDirectory(argv[1]);
    int seedValue = 0;
    
    if (argc == 3)
    {
        seedValue = boost::lexical_cast<int>(argv[2]);
    }
    else
    {
        seedValue = std::time(NULL);
    }
    
    srand(seedValue);
    
    std::ifstream filestream;
    modifier::Randomizer packetModifier;    
    bool writeGlobal = true;
    
    boost::asio::io_service ioHandler;
    boost::asio::ip::tcp::socket outputSocket(ioHandler);
    boost::asio::ip::tcp::endpoint server(boost::asio::ip::address::from_string("127.0.0.1"), 11111);
    outputSocket.connect(server);

    //boost::uint32_t timestamp = 0;
    
    for (boost::filesystem::recursive_directory_iterator iter(rootDirectory);
         iter != boost::filesystem::recursive_directory_iterator(); ++iter)
    {
        if (boost::filesystem::is_regular_file(iter->path()))
        {
            filestream.open(iter->path().string().c_str(), std::ifstream::in);
            
            if (!filestream.good())
            {
                std::cout << "File skipped: " << iter->path().string() << " failed to open." << std::endl;
                continue;                
            }
            
            //read the global pcap header
            filestream.read(readBuffer, 24);
                
            if (filestream.eof())
            {
                std::cout << "File skipped: " << iter->path().string()
                          << " not enough data." << std::endl;
                filestream.close();
                continue;
            }
            
            if (memcmp(readBuffer, "\xd4\xc3\xb2\xa1", 4) != 0)
            {
                std::cout << "File skipped: " << iter->path().string()
                          << " couldn't find magic bytes." << std::endl;
                filestream.close();
                continue;
            }
            
            if (memcmp(readBuffer + 20, "\x01\x00\x00\x00", 4) != 0)
            {
                std::cout << "File skipped: " << iter->path().string() 
                          << " link type is not ethernet." << std::endl;
                filestream.close();
                continue;
            }
            
            if (writeGlobal)
            {
                boost::asio::write(outputSocket, boost::asio::buffer(readBuffer, 24));
                writeGlobal = false;
            }
                        
            while (!filestream.eof())
            {
                //read start of next header
                filestream.read(readBuffer, 16);
                        
                if (filestream.eof())
                {
                    break;
                }
                                           
               // timestamp = std::time(NULL);
               // memcpy(readBuffer, &timestamp, sizeof(boost::uint32_t));
               // memcpy(readBuffer + sizeof(boost::uint32_t), "\0\0\0\0", 4);
               // boost::asio::write(outputSocket, boost::asio::buffer(readBuffer, 16));
                boost::uint32_t frameSize = *reinterpret_cast<boost::uint32_t*>(readBuffer + 12);
                        
                filestream.read(readBuffer, frameSize);
                packetModifier.modifyData(
                reinterpret_cast<unsigned char*>(readBuffer),
                static_cast<boost::uint16_t>(frameSize));
                        
                boost::asio::write(outputSocket, boost::asio::buffer(readBuffer, frameSize));
            }
                    
            std::cout << "File completed: " << iter->path().string() << std::endl;
            filestream.close();
        }
    }
 
    outputSocket.close();   
    
    std::cout << "Your seed was: " << seedValue << std::endl;
    return 0;
}

