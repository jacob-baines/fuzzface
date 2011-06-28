#include <arpa/inet.h>
#include <fstream>
#include <string>
#include <cstdio>
#include <ctime>
#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/io_service.hpp>
#include "modifier/randomizer.hpp"

static char readBuffer[65356] = {0};

int main(int argc, char* argv[])
{
    if (argc != 2)
    {
        std::cout << "You aren't doing it right." << std::endl;
        return 0;
    }
    
    std::ifstream filestream;
    modifier::Randomizer packetModifier;    
    bool writeGlobal = true;
    
    boost::asio::io_service ioHandler;
    boost::asio::ip::tcp::socket outputSocket(ioHandler);
    boost::asio::ip::tcp::endpoint server(boost::asio::ip::address::from_string("127.0.0.1"), 11111);
    outputSocket.connect(server);
    
    boost::uint32_t timestamp = 0;
    std::string rootDirectory(argv[1]);
    
    for (boost::filesystem::recursive_directory_iterator iter(rootDirectory);
         iter != boost::filesystem::recursive_directory_iterator(); ++iter)
    {
        if (boost::filesystem::is_regular_file(iter->path()))
        {
            filestream.open(iter->path().string().c_str(), std::ifstream::in);
            
            if (filestream.good())
            {
                filestream.read(readBuffer, 4);
                
                if (memcmp(readBuffer, "\xd4\xc3\xb2\xa1", 4) == 0)
                {               
                    //read the global header - link type is the last four
                    if (writeGlobal)
                    {
                        boost::asio::write(outputSocket, boost::asio::buffer(readBuffer, 4));
                    }
                    
                    filestream.read(readBuffer, 20);
                    
                    if (writeGlobal)
                    {
                        boost::asio::write(outputSocket, boost::asio::buffer(readBuffer, 20));
                        writeGlobal = false;
                    }
                        
                    while (!filestream.eof())
                    {
                        //read start of next header
                        filestream.read(readBuffer, 12);
                        
                        if (filestream.eof())
                        {
                            break;
                        }
                                           
                        timestamp = std::time(NULL);
                        memcpy(readBuffer, &timestamp, sizeof(boost::uint32_t));
                        memcpy(readBuffer + sizeof(boost::uint32_t), "\0\0\0\0", 4);
                        boost::asio::write(outputSocket, boost::asio::buffer(readBuffer, 12));
                    
                        //read length out of the pcap header
                        filestream.read(readBuffer, 4);
                        boost::asio::write(outputSocket, boost::asio::buffer(readBuffer, 4));
                    
                        boost::uint32_t frameSize = *reinterpret_cast<boost::uint32_t*>(readBuffer);
                        
                        filestream.read(readBuffer, frameSize);
                        packetModifier.modifyData(
                            reinterpret_cast<unsigned char*>(readBuffer),
                            static_cast<boost::uint16_t>(frameSize));
                        boost::asio::write(outputSocket, boost::asio::buffer(readBuffer, frameSize));
                    }
                    
                    printf("file completed\n");
                }
            }
            
            filestream.close();
        }
    }
 
    outputSocket.close();   
    return 0;
}
