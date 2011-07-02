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

static char s_readBuffer[65356] = {0};
static std::string s_rootDirectory;
static int s_seedValue = 0;

/*
    Checks to make sure the command line params are present and
    valid. Also, initializes srand here.
*/
bool validateInput(int argc, char* argv[],
                   std::string& p_rootDirectory, int& p_seedValue)
{
    //currently we need argc to be 2 or 3
    if (argc < 2 || argc > 3)
    {
        return false;
    }

    p_rootDirectory.assign(argv[1]);
    if (!boost::filesystem::is_directory(p_rootDirectory))
    {
        std::cerr << p_rootDirectory << " is not a directory." << std::endl;
        return false;
    }
    
    // use the seed provided or generate a new one
    if (argc == 3)
    {
        try
        {
            p_seedValue = boost::lexical_cast<int>(argv[2]);
        }
        catch (std::exception& e)
        {
            std::cerr << "Failed to convert your seed value to an integer."
                      << std::endl;
            return false;
        }
    }
    else
    {
        p_seedValue = std::time(NULL);
    }    
    
    srand(p_seedValue);
    return true;
}

int main(int argc, char* argv[])
{   
    if (!validateInput(argc, argv, s_rootDirectory, s_seedValue))
    {
        std::cout << "Usage: ./fuzzface <directory>" << std::endl;
        return EXIT_FAILURE;
    }
    
    std::ifstream filestream;
    modifier::Randomizer packetModifier;    
    bool writeGlobal = true;
    
    boost::asio::io_service ioHandler;
    boost::asio::ip::tcp::socket outputSocket(ioHandler);
    boost::asio::ip::tcp::endpoint server(boost::asio::ip::address::from_string("127.0.0.1"), 11111);
    outputSocket.connect(server);

    boost::uint32_t timestamp = 0;
    
    for (boost::filesystem::recursive_directory_iterator iter(s_rootDirectory);
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
            filestream.read(s_readBuffer, 24);
                
            if (filestream.eof())
            {
                std::cout << "File skipped: " << iter->path().string()
                          << " not enough data." << std::endl;
                filestream.close();
                continue;
            }
            
            if (memcmp(s_readBuffer, "\xd4\xc3\xb2\xa1", 4) != 0)
            {
                std::cerr << "File skipped: " << iter->path().string()
                          << " couldn't find magic bytes." << std::endl;
                filestream.close();
                continue;
            }
            
            if (memcmp(s_readBuffer + 20, "\x01\x00\x00\x00", 4) != 0)
            {
                std::cout << "File skipped: " << iter->path().string() 
                          << " link type is not ethernet." << std::endl;
                filestream.close();
                continue;
            }
            
            if (writeGlobal)
            {
                boost::asio::write(outputSocket, boost::asio::buffer(s_readBuffer, 24));
                writeGlobal = false;
            }
        
            while (!filestream.eof())
            {   
                //read start of next header
                filestream.read(s_readBuffer, 16);
                        
                if (filestream.eof())
                {
                    break;
                }
                                           
                timestamp = std::time(NULL);
                memcpy(s_readBuffer, &timestamp, sizeof(boost::uint32_t));
                memcpy(s_readBuffer + sizeof(boost::uint32_t), "\0\0\0\0", 4);
                
                boost::uint32_t frameSize = *reinterpret_cast<boost::uint32_t*>(s_readBuffer + 8);

                if (frameSize > sizeof(s_readBuffer))
                {
                    std::cout << "Frame too large (" << frameSize
                              << " bytes): " << iter->path().string()
                              << std::endl;
                    break;
                }

                boost::asio::write(outputSocket, boost::asio::buffer(s_readBuffer, 16));
                                                               
                filestream.read(s_readBuffer, frameSize);
                packetModifier.modifyData(
                    reinterpret_cast<unsigned char*>(s_readBuffer),
                    static_cast<boost::uint16_t>(frameSize));
                        
                boost::asio::write(outputSocket, boost::asio::buffer(s_readBuffer, frameSize));
               
            }
                    
            std::cout << "File completed: " << iter->path().string() << std::endl;
            filestream.close();
        }
    }
 
    outputSocket.close();   
    
    std::cout << "Your seed was: " << s_seedValue << std::endl;
    return 0;
}

