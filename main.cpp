#include <string>
#include <cstdio>
#include <iostream>
#include <boost/cstdint.hpp>
#include <boost/filesystem.hpp>
#include <boost/lexical_cast.hpp>

#include "fuzzface.hpp"

/*
    Checks to make sure the command line params are present and
    valid. Also, initializes srand here.
*/
bool validateInput(int argc, char* argv[],
                   std::string& p_rootDirectory,
                   boost::asio::ip::address& p_ipAddress,
                   boost::uint16_t& p_port, int& p_seedValue)
{
    //currently we need argc to be 2 or 3
    if (argc < 4 || argc > 5)
    {
        return false;
    }

    p_rootDirectory.assign(argv[1]);
    if (!boost::filesystem::is_directory(p_rootDirectory))
    {
        std::cerr << p_rootDirectory << " is not a directory." << std::endl;
        return false;
    }
    
    try
    {
        p_ipAddress.from_string(argv[2]);    
    }
    catch (std::exception&)
    {
        std::cerr << "Failed to convert the IP address paramater to a IPv4 or"
                     " IPv6 address." << std::endl;
        return false;
    }
    
    try
    {
        p_port = boost::lexical_cast<boost::uint16_t>(argv[3]);
    }
    catch (std::exception&)
    {
        std::cerr << "Failed to convert port value to a 16 bit integer"
                  << std::endl;
        return false;
    }
    
    // use the seed provided or generate a new one
    if (argc == 5)
    {
        try
        {
            p_seedValue = boost::lexical_cast<int>(argv[4]);
        }
        catch (std::exception& e)
        {
            std::cerr << "Failed to convert seed parameter value to an integer."
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
    //expected command line params
    int seedValue = 0;
    boost::uint16_t port = 0;
    std::string rootDirectory;
    boost::asio::ip::address ipAddress;
   
    if (!validateInput(argc, argv, rootDirectory, ipAddress, port, seedValue))
    {
        std::cout << "Usage: ./fuzzface <directory> <server ip> <server port>"
                     " [optional seed]" << std::endl;
        return EXIT_FAILURE;
    }
    
    FuzzFace pcapFuzzer;
    
    try
    {
        pcapFuzzer.connect(ipAddress, port);
    }
    catch (std::exception& e)
    {
        std::cerr << "Failed to connect the server: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    
    try
    {
        pcapFuzzer.processFiles(rootDirectory);
    }
    catch (std::exception& e)
    {
        std::cerr << "Shutting down. Error while processing: " << e.what()
                  << std::endl;
    }

    pcapFuzzer.printStats();
        
    std::cout << "\nYour seed was: " << seedValue << std::endl;
    return 0;
}

