#include "fuzzface.hpp"

#include <ctime>
#include <fstream>
#include <iostream>
#include <arpa/inet.h>

#include <boost/spirit/include/karma.hpp>
#include <boost/spirit/include/karma_generate.hpp>
#include <boost/spirit/include/karma_uint.hpp>

// the buffer to read into / write out with
static char s_readBuffer[65356] = {0};

FuzzFace::FuzzFace() :
    m_randomizer(),
    m_ioHandler(),
    m_socketOutput(m_ioHandler),
    m_totalBytes(0),
    m_totalPackets(0),
    m_fuzzedFiles(0),
    m_skippedFiles(0)
{
}

FuzzFace::~FuzzFace()
{
}

void FuzzFace::printStats() const
{
    std::cout << "\n===Processing Statistics===" << std::endl;
    std::string output("Files Fuzzed: ");
    generateStat(output, m_fuzzedFiles);
    
    output.assign("Skipped Files: ");
    generateStat(output, m_skippedFiles);
    
    output.assign("Total Packets Processed: ");
    generateStat(output, m_totalPackets);
    
    output.assign("Total Bytes Processed: ");
    generateStat(output, m_totalBytes);
}

void FuzzFace::generateStat(std::string& p_output, boost::uint64_t p_stat) const
{
    boost::spirit::karma::generate(
        std::back_insert_iterator<std::string>(p_output),
        boost::spirit::karma::ulong_long, p_stat);
    
    std::cout << p_output << std::endl;
}

void FuzzFace::connect(const boost::asio::ip::address& p_serverAddress,
                       boost::uint16_t p_serverPort)
{
    boost::asio::ip::tcp::endpoint server(p_serverAddress, p_serverPort);
    m_socketOutput.connect(server);
}

bool FuzzFace::validateGlobalHeader(std::ifstream& p_fileStream, 
                                    boost::filesystem::recursive_directory_iterator& p_iter,
                                    char* p_readBuffer)
{
    if (!p_fileStream.good())
    {
        std::cerr << "File skipped: " << p_iter->path().string()
                  << " failed to open." << std::endl;
        return false;                
    }
            
    //read the global pcap header
    p_fileStream.read(p_readBuffer, 24);
                
    if (p_fileStream.eof())
    {
        std::cerr << "File skipped: " << p_iter->path().string()
                  << " not enough data." << std::endl;
        p_fileStream.close();
        return false;
    }
    
    //check for PCAP magic bytes (little endian)        
    if (memcmp(p_readBuffer, "\xd4\xc3\xb2\xa1", 4) != 0)
    {
        std::cerr << "File skipped: " << p_iter->path().string()
                  << " couldn't find magic bytes." << std::endl;
        p_fileStream.close();
        return false;
    }
    
    //verify link type in PCAP header
    if (memcmp(p_readBuffer + 20, "\x01\x00\x00\x00", 4) != 0)
    {
        std::cerr << "File skipped: " << p_iter->path().string() 
                  << " link type is not ethernet." << std::endl;
        p_fileStream.close();
        return false;
    }
    
    return true;
}


void FuzzFace::processFiles(const std::string& p_rootDirectory)
{
    bool writeGlobal = true;
    std::ifstream currentFile;
    
    for (boost::filesystem::recursive_directory_iterator iter(p_rootDirectory);
         iter != boost::filesystem::recursive_directory_iterator(); ++iter)
    {
        if (boost::filesystem::is_regular_file(iter->path()))
        {
            currentFile.open(iter->path().string().c_str(), std::ifstream::in);
            
            if (!validateGlobalHeader(currentFile, iter, s_readBuffer))
            {
                //skip this file
                ++m_skippedFiles;
                continue;
            }

            ++m_fuzzedFiles;                             
            if (writeGlobal)
            {
                boost::asio::write(m_socketOutput, boost::asio::buffer(s_readBuffer, 24));
                writeGlobal = false;
            }
        
            while (!currentFile.eof())
            {   
                //read start of next header
                currentFile.read(s_readBuffer, 16);
                        
                if (currentFile.eof())
                {
                    break;
                }
                                           
                boost::uint32_t timestamp = std::time(NULL);
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

                ++m_totalPackets;
                m_totalBytes += frameSize;
                boost::asio::write(m_socketOutput, boost::asio::buffer(s_readBuffer, 16));
                                                               
                currentFile.read(s_readBuffer, frameSize);
                m_randomizer.modifyData(
                    reinterpret_cast<unsigned char*>(s_readBuffer),
                    static_cast<boost::uint16_t>(frameSize));
                        
                boost::asio::write(m_socketOutput, boost::asio::buffer(s_readBuffer, frameSize));
               
            }
                    
            std::cout << "File completed: " << iter->path().string() << std::endl;
            currentFile.close();
        }
    }
 
    m_socketOutput.close();   
}
