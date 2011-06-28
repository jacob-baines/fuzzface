#include <cstdio>
#include "randomizer.hpp"

namespace modifier
{
    Randomizer::Randomizer() :
        m_randomData()
    {
    }

    Randomizer::~Randomizer()
    {
    }
    
    void Randomizer::modifyData(unsigned char* p_data,
                                boost::uint16_t p_dataLength)
    {
        boost::uint16_t bytesToChange = p_dataLength * 0.10;

        while (bytesToChange != 0)
        {
            boost::uint16_t index = rand() % p_dataLength;

            if (m_randomData.find(index) == m_randomData.end())
            {
                m_randomData.insert(std::make_pair(index, rand() % 256));
                --bytesToChange;
            }
        }
        
        for (std::map<boost::uint16_t, boost::uint16_t>::iterator iter(m_randomData.begin());
             iter != m_randomData.end();
             ++iter)
        {
            p_data[iter->first] = iter->second;
        }
        
        m_randomData.clear();
    }
}


