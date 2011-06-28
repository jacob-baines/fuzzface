#include <map>
#include <boost/cstdint.hpp>

namespace modifier
{
    class Randomizer
    {
    public:
    
        Randomizer();
        ~Randomizer();
    
        void modifyData(unsigned char* p_data, boost::uint16_t p_length);

    private:

        Randomizer(const Randomizer&);
        Randomizer& operator=(const Randomizer&);   
        
    private:
    
        std::map<boost::uint16_t, boost::uint16_t> m_randomData; 
    
    };
}
