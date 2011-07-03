# Set this variable to the desired name of your executable.
# For example:
# PROGRAM_NAME = test_program
PROGRAM_NAME = fuzzface

# Set this variable to a space separated list of all object files to be
# compiled.  For example:
# OBJS = cmdline.o main.o
OBJS = main.o fuzzface.o ./modifier/randomizer.o

# Executable used to perform compile and link operations
CXX = g++

# Flags to be passed to the compiler
CXXFLAGS = -Wall -Wextra -Werror -Weffc++ -Wshadow -O1

# Flags to be passed to the linker (libraries, etc.)
LDFLAGS = -lboost_filesystem

all: $(PROGRAM_NAME)

$(PROGRAM_NAME): $(OBJS)
	$(CXX) -o $@ $(LDFLAGS) $^

-include $(OBJS:.o=.d)

%.o: %.cpp
	$(CXX) -c $(CXXFLAGS) $*.cpp -o $*.o
	@$(CXX) -MM $(CXXFLAGS) $*.cpp > $*.d
	@mv -f $*.d $*.d.tmp
	@sed -e 's|.*:|$*.o:|' < $*.d.tmp > $*.d
	@sed -e 's/.*://' -e 's/\\$$//' < $*.d.tmp | fmt -1 | \
		sed -e 's/^ *//' -e 's/$$/:/' >> $*.d
	@rm -f $*.d.tmp

clean:
	rm -rf *.o *.d ./modifier/*.o ./modifier/*.d $(PROGRAM_NAME)

.SECONDARY:
