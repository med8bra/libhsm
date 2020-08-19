CXX=g++
CXXFLAGS= -DOS_UNIX -O3 -Wall -Iinclude
LDFLAGS= 
SRC_DIR= src
OBJ_DIR= obj
LIB_DIR= lib
SRCs= $(addprefix $(SRC_DIR)/, p11hsm.cpp mechtype.cpp)
OBJs= $(SRCs:$(SRC_DIR)/%.cpp=$(OBJ_DIR)/%.o)
LIBs= $(addprefix $(LIB_DIR)/, libhsm.so)

all: $(LIBs)

$(LIB_DIR)/%.so: $(OBJs)
	@mkdir -p $(LIB_DIR)
	@echo 'Building shared lib: $@'
	@$(CXX) -shared -o $@ $^ $(LDFLAGS)
	@echo 'Finished building target: $@'
	@echo ' '

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(OBJ_DIR)
	@echo 'Building target: $@'
	@$(CXX) $(CXXFLAGS) -c $^ -o $@
	@echo 'Finished building target: $@'
	@echo ' '

.PHONY: clean
.PRECIOUS: $(OBJ_DIR)/%.o

clean:
	rm -rf $(OBJs) $(LIBs)

