
#################################################################################################
#                                                                                               #
# Description:                                                                                  #
#     厦大海西通讯工程中心, Makefile格式以及源代码目录规范                                      #
#     $(PWD)                                                                                    #
#       |--src    源代码目录，src目录下以及一级子目录中的c文件参与编译                          #
#       |--objs   编译c源码文件生成.o文件目录                                                   #
#       |--bin    最终生成库文件或可执行文件                                                    #
#                                                                                               #
# Author：                                                                                      #
#     eric.woo (wadahana@gmail.com)                                                             #
#                                                                                               #
# Version:                                                                                      #
#     Ver0.1.0 2010-08-25  初次制定                                                             #
#     Ver0.2.0 2010-10-23  支持src下两级目录                                                	#
#     Ver0.3.0 2011-02-28  确定config.mk包含格式                                            	#
#     Ver0.4.0 2011-04-23  目标文件名由目录名生成                                             	#
#     Ver0.5.0 2011-06-22  增加连接外部库文件                                                	#
#     Ver0.6.0 2011-10-03  增加自动生成BIN目录和objs目录，增加对cpp文件和m文件的支持变量手工定义#
#     Ver0.7.0 2016-03-11  修改LDFLAGS 搬移到.o文件后面                                         #
#     V340.7.1 2016-03-24  增加jni和jni-clean支持                                               ＃
#################################################################################################

include config.mk

CFLAGS +=  -I$(SRC_DIR) -Wall
LDFLAGS +=

INC_DIR = ./inc
SRC_DIR = ./src
OBJ_DIR = ./objs
BIN_DIR = ./bin



######### 检查库文件或可执行文件名  ##########
ifndef EXEC
	EXEC = $(shell basename `pwd`)
endif


VPATH += $(SRC_SUB_DIRS)


SRC_SUB_DIRS = $(shell find $(SRC_DIR) -maxdepth 1 -type d)

#SRC_SUB_DIRS += $(SRC_DIR)


SRC += $(foreach path, $(SRC_SUB_DIRS), $(wildcard $(path)/*.c))
OBJS += $(foreach path, $(SRC_SUB_DIRS), $(patsubst $(path)/%.c, $(OBJ_DIR)/%.o, $(wildcard $(path)/*.c)))

CXXSRC += $(foreach path, $(SRC_SUB_DIRS), $(wildcard $(path)/*.cpp))
CXXOBJS += $(foreach path, $(SRC_SUB_DIRS), $(patsubst $(path)/%.cpp, $(OBJ_DIR)/%.o, $(wildcard $(path)/*.cpp)))

OOCSRC += $(foreach path, $(SRC_SUB_DIRS), $(wildcard $(path)/*.m))
OOCOBJS += $(foreach path, $(SRC_SUB_DIRS), $(patsubst $(path)/%.m, $(OBJ_DIR)/%.o, $(wildcard $(path)/*.m)))



all : __mkdir $(BIN_DIR)/$(EXEC)

jni:
	@echo '\n  [NDK-BUILD] '$(PWD)'\n\n';ndk-build NDK_PROJECT_PATH=. NDK_OUT=$(OBJ_DIR) NDK_LIBS_OUT=$(BIN_DIR) $(JNIFLAGS)

jni-clean:
	@echo '\n  [NDK-BUILD] clean'$(PWD)'\n\n';ndk-build clean NDK_PROJECT_PATH=. NDK_OUT=$(OBJ_DIR) NDK_LIBS_OUT=$(BIN_DIR) $(JNIFLAGS)

install :  all
	@echo '  [CP] '		$(BIN_DIR)/$(EXEC)  $(PREFIX)/bin/$(EXEC); cp -arp $(BIN_DIR)/$(EXEC)  $(PREFIX)/bin/$(EXEC)

__mkdir:
	@echo '  [MKDIR]  '$(BIN_DIR); mkdir -p $(BIN_DIR)
	@echo '  [MKDIR]  '$(OBJ_DIR); mkdir -p $(OBJ_DIR)

#upload: all
#	@echo '   [UPLOAD]  '$(BIN_DIR)/$(EXEC) ; $(BIN_DIR)/$(EXEC) root@$(DEVICE_IP):/Applications/ErPower_HD.app/

$(BIN_DIR)/$(EXEC)	: $(OBJS)	$(CXXOBJS)     $(OOCOBJS)
	@echo '  [LD]  '		$@ ;	$(LD) -o $@ $(OBJS) $(CXXOBJS) $(OOCOBJS) $(EXTRA_OBJS) $(LDFLAGS)


$(OBJS) : $(OBJ_DIR)/%.o : %.c
	@echo '  [CC]  '    $@ ;	$(CC) -c $(CFLAGS) -c $< -o $@


$(CXXOBJS) : $(OBJ_DIR)/%.o : %.cpp
	@echo '  [CC]  '    $@ ;	$(CC) -c $(CFLAGS) -c $< -o $@

$(OOCOBJS) : $(OBJ_DIR)/%.o : %.m
	@echo '  [OBJ-CC]  '    $@ ;	$(OBJCC) -c $(CFLAGS) -c $< -o $@

clean:
	@echo '  [RM]  '$(OBJS); rm -f $(OBJS)
	@echo '  [RM]  '$(CXXOBJS); rm -f $(CXXOBJS)
	@echo '  [RM]  '$(OOCOBJS); rm -f $(OOCOBJS)
	@echo '  [RM]  '$(BIN_DIR)/$(EXEC); rm -f $(BIN_DIR)/$(EXEC)
