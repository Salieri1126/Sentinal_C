MYSQL_CONFIG=${shell which mysql_config}
MYSQL_INC=${shell $(MYSQL_CONFIG) --cflags}
MYSQL_LIB=${shell $(MYSQL_CONFIG) --libs}

PATCH_PATH="patch_ips"

IPSMANAGER = dbms_ips_manager

#CFLAGS      = -O2 -D_REENTRANT -Wall -Wno-write-strings -I include -I/usr/include/pcap -I/usr/local/include/mysql -I/usr/include/mysql ${MYSQL_INC}
CFLAGS      = -pg -D_REENTRANT -Wall -Wno-write-strings -I include -I/usr/include/pcap -I/usr/local/include/mysql -I/usr/include/mysql ${MYSQL_INC}
#CFLAGS      = -p -D_REENTRANT -Wall -Wno-write-strings -I include -I/usr/include/pcap -I/usr/local/include/mysql -I/usr/include/mysql ${MYSQL_INC}
#CFLAGS      = -Wl,--no-as-needed,-lprofiler,--as-needed -pg -D_REENTRANT -Wall -Wno-write-strings -I include -I/usr/include/pcap -I/usr/local/include/mysql -I/usr/include/mysql ${MYSQL_INC}


############### Linux
CC          = g++
OS          = _LINUX_MACHINE 
LIBS        = -lpthread ${MYSQL_LIB}

all: delpro $(IPSMANAGER)

delpro: 
	@rm -f $(IPSMANAGER)

clean:
	@rm -f $(OBJS) $(IPSMANAGER) *.o *.tmp
	@rm -rf ${PATCH_PATH}
	@exit;

$(IPSMANAGER):
	@if test "`uname`" = "Linux"; then  \
		$(CC) $(CFLAGS) -D_LINUX_MACHINE -o $(IPSMANAGER) -DIPS_MANAGER_NAME=\"$(IPSMANAGER)\" *.cpp $(LIBS) -lpcap; \
	else  \
		$(CC) $(CFLAGS) -o $(IPSMANAGER) -DIPS_MANAGER_NAME=\"$(IPSMANAGER)\" *.cpp $(LIBS) -lwpcap -lz -lcrypt -lm; \
	fi; \
	mkdir ${PATCH_PATH} 2> /dev/null; \
	mkdir ${PATCH_PATH}/locale 2> /dev/null; \
	cp locale/* ${PATCH_PATH}/locale 2> /dev/null; \
	cp -pf $(IPSMANAGER) ${PATCH_PATH} 2> /dev/null; \
	#chmod +x patch.sh; \
	#cp -pf patch.sh ${PATCH_PATH} 2> /dev/null; 

.SUFFIXES: .cpp .c .o
.cpp .c.o:
	@if test "`uname`" = "Linux"; then  \
		$(CC) $(CFLAGS) $(LIBS) -D_LINUX_MACHINE -c $< \
	else  \
		$(CC) $(CFLAGS) $(LIBS) -c $< \
	fi
