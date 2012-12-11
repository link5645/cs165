COMPILER	= g++
FLAGS	 	= 
LIBRARIES	= -l ssl -l crypto

all: server/ssl_server.cpp client/ssl_client.cpp
	$(COMPILER) $(FLAGS) -o server/server_app server/ssl_server.cpp $(LIBRARIES)
	$(COMPILER) $(FLAGS) -o client/client_app client/ssl_client.cpp $(LIBRARIES)
clean:
	rm -rf client/client_app server/server_app client/*.*~ server/*.*~ client/simon.txt *.*~ *~

