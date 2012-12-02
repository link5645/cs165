COMPILER	= g++
FLAGS	 	= 
LIBRARIES	= -l ssl -l crypto

all: server/ssl_server.cpp client/ssl_client.cpp
	$(COMPILER) $(FLAGS) -o server_app server/ssl_server.cpp $(LIBRARIES)
	$(COMPILER) $(FLAGS) -o client_app client/ssl_client.cpp $(LIBRARIES)
clean:
	rm -rf client_app server_app *.*~ *~

