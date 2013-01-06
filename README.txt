CS165 Project
By Ryan Simon

To compile my programs, please use the provided make file. It will create a client_app and server_app executable files in the client and server folders, respectively. The client will save any file request to its own folder, and the server will only send files that are within its own folder as well.

To run the programs, use the following syntax:
client_app hostaddress:portnum filerequest
server_app portnum

There is a known issue with the program. For some reason strings with double 0's are not read completely. So the program crashes if either the client encryption and/or server encryption contains a string with two consecutive zeroes. This will cause a segmentation fault. The program will eventually process correctly IF neither encryption string contains consecutive zeroes.
