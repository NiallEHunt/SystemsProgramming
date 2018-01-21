#include "knock.h"

bool hflag, pflag, wflag, fflag;
int sock, portno, result;
struct sockaddr_in serv_addr;
struct hostent *server;
char buffer[1000];
char *hostname;
ofstream outputFile;


int main(int argc, char *argv[])
{
	processArguments(argc, argv);

	sock = socket(AF_INET, SOCK_STREAM, 0);

	if(sock < 0)
	{
		fprintf(stderr, "ERROR opening socket\n");
		exit(1);
	}

	if(server == NULL)
	{
		fprintf(stderr, "ERROR no such host\n");
		exit(1);
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;
	bcopy((char *) server->h_addr, (char *) &serv_addr.sin_addr.s_addr, server->h_length);
	serv_addr.sin_port = htons(portno);

	if(connect(sock, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0)
	{
		fprintf(stderr, "ERROR connecting\n");
		exit(1);
	}

	bzero(buffer, 1000);

	char tmpBuf[1000];
	if(wflag)
		sprintf(tmpBuf, "GET / \r\n\r\n");
	else
		sprintf(tmpBuf, "GET / HTTP/1.1\r\n"
						"HOST: %s\r\n"
						"\r\n", hostname);

	memcpy(buffer, tmpBuf, 1000);

	result = write(sock, buffer, strlen(buffer));
	if(result < 0)
	{
		fprintf(stderr, "ERROR writing to socket\n");
		exit(1);
	}

	bzero(buffer, 1000);

	result = read(sock, buffer, 999);
	if(result < 0)
	{
		fprintf(stderr, "ERROR reading from socket\n");
		exit(1);
	}

	if(!fflag)
		printf("%s\n", buffer);
	else
	{
		outputFile << buffer;
		outputFile.close();
	}
	close(sock);

	return 0;
}

void usage(int n)
{
	fprintf((n < 2)? stderr: stdout,
		"usage: ./knock -h host -p port [-H] [-w] [-f file]\n\n"
		"Knock needs at least a host and a port as arguments\n");

	if(n < 2)
		return;
	fprintf(stdout, "\t------ Listing options ------\n"
		  "-h -host			The host address to knock\n"
		  "-p -port			The port number of the host to knock\n"
		  "-w -web				Make an HTTP GET request for the '/' resource\n"
		  "-f -file filename		A file to write the response to\n"
		  "-H -? -help			Print usage and exit\n");
	exit(0);
}

void processArguments(int argc, char *argv[])
{
	if(argc < 2)
	{
		usage(1);
		exit(1);
	}

	int n;
	for(int i = n = 0;(i < argc);i = n)
	{
		n++;

		if(argv[i][0] == '-' && argv[i][1])
		{
			for(int j = 1;(argv[i][j]);j++)
			{
				switch(argv[i][j])
				{
				case 'H':
				case '?':
					if(argv[i][j + 1] && strcmp("-Help", argv[i]))
					{
						usage(1);
						exit(1);
					}

					usage(2);
					exit(0);
					break;
				case 'h':
					if(argv[i][j + 1] && strcmp("-host", argv[i]))
					{
						usage(1);
						exit(1);
					}

					hflag = true;

					if(argv[n] == NULL || argv[n][0] == '-')
					{
						fprintf(stderr, "ERROR: Missing argument to -h option\n");
						usage(1);
						exit(1);
					}

					hostname = argv[n];
					server = gethostbyname(argv[n++]);
					break;
				case 'p':
					if(argv[i][j + 1] && strcmp("-port", argv[i]))
					{
						usage(1);
						exit(1);
					}

					pflag = true;

					if(argv[n] == NULL || argv[n][0] == '-')
					{
						fprintf(stderr, "ERROR: Missing argument to -p option\n");
						usage(1);
						exit(1);
					}

					portno = atoi(argv[n++]);
					break;
				case 'w':
					if(argv[i][j + 1] && strcmp("-web", argv[i]))
					{
						usage(1);
						exit(1);
					}
					wflag = true;
					break;
				case 'f':
					if(argv[i][j + 1] && strcmp("-file", argv[i]))
					{
						usage(1);
						exit(1);
					}

					fflag = true;

					if(argv[n] == NULL || argv[n][0] == '-')
					{
						fprintf(stderr, "ERROR: Missing argument to -f option\n");
						usage(1);
						exit(1);
					}

					outputFile.open(argv[n++]);

					break;
				default:
					usage(1);
					exit(1);
					break;
				}
			}
		}
	}

	if(!hflag || !pflag)
	{
		usage(1);
		exit(1);
	}
}