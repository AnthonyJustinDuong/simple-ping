#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <math.h>
#include <errno.h>
#include <signal.h>

// IPv4
#define IPV4_HDR_SIZE 20
#define TTL_BYTE 8
// ICMP
#define ICMP_HDR_SIZE 8
#define TYPE 0
#define CODE 1
#define CHECKSUM 2
#define IDENTIFIER 4
#define SEQ_NUM 6

// Target host
char *hostname;
int soc_fd;
struct sockaddr *hostaddr;

// Options
int ttl = 255;
float interval = 1;
int packetsize = 56;

uint16_t uniq_id;
// Summary statistics
float min_time, max_time, total_time;
float sum_t2; 	// the sum of each time squared
				// used to calculate standard deviation
unsigned int nsent, nrecvd = 0; // counting packets sent and received

// Helper functions
void process_cmd_line_args(int argc, char **argv);
void get_host_address();
void set_signal_handlers();
void update_time_stats(float new_time);
uint16_t calculate_checksum(uint16_t *pckt, int byte_len);

void print_usage(char *prog_name) {
	fprintf(stderr, "Usage: %s [-i interval] [-t ttl] [-s packetsize] destination\n", prog_name);
	exit(2);
}

// Signal handlers
void send_packet(int sig); // ALRM signal for real itimer expiry
void sigint_h(int sig); // INT signal for program termination

int main(int argc, char **argv) {
	process_cmd_line_args(argc, argv);

	// Assigns <hostaddr> global var using <hostname>
	get_host_address();
	
	// Create raw socket with ICMP protocol
	soc_fd = socket(AF_INET, SOCK_RAW, 1);
	if (soc_fd < 0) {
		perror("socket");
		exit(2);
	}

	// Set the time-to-live
	if (setsockopt(soc_fd, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == -1) {
		perror("setsockopt");
		exit(2);
	}
	
	// Use this process id as the unique identifier for the packets
	uniq_id = getpid();
	
	set_signal_handlers();

	printf("PING %s %d(%d) bytes of data.\n", hostname, packetsize, packetsize + ICMP_HDR_SIZE + IPV4_HDR_SIZE);

	// Set up timer to send packets periodically
	struct itimerval timer;
	timer.it_interval.tv_sec = (int) interval;
	timer.it_interval.tv_usec = (int) ((interval - (int) interval) * 1000000);
	timer.it_value.tv_sec = 0;
	timer.it_value.tv_usec = 1;
	if (setitimer(ITIMER_REAL, &timer, NULL) == -1) {
		perror("setitimer");
		exit(2);
	}
	
	// Continually read for echo replies
	struct timeval end_time;
	uint8_t in_buf[IPV4_HDR_SIZE + ICMP_HDR_SIZE + packetsize];
	for (;;) {
		// Receive a reply
		int num_read = recv(soc_fd, in_buf, sizeof(in_buf), 0);
		if (errno == EINTR) {
			// The read call was interrupted by signal
			continue;
		}
		if (num_read < 0) {
			perror("recv");
			exit(2);
		}

		// Record the time that the reply was received
		if (gettimeofday(&end_time, NULL) == -1) {
			perror("gettimeofday");
			exit(2);
		}

		uint8_t recvd_type = in_buf[IPV4_HDR_SIZE + TYPE];
		uint16_t recvd_identifier = *(uint16_t *) (in_buf + IPV4_HDR_SIZE + IDENTIFIER);
		// Check if echo reply was for this unique process
		if (recvd_type != 0 || recvd_identifier != uniq_id) continue;

		nrecvd++;

		// Check if payload size fits timeval
		if (num_read - IPV4_HDR_SIZE - ICMP_HDR_SIZE >= sizeof(struct timeval)) {
			struct timeval *start_time = 
				(struct timeval *) (in_buf + IPV4_HDR_SIZE + ICMP_HDR_SIZE);

			// Calculate time taken for packet
			float time = 1000 * (end_time.tv_sec - start_time->tv_sec)
				+ (float) (end_time.tv_usec - start_time->tv_usec) 
				/ 1000; // in milliseconds

			update_time_stats(time);
			
			// Report round trip
			printf("%d bytes from %s: icmp_seq=%u ttl=%u time=%0.3f ms\n", 
					num_read, hostname, in_buf[IPV4_HDR_SIZE + SEQ_NUM],
					in_buf[TTL_BYTE], time);
		} else {
			// Report round trip
			printf("%d bytes from %s: icmp_seq=%u ttl=%u\n", 
					num_read, hostname, in_buf[IPV4_HDR_SIZE + SEQ_NUM],
					in_buf[TTL_BYTE]);
		}

	}

	// Should not reach here
	return 2;
}

/*
 * Signal handler to update and send a packet.
 */
void send_packet(int sig) {
	uint8_t packet[ICMP_HDR_SIZE + packetsize];

	// Prepare the packet to send
	packet[TYPE] = 8; // ICMP_ECHO Request type
	packet[CODE] = 0;
	*((uint16_t *) (packet + IDENTIFIER)) = uniq_id;
	*((uint16_t *) (packet + SEQ_NUM)) = nsent + 1;

	if (packetsize >= sizeof(struct timeval)) {
		// Place time at the beginning of the ICMP payload
		if (gettimeofday((struct timeval *) (packet + ICMP_HDR_SIZE), NULL) == -1) {
			perror("gettimeofday");
			exit(2);
		}

		// Zero the remaining payload
		for (int i = ICMP_HDR_SIZE + sizeof(struct timeval); i < sizeof(packet); i++) {
			packet[i] = 0;
		}
	} else {
		// Zero the remaining payload
		for (int i = ICMP_HDR_SIZE; i < sizeof(packet); i++) {
			packet[i] = 0;
		}
	}
	// Initial checksum is 0 for calculation
	*((uint16_t *) (packet + CHECKSUM)) = 0;
	*((uint16_t *) (packet + CHECKSUM)) = calculate_checksum((uint16_t *) packet, sizeof(packet));

	// Send the packet
	if (sendto(soc_fd, packet, sizeof(packet), 0,
				hostaddr, sizeof(*hostaddr)) == -1) {
		perror("sendto");
		exit(2);
	}
	nsent++;
}

/*
 * Signal handler to report summary statistics and
 * terminate the program.
 */
void sigint_h(int sig) {
	int exit_status = 0;
	printf("\n--- %s ping statistics ---\n", hostname);
	if (nrecvd == 0) {
		printf("%d packets transmitted, %d received, 100%% packet loss\n", 
				nsent, nrecvd);

		exit_status = 1;
	} else { // nrecvd != 0
		printf("%d packets transmitted, %d received, %.0f%% packet loss\n", 
				nsent, nrecvd, 100 - 100 * ((float) nrecvd / nsent));

		if (packetsize >= sizeof(struct timeval)) {
			float mean = total_time / nrecvd;
			printf("rtt min/avg/max/stddev = %0.3f/%0.3f/%0.3f/%0.3f ms\n", min_time, 
					mean, max_time, sqrtf((sum_t2 / nrecvd) - (mean * mean)));
		}
		exit_status = 0;
	}

	free(hostaddr);
	exit(exit_status);
}

/*
 * Processes command line arguments and validates
 * the inputs.
 */
void process_cmd_line_args(int argc, char **argv) {
	if (argc < 2 ) {
		print_usage(argv[0]);
	}

	// Process options
	int opt;
	while ((opt = getopt(argc, argv, "t:i:s:")) != -1) {
		switch (opt) {
			case 't': 
				ttl = atoi(optarg);
				if ((unsigned int) ttl > 255) {
					fprintf(stderr, "ttl %u out of range\n", ttl);
					exit(2);
				}
				break;
			case 'i':
				interval = strtof(optarg, NULL);
				if (interval < 0.2) {
					fprintf(stderr, "minimum interval allowed for user is 200ms\n");
					exit(2);
				}
				break;
			case 's':
				packetsize = atoi(optarg);
				if (packetsize < 0) {
					fprintf(stderr, "illegal negative packet size %d\n", packetsize);
					exit(2);
				} else if (packetsize > 65535 - ICMP_HDR_SIZE - IPV4_HDR_SIZE) {
					fprintf(stderr, "packet size %d is too large. Maximum is %d \n", 
							packetsize, 65535 - ICMP_HDR_SIZE - IPV4_HDR_SIZE);
					exit(2);
				}
				break;
			default:
				print_usage(argv[0]);
				break;
		}
	}

	// destination should be the only non-option arg
	if (optind != argc - 1) print_usage(argv[0]);
	hostname = argv[optind];
}
	
/*
 * Sets the <hostaddr> field to a valid adress
 * or terminates the program otherwise.
 */
void get_host_address() {
	// Prepare hint
	struct addrinfo hint;
	hint.ai_family = AF_INET;
	hint.ai_socktype = SOCK_RAW;
	hint.ai_protocol = 1;
	hint.ai_flags = 0;
	hint.ai_addrlen = 0;
	hint.ai_addr = NULL;
	hint.ai_canonname = NULL;
	hint.ai_next = NULL;

	// Get address of host
	struct addrinfo *res;
	int ret_get = getaddrinfo(hostname, NULL, &hint, &res);
	if (ret_get != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(ret_get));
		exit(2);
	}
	if (res == NULL) {
		fprintf(stderr, "%s: Name not known", hostname);
		exit(2);
	}

	// Dynamically allocate the socket address	
	hostaddr = malloc(sizeof(struct addrinfo));
	if (hostaddr == NULL) {
		perror("malloc");
		exit(2);
	}
	// Take the first result as the host address
	memmove(hostaddr, res[0].ai_addr, sizeof(struct addrinfo));

	// Free results
	freeaddrinfo(res);
}

/*
 * Set up handlers for the INT signal and ALRM signal.
 */
void set_signal_handlers() {
	// Set up handler for interrupt signal
	struct sigaction int_act;
	int_act.sa_handler = sigint_h;
	int_act.sa_flags = 0;
	sigemptyset(&(int_act.sa_mask));
	if (sigaction(SIGINT, &int_act, NULL) == -1) {
		perror("sigaction");
		exit(2);
	}

	// Set up handler for alrm signal (timer expiry)
	struct sigaction alrm_act;
	alrm_act.sa_handler = send_packet;
	alrm_act.sa_flags = SA_RESTART;
	sigemptyset(&(alrm_act.sa_mask));
	if (sigaction(SIGALRM, &alrm_act, NULL) == -1) {
		perror("sigaction");
		exit(2);
	}
}	

/*
 * Updates values necessary to calculate time statistics
 */
void update_time_stats(float new_time) {
	if (nrecvd == 1) {
		min_time = new_time;
		max_time = new_time;
		total_time = new_time;
		sum_t2 = new_time * new_time;
	} else {
		if (new_time < min_time) {
			min_time = new_time;
		}
		if (new_time > max_time) {
			max_time = new_time;
		}
		total_time += new_time;
		sum_t2 += (new_time * new_time);
	}
}

/*
 * Calculates the checksum of the packet.
 * algorithm from tools.ietf.org/html/rfc1071#section-4
 */
uint16_t calculate_checksum(uint16_t *pckt, int byte_len) {
	uint32_t sum = 0;
	
	// Calculuates the 16-bit one's complement sum
	// 1) Adds adjacent bytes to sum
	// Defers the adding the overflow
	for (int i = 0; i < byte_len / 2; i++) {
		sum += pckt[i];
	}

	// 2) Handle odd byte case
	if (byte_len % 2 == 1) {
		sum += *(uint8_t *) (pckt + (byte_len / 2));
	}

	// 3) Add overflows
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	// Compute one's complment of one's complement sum
	return (uint16_t) ~sum;
}
