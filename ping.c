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

#define IPV4_HDR_SIZE 20
#define TTL_BYTE 8

// Target host
char *hostname;
int soc_fd;
struct sockaddr *hostaddr;

// Options
int ttl = 255;
float interval = 1;
	
typedef struct {
	uint8_t type;
	uint8_t code;
	uint16_t checksum;
	uint16_t identifier;
	uint16_t sequence_number;
	struct timeval start_time;
} icmp_header_t;
// Packet ICMP header to send
icmp_header_t hdr;

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
void calculate_checksum(icmp_header_t *headr, int byte_len);

void print_usage(char *prog_name) {
	fprintf(stderr, "Usage: %s [-i interval] [-t ttl] destination\n", prog_name);
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
	
	uint16_t uniq_id = getpid();
	// Prepare the packet to send
	hdr.type = 8; 	// ICMP Echo Request
	hdr.code = 0;
	hdr.identifier = uniq_id; // Use pid as unique identifier
	hdr.sequence_number = 0;

	set_signal_handlers();
	
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
	uint8_t in_buf[IPV4_HDR_SIZE + sizeof(icmp_header_t)];
	icmp_header_t recvd_hdr;
	for (;;) {
		// Receive a reply
		int num_read = recv(soc_fd, in_buf, sizeof(in_buf), 0);
		if (errno == EINTR) {
			// Read call was interrupted by signal
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

		// The ICMP Header begins after the ipv4 header
		memmove(&recvd_hdr, in_buf + IPV4_HDR_SIZE, sizeof(recvd_hdr));

		// Check if echo reply was for this unique process
		if (recvd_hdr.type != 0 || recvd_hdr.identifier != uniq_id) continue;

		// Calculate time taken for packet
		float time = 1000 * (end_time.tv_sec - recvd_hdr.start_time.tv_sec)
			+ (float) (end_time.tv_usec - recvd_hdr.start_time.tv_usec) 
			/ 1000; // in milliseconds

		update_time_stats(time);
		
		// Report round trip
		printf("%d bytes from %s: icmp_seq=%u ttl=%u time=%0.3f ms\n", 
				num_read, hostname, recvd_hdr.sequence_number,
				in_buf[TTL_BYTE], time);
	}

	// Should not reach here
	return 2;
}

/*
 * Signal handler to update and send a packet.
 */
void send_packet(int sig) {
	// Update packet and record start time
	hdr.sequence_number++;
	if (gettimeofday(&(hdr.start_time), NULL) == -1) {
		perror("gettimeofday");
		exit(2);
	}
	calculate_checksum(&hdr, sizeof(hdr));

	// Send the packet
	if (sendto(soc_fd, &hdr, sizeof(hdr), 0,
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
	printf("%d packets transmitted, %d received\n", nsent, nrecvd);
	if (nrecvd == 0) {
		exit_status = 1;
	} else { // nrecvd != 0
		float mean = total_time / nrecvd;
		printf("rtt min/avg/max/stddev = %0.3f/%0.3f/%0.3f/%0.3f ms\n", 
				min_time, mean, max_time,
				sqrtf((sum_t2 / nrecvd) - (mean * mean)));
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
	while ((opt = getopt(argc, argv, "t:i:")) != -1) {
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
 * and increments <nrecvd>
 */
void update_time_stats(float new_time) {
	if (nrecvd == 0) {
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

	nrecvd++;
}

/*
 * Calculates the checksum of the packet and
 * updates the checksum field accordingly.
 * algorithm from tools.ietf.org/hml/rfc1071#section-4
 */
void calculate_checksum(icmp_header_t *headr, int byte_len) {
	headr->checksum = 0;
	uint16_t *pckt = (uint16_t *) headr;
	int32_t sum = 0;
	
	// Will defer the carry of the overflow
	for (int i = 0; i < byte_len / 2; i += 1) {
		sum += pckt[i];
	}

	if (byte_len % 2 == 1) {
		sum += *(uint8_t *) (pckt + byte_len - 1);
	}

	// Add overflows
	while (sum >> 16) {
		sum = (sum & 0xffff) + (sum >> 16);
	}

	headr->checksum = ~sum;
}
