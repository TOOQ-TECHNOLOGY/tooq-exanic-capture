#include <string.h>
#include <ctype.h>
#include <signal.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <limits.h>
#include <fcntl.h>
#include <getopt.h>
#include <time.h>
#include <endian.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <arpa/inet.h>

#include <exanic/exanic.h>
#include <exanic/config.h>
#include <exanic/port.h>
#include <exanic/fifo_rx.h>
#include <exanic/time.h>
#include <exanic/filter.h>

#include "pcap-structures.h"
#include "ptp_clock.h"

typedef enum {
    FORMAT_PCAP = 0,
    FORMAT_ERF = 1,
} file_format_type;

volatile sig_atomic_t run = 1;
static int durable = 0;
static struct ptp_clock ptp = {.fd = -1};

void signal_handler(int signum) {
    (void)signum;
    run = 0;
}

static int parse_number(const char *s, unsigned long min, unsigned long max, unsigned long *out) {
    char *end;
    errno = 0;
    if (!s || !isdigit((unsigned char)*s)) return -1;
    unsigned long value = strtoul(s, &end, 10);
    if (errno || *end || value < min || value > max) return -1;
    *out = value;
    return 0;
}

static int write_exact(FILE *fp, const void *data, size_t size) {
    if (fwrite(data, 1, size, fp) != size || ferror(fp)) {
        if (!errno) errno = EIO;
        perror("capture write");
        return -1;
    }
    return 0;
}

static int rotation_due(unsigned long size, unsigned long header, size_t record,
                        unsigned long limit, unsigned int seconds, time_t now, time_t next) {
    return (seconds && now >= next) ||
           (limit && size > header && (size >= limit || record > limit - size));
}


/* Parses a string of the format "<device>:<port>" */
int parse_device_port(const char *str, char *device, int *port_number) {
    const char *p;
    unsigned long value;
    p = strchr(str, ':');
    if (p == NULL) return -1;
    if (p == str || (p-str) >= 16) return -1;
    strncpy(device, str, p - str);
    device[p - str] = '\0';
    if (parse_number(p + 1, 0, INT_MAX, &value)) return -1;
    *port_number = (int)value;
    return 0;
}

int parse_one_filter(char ***argv, int *argc, exanic_ip_filter_t *filter, int *bidir) {
    struct in_addr ip_addr;
    unsigned long port;
    int host_specified = 0, dst_specified = 0, src_specified = 0;
    int port_specified = 0, dport_specified = 0, sport_specified = 0;
    int proto_specified = 0;
    memset(filter, 0, sizeof(*filter));

    while (*argc) {
        if (strcmp((*argv)[0], "host") == 0) {
            if (host_specified) return 0;
            if (dst_specified || src_specified || dport_specified || sport_specified) return 0;
            (*argv)++; (*argc)--;
            if (!*argc || inet_aton((*argv)[0], &ip_addr) == 0) return 0;
            filter->dst_addr = ip_addr.s_addr;
            (*argv)++; (*argc)--;
            host_specified = 1;
        }
        else if (strcmp((*argv)[0], "dst") == 0) {
            if (dst_specified) return 0;
            if (host_specified || port_specified) return 0;
            (*argv)++; (*argc)--;
            if (!*argc || inet_aton((*argv)[0], &ip_addr) == 0) return 0;
            filter->dst_addr = ip_addr.s_addr;
            (*argv)++; (*argc)--;
            dst_specified = 1;
        }
        else if (strcmp((*argv)[0], "src") == 0) {
            if (src_specified) return 0;
            if (host_specified || port_specified) return 0;
            (*argv)++; (*argc)--;
            if (!*argc || inet_aton((*argv)[0], &ip_addr) == 0) return 0;
            filter->src_addr = ip_addr.s_addr;
            (*argv)++; (*argc)--;
            src_specified = 1;
        }
        else if (strcmp((*argv)[0], "port") == 0) {
            if (port_specified) return 0;
            if (dst_specified || src_specified || dport_specified || sport_specified) return 0;
            (*argv)++; (*argc)--;
            if (!*argc) return 0;
            if (parse_number((*argv)[0], 0, 65535, &port)) return 0;
            filter->dst_port = htons((uint16_t)port);
            (*argv)++; (*argc)--;
            port_specified = 1;
        }
        else if (strcmp((*argv)[0], "dport") == 0) {
            if (dport_specified) return 0;
            if (host_specified || port_specified) return 0;
            (*argv)++; (*argc)--;
            if (!*argc) return 0;
            if (parse_number((*argv)[0], 0, 65535, &port)) return 0;
            filter->dst_port = htons((uint16_t)port);
            (*argv)++; (*argc)--;
            dport_specified = 1;
        }
        else if (strcmp((*argv)[0], "sport") == 0) {
            if (sport_specified) return 0;
            if (host_specified || port_specified) return 0;
            (*argv)++; (*argc)--;
            if (!*argc) return 0;
            if (parse_number((*argv)[0], 0, 65535, &port)) return 0;
            filter->src_port = htons((uint16_t)port);
            (*argv)++; (*argc)--;
            sport_specified = 1;
        }
        else if (strcmp((*argv)[0], "tcp") == 0) {
            if (proto_specified) return 0;
            filter->protocol = 6;
            (*argv)++; (*argc)--;
            proto_specified = 1;
        }
        else if (strcmp((*argv)[0], "udp") == 0) {
            if (proto_specified) return 0;
            filter->protocol = 17;
            (*argv)++; (*argc)--;
            proto_specified = 1;
        }
        else if (strcmp((*argv)[0], "or") == 0) {
            if (!(host_specified || dst_specified || src_specified || port_specified ||
                  dport_specified || sport_specified || proto_specified) || *argc == 1) return 0;
            (*argv)++; (*argc)--;
            *bidir = host_specified || port_specified;
            return 1;
        }
        else return 0;
    }

    *bidir = host_specified || port_specified;
    return (*argc == 0);
}

int apply_filters(exanic_t *exanic, exanic_rx_t *rx, char **argv, int argc) {
    exanic_ip_filter_t filter;
    int bidir;
    while (argc && parse_one_filter(&argv, &argc, &filter, &bidir)) {
        int ret = exanic_filter_add_ip(exanic, rx, &filter);
        if ((ret != -1) && bidir) {
            filter.src_addr = filter.dst_addr;
            filter.dst_addr = 0;
            filter.src_port = filter.dst_port;
            filter.dst_port = 0;
            ret = exanic_filter_add_ip(exanic, rx, &filter);
        }
        if (ret == -1) {
            fprintf(stderr, "error adding filter: %s\n", exanic_get_last_error());
            return 0;
        }
    }
    if (argc != 0) {
        fprintf(stderr, "parse error near %s\n", argv[0]);
        return 0;
    }
    return 1;
}

int write_pcap_header(FILE *fp, int nsec_pcap, int snaplen) {
    struct pcap_file_header hdr;
    hdr.magic = nsec_pcap ? NSEC_TCPDUMP_MAGIC : TCPDUMP_MAGIC;
    hdr.version_major = PCAP_VERSION_MAJOR;
    hdr.version_minor = PCAP_VERSION_MINOR;
    hdr.thiszone = 0;
    hdr.sigfigs = 0; /* 9? libpcap always writes 0 */
    hdr.snaplen = snaplen;
    hdr.linktype = DLT_EN10MB;

    if (write_exact(fp, &hdr, sizeof(hdr)) != 0) return -1;
    return sizeof(hdr);
}

int write_pcap_packet(char *data, ssize_t len, struct exanic_timespecps *tsps, int nsec_pcap, int snaplen, FILE *fp) {
    struct pcap_pkthdr hdr;
    ssize_t caplen = (len > snaplen) ? snaplen : len;

    hdr.ts_sec = tsps->tv_sec;
    hdr.ts_usec = nsec_pcap ? (tsps->tv_psec / 1000) : (tsps->tv_psec/1000/1000);
    hdr.caplen = caplen;
    hdr.len = len;

    if (write_exact(fp, &hdr, sizeof(hdr)) != 0 ||
        write_exact(fp, data, caplen) != 0) return -1;
    return sizeof(hdr) + caplen;
}

/* https://wiki.wireshark.org/ERF */
struct erf_record {
    uint32_t ts_frac;
    uint32_t ts_sec;
    uint8_t type;
    uint8_t flags;
    uint16_t rlen;
    uint16_t lctr;
    uint16_t wlen;
    uint16_t eth_pad;
};

int write_erf_packet(char *data, ssize_t len, struct exanic_timespecps *tsps, int port, int snaplen, FILE *fp) {
    struct erf_record hdr;
    const size_t size_hdr = 18;

    // times in little endian
    hdr.ts_sec = htole32(tsps->tv_sec);

    /* convert to 32 bit binary fraction of a second
     * (ps << 32) / 10**12 => (ps << 20) / 244140625 */
    const uint64_t ps = tsps->tv_psec;
    const uint32_t erfbinfrac = (ps << 20) / 244140625;
    hdr.ts_frac = htole32(erfbinfrac);

    hdr.type = 2;          // type ETH with no extension header
    hdr.flags = 1 << 2;    // variable length record
    hdr.flags |= (port & 0x3);

    ssize_t caplen = (len > snaplen) ? snaplen : len;
    hdr.rlen = htons(caplen + size_hdr);
    hdr.lctr = 0;
    hdr.wlen = htons(len);
    hdr.eth_pad = 0;

    if (write_exact(fp, &hdr, size_hdr) != 0 ||
        write_exact(fp, data, caplen) != 0) return -1;
    return size_hdr + caplen;
}

void print_time(struct exanic_timespecps *tsps) {
    struct tm tm;
    time_t seconds = tsps->tv_sec;
    if (!localtime_r(&seconds, &tm)) return;
    printf("%04d%02d%02dT%02d%02d%02d.%012ld ",
           tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
           tm.tm_hour, tm.tm_min, tm.tm_sec,
           tsps->tv_psec);
}

void print_hexdump(char *data, int len) {
    char ascii[16];
    int i, rem;

    for (i = 0; i < len; ) {
        if ((i % 16) == 0) printf("%04x: ", i);

        printf("%02x", (unsigned char)data[i]);
        if (isprint((unsigned char)data[i])) ascii[i%16] = data[i];
        else ascii[i%16] = '.';
        i++;

        if ((i % 2) == 0) printf(" ");
        if ((i % 16) == 0) printf(" %.16s\n", ascii);
    }

    rem = i % 16;
    if (rem) printf("%*.*s\n", 2*(16-rem)+((16-rem+1)/2)+rem+1, rem, ascii);
}

/* Use the library's post-copy overflow check and discard damaged frames. */
ssize_t exanic_receive_frame_ex(exanic_rx_t *rx, char *buf, size_t size,
                              uint32_t *timestamp, int *status) {
    ssize_t n = exanic_receive_frame(rx, buf, size, timestamp);
    *status = n < 0 ? (int)-n : EXANIC_RX_FRAME_OK;
    return n == 0 ? -1 : n;
}

static int set_promiscuous_mode(exanic_t *exanic, int port_number, int enable) {
    struct ifreq ifr;
    int fd, ret;

    memset(&ifr, 0, sizeof(ifr));
    if (exanic_get_interface_name(exanic, port_number, ifr.ifr_name, sizeof(ifr.ifr_name)) == -1) {
        fprintf(stderr, "%s:%d: %s\n", exanic->name, port_number, exanic_get_last_error());
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd == -1) {
        fprintf(stderr, "Socket creation failed \n");
        return -1;
    }

    ret = ioctl(fd, SIOCGIFFLAGS, &ifr);
    if (ret != -1) {
        if (enable) ifr.ifr_flags |= IFF_PROMISC;
        else ifr.ifr_flags &= ~IFF_PROMISC;
        ret = ioctl(fd, SIOCSIFFLAGS, &ifr);
    }
    close(fd);

    if (ret == -1) {
        fprintf(stderr, "failed to %s promiscuous mode (%s)%s\n",
                enable ? "enable" : "disable",
                strerror(errno),
                enable ? ", continuing anyway" : "");
        return -1;
    }
    return 0;
}

static int ensure_dir(const char *path)
{
    if (!path || !*path) return 0;
    struct stat st;
    if (stat(path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) return 0;
        fprintf(stderr, "Path exists and is not a directory: %s\n", path);
        return -1;
    }
    if (mkdir(path, 0755) == -1) {
        if (errno != EEXIST || stat(path, &st) != 0 || !S_ISDIR(st.st_mode)) {
            perror(path);
            return -1;
        }
    }
    return 0;
}


static const char* path_basename(const char* path) {
    const char* slash = strrchr(path, '/');
    return slash ? slash + 1 : path;
}

static void path_dirname_into(const char* path, char* out, size_t out_sz) {
    const char* slash = strrchr(path, '/');
    if (!slash) { snprintf(out, out_sz, "."); return; }
    size_t len = (size_t)(slash - path);
    if (len == 0) len = 1;
    if (len >= out_sz) len = out_sz - 1;
    memcpy(out, path, len);
    out[len] = '\0';
}

static void split_base_ext(const char* fname, char* base, size_t base_sz, char* ext, size_t ext_sz, file_format_type fmt) {
    const char* dot = strrchr(fname, '.');
    if (dot && dot != fname) {
        size_t blen = (size_t)(dot - fname);
        if (blen >= base_sz) blen = base_sz - 1;
        memcpy(base, fname, blen);
        base[blen] = '\0';
        snprintf(ext, ext_sz, "%s", dot + 1);
    } else {
        snprintf(base, base_sz, "%s", fname);
        snprintf(ext,  ext_sz,  "%s", (fmt == FORMAT_ERF) ? "erf" : "pcap");
    }
}
/* Publish only a successfully closed stream. Never replace an existing capture. */
static int finish_file_impl(FILE **fp, const char *final_name) {
    if (!*fp) return 0;
    FILE *stream = *fp;
    *fp = NULL;
    int failed = ferror(stream) != 0;
    if (fflush(stream) != 0) { perror("capture flush"); failed = 1; }
    if (!failed && durable && fsync(fileno(stream)) != 0) {
        perror("capture fsync"); failed = 1;
    }
    if (fclose(stream) != 0) { perror("capture close"); failed = 1; }
    if (failed) return -1;
    if (!final_name || !*final_name) return 0;
    char part[4101];
    if (snprintf(part, sizeof(part), "%s.part", final_name) >= (int)sizeof(part)) return -1;
    /* Hard linking within the same directory publishes atomically without clobbering. */
    if (link(part, final_name) != 0) { perror("publish capture"); return -1; }
    if (unlink(part) != 0) { perror("remove published .part"); return -1; }
    if (durable) {
        char dir[4096];
        path_dirname_into(final_name, dir, sizeof(dir));
        int fd = open(dir, O_RDONLY | O_DIRECTORY);
        if (fd < 0) { perror("open capture directory"); return -1; }
        int rc = fsync(fd);
        if (rc != 0) perror("directory fsync");
        if (close(fd) != 0) { perror("directory close"); return -1; }
        if (rc != 0) return -1;
    }
    fprintf(stderr, "Finalizado: %s\n", final_name);
    return 0;
}

static int finish_file(FILE **fp, const char *final_name) {
    int had_file = *fp != NULL;
    int result = finish_file_impl(fp, final_name);
    if (had_file) ptp_audit_close(&ptp, result == 0);
    return result;
}

static int rotate_file(
    FILE **savefp, const char *savefile,
    char *file_name_buf, size_t file_name_buf_size,
    file_format_type file_format, int nsec_pcap, int snaplen,
    unsigned long *file_size, int *file_no, const char *repo_dir
) {
    if (finish_file(savefp, file_name_buf) != 0) return -1;
    char out_dir[4096];
    if (strchr(savefile, '/')) path_dirname_into(savefile, out_dir, sizeof(out_dir));
    else if (repo_dir && *repo_dir) {
        if (snprintf(out_dir, sizeof(out_dir), "%s", repo_dir) >= (int)sizeof(out_dir)) {
            fprintf(stderr, "Directory path too long\n"); return -1;
        }
    } else snprintf(out_dir, sizeof(out_dir), ".");
    if (ensure_dir(out_dir) != 0) return -1;

    const char *fname = path_basename(savefile);
    char base[4096], ext[4096], part[4101];
    if (!*fname || strlen(fname) >= sizeof(base)) {
        fprintf(stderr, "Invalid capture filename\n"); return -1;
    }
    split_base_ext(fname, base, sizeof(base), ext, sizeof(ext), file_format);
    for (;;) {
        if (*file_no == INT_MAX) { fprintf(stderr, "Capture index exhausted\n"); return -1; }
        ++*file_no;
        if (snprintf(file_name_buf, file_name_buf_size, "%s/%s%d.%s",
                     out_dir, base, *file_no, ext) >= (int)file_name_buf_size ||
            snprintf(part, sizeof(part), "%s.part", file_name_buf) >= (int)sizeof(part)) {
            fprintf(stderr, "Filename too long\n"); return -1;
        }
        struct stat st;
        if (lstat(file_name_buf, &st) == 0) continue;
        if (errno != ENOENT) { perror(file_name_buf); return -1; }
        *savefp = fopen(part, "wbx");
        if (*savefp) break;
        if (errno != EEXIST) { perror(part); return -1; }
    }
    /* Larger buffering reduces syscall overhead; errors are checked at finalization. */
    static char output_buffer[1024 * 1024];
    if (setvbuf(*savefp, output_buffer, _IOFBF, sizeof(output_buffer)) != 0) {
        fprintf(stderr, "Cannot configure capture buffering\n"); return -1;
    }
    *file_size = 0;
    if (file_format == FORMAT_PCAP) {
        int n = write_pcap_header(*savefp, nsec_pcap, snaplen);
        if (n < 0) return -1;
        *file_size = (unsigned long)n;
    }
    fprintf(stderr, "Capturando em: %s\n", part);
    ptp_audit_open(&ptp, file_name_buf);
    return 0;
}

int main(int argc, char *argv[]) {
    const char *interface = NULL;
    const char *savefile = NULL;
    FILE *savefp = NULL;

    char device[16];
    int port_number;
    exanic_t *exanic;
    exanic_rx_t *rx;
    char rx_buf[16384];
    ssize_t rx_size;
    int status;
    exanic_cycles32_t timestamp;
    struct timespec ts;
    struct exanic_timespecps tsps;

    int hw_tstamp = 0, nsec_pcap = 0, snaplen = sizeof(rx_buf), flush = 0;
    int promisc = 1, set_promisc = 0, filter;

    unsigned long rx_success = 0, rx_aborted = 0, rx_corrupt = 0, rx_hwovfl = 0, rx_swovfl = 0, rx_other = 0;
    file_format_type file_format = FORMAT_PCAP;

    int file_no = 0;
    unsigned long file_size = 0, file_size_limit = 0;
    char file_name_buf[4096] = "";
    int c;

    unsigned int rotate_seconds = 0;
    time_t next_rotation_time = 0;
    unsigned long number;
    const char *repo_dir = NULL;
    struct ptp_config ptp_config = {
        .tai_offset = -1, .max_offset_ns = 1000, .stale_seconds = 5,
        .expected_domain = -1,
    };
    int scale_given = 0, ptp_options = 0;
    enum { OPT_PTP = 256, OPT_SCALE, OPT_TAI_OFFSET, OPT_STATUS_SOCKET,
           OPT_MAX_OFFSET, OPT_STALE, OPT_CLOCK_ID, OPT_GM, OPT_DOMAIN, OPT_AUDIT };
    static const struct option long_options[] = {
        {"ptp", no_argument, NULL, OPT_PTP},
        {"ptp-audit", required_argument, NULL, OPT_AUDIT},
        {"hw-clock-scale", required_argument, NULL, OPT_SCALE},
        {"tai-offset", required_argument, NULL, OPT_TAI_OFFSET},
        {"ptp-status-socket", required_argument, NULL, OPT_STATUS_SOCKET},
        {"ptp-max-offset-ns", required_argument, NULL, OPT_MAX_OFFSET},
        {"ptp-stale-seconds", required_argument, NULL, OPT_STALE},
        {"ptp-clock-id", required_argument, NULL, OPT_CLOCK_ID},
        {"ptp-expected-gm", required_argument, NULL, OPT_GM},
        {"ptp-domain", required_argument, NULL, OPT_DOMAIN},
        {NULL, 0, NULL, 0},
    };

    while ((c = getopt_long(argc, argv, "i:w:s:C:F:pHNDG:R:h?", long_options, NULL)) != -1) {
        switch (c) {
            case OPT_PTP: ptp_config.enabled = 1; break;
            case OPT_AUDIT:
                if (strcmp(optarg, "on") && strcmp(optarg, "off")) goto usage_error;
                ptp_config.disable_audit = !strcmp(optarg, "off");
                ptp_options = 1; break;
            case OPT_SCALE:
                if (strcmp(optarg, "tai") && strcmp(optarg, "utc")) goto usage_error;
                ptp_config.tai = !strcmp(optarg, "tai");
                scale_given = ptp_options = 1; break;
            case OPT_TAI_OFFSET:
                if (!strcmp(optarg, "kernel")) ptp_config.tai_offset = -1;
                else {
                    if (parse_number(optarg, 1, 1000, &number)) goto usage_error;
                    ptp_config.tai_offset = (int)number;
                }
                ptp_options = 1; break;
            case OPT_STATUS_SOCKET: ptp_config.socket_path = optarg; ptp_options = 1; break;
            case OPT_MAX_OFFSET:
                if (parse_number(optarg, 0, INT_MAX, &number)) goto usage_error;
                ptp_config.max_offset_ns = (int64_t)number; ptp_options = 1; break;
            case OPT_STALE:
                if (parse_number(optarg, 1, 3600, &number)) goto usage_error;
                ptp_config.stale_seconds = (unsigned)number; ptp_options = 1; break;
            case OPT_CLOCK_ID: ptp_config.clock_id = optarg; ptp_options = 1; break;
            case OPT_GM: ptp_config.expected_gm = optarg; ptp_options = 1; break;
            case OPT_DOMAIN:
                if (parse_number(optarg, 0, 255, &number)) goto usage_error;
                ptp_config.expected_domain = (int)number; ptp_options = 1; break;
            case 'i': interface = optarg; break;
            case 'w': savefile = optarg; break;
            case 's':
                if (parse_number(optarg, 1, sizeof(rx_buf), &number)) goto usage_error;
                snaplen = (int)number; break;
            case 'C': /* as per tcpdump */
                if (parse_number(optarg, 1, ULONG_MAX / 1000000UL, &number)) goto usage_error;
                file_size_limit = 1000000UL * number;
                break;
            case 'F': /* formats as per editcap */
                if (strcmp(optarg, "pcap") == 0) file_format = FORMAT_PCAP;
                else if (strcmp(optarg, "erf") == 0) file_format = FORMAT_ERF;
                else goto usage_error;
                break;
            case 'G':
                if (parse_number(optarg, 1, INT_MAX, &number)) goto usage_error;
                rotate_seconds = (unsigned int)number; break;
            case 'D': durable = 1; break;
            case 'p': promisc = 0; break;
            case 'H': hw_tstamp = 1; break;
            case 'N': nsec_pcap = 1; break;
            case 'R': repo_dir = optarg; break;
            default: goto usage_error;
        }
    }
    if (interface == NULL) goto usage_error;
    if (ptp_options && !ptp_config.enabled) goto usage_error;
    if (ptp_config.enabled) {
        if (!scale_given || (!ptp_config.tai && ptp_config.tai_offset >= 0)) goto usage_error;
        hw_tstamp = nsec_pcap = 1;
    }
    if ((!savefile || strcmp(savefile, "-") == 0) &&
        (rotate_seconds || file_size_limit || durable || repo_dir)) goto usage_error;

    if (exanic_find_port_by_interface_name(interface, device, 16, &port_number) != 0 &&
        parse_device_port(interface, device, &port_number) != 0) {
        fprintf(stderr, "%s: no such interface or not an ExaNIC\n", interface);
        return 1;
    }

    if (!ptp_config.clock_id) ptp_config.clock_id = device;
    if (ptp_clock_init(&ptp, &ptp_config)) return 1;

    if (savefile != NULL) {
        if (strcmp(savefile, "-") == 0) {
            savefp = stdout;
            flush = 1;
            if (file_format == FORMAT_PCAP && write_pcap_header(savefp, nsec_pcap, snaplen) < 0)
                goto err_acquire_handle;
        } else {
            file_name_buf[0] = '\0';
            if (rotate_file(&savefp, savefile, file_name_buf, sizeof(file_name_buf),
                            file_format, nsec_pcap, snaplen, &file_size, &file_no, repo_dir) != 0)
                goto err_acquire_handle;

            if (rotate_seconds > 0) {
                if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
                    perror("clock_gettime"); goto err_acquire_handle;
                }
                next_rotation_time = ts.tv_sec + rotate_seconds;
            }
        }
    }

    /* Get the exanic handle */
    exanic = exanic_acquire_handle(device);
    if (exanic == NULL) {
        fprintf(stderr, "%s: %s\n", device, exanic_get_last_error());
        goto err_acquire_handle;
    }
    if (hw_tstamp && exanic->tick_hz == 0) {
        fprintf(stderr, "Hardware timestamp clock unavailable\n");
        goto err_acquire_rx;
    }

    filter = optind < argc;
    if (filter)
        rx = exanic_acquire_unused_filter_buffer(exanic, port_number);
    else
        rx = exanic_acquire_rx_buffer(exanic, port_number, 0);

    if (rx == NULL) {
        fprintf(stderr, "%s:%d: %s\n", device, port_number, exanic_get_last_error());
        goto err_acquire_rx;
    }

    if (filter && !apply_filters(exanic, rx, &argv[optind], argc - optind))
        goto err_apply_filters;

    set_promisc = promisc && !exanic_get_promiscuous_mode(exanic, port_number);

    struct sigaction action = {0};
    action.sa_handler = signal_handler;
    sigemptyset(&action.sa_mask);
    const int signals[] = {SIGHUP, SIGINT, SIGPIPE, SIGALRM, SIGTERM};
    for (size_t i = 0; i < sizeof(signals) / sizeof(signals[0]); ++i) {
        if (sigaction(signals[i], &action, NULL) != 0) {
            perror("sigaction"); goto err_apply_filters;
        }
    }

    if (set_promisc) {
        if (set_promiscuous_mode(exanic, port_number, 1) == -1)
            set_promisc = 0;
    }
    
    /* Start reading from the rx buffer */
    unsigned int poll_counter = 0;
    while (run) {
        if (ptp_config.enabled && (poll_counter++ & 1023U) == 0) {
            ptp_clock_poll(&ptp);
            ptp_audit_event(&ptp);
        }
        rx_size = exanic_receive_frame_ex(rx, rx_buf, sizeof(rx_buf), &timestamp, &status);
        if (rx_size < 0 && status == EXANIC_RX_FRAME_OK) continue;

        /* Get timestamp */
        if (rx_size > 0 && hw_tstamp) {
            const uint64_t timestamp64 = exanic_expand_timestamp(exanic, timestamp);
            exanic_cycles_to_timespecps(exanic, timestamp64, &tsps);
            if (ptp_config.enabled && ptp_to_utc(tsps.tv_sec, ptp.correction, &tsps.tv_sec)) {
                fprintf(stderr, "Hardware timestamp cannot be represented as PCAP/ERF UTC\n");
                goto err_open_next_file;
            }
        } else {
            if (clock_gettime(CLOCK_REALTIME, &ts) != 0) {
                perror("clock_gettime"); goto err_open_next_file;
            }
            tsps.tv_sec = ts.tv_sec;
            tsps.tv_psec = ts.tv_nsec * 1000ULL;
        }

        if (savefp != NULL) {
            /* Log to pcap file */
            if (rx_size > 0 && status == EXANIC_RX_FRAME_OK) {
                size_t caplen = rx_size > snaplen ? (size_t)snaplen : (size_t)rx_size;
                size_t record_size = (file_format == FORMAT_PCAP ? sizeof(struct pcap_pkthdr) : 18) + caplen;
                unsigned long header_size = file_format == FORMAT_PCAP ? sizeof(struct pcap_file_header) : 0;
                if (rotate_seconds || file_size_limit) {
                    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
                        perror("clock_gettime"); goto err_open_next_file;
                    }
                    time_t now = ts.tv_sec;
                    if (rotation_due(file_size, header_size, record_size, file_size_limit,
                                     rotate_seconds, now, next_rotation_time)) {
                        if (rotate_file(&savefp, savefile, file_name_buf, sizeof(file_name_buf),
                                        file_format, nsec_pcap, snaplen, &file_size, &file_no, repo_dir) != 0)
                            goto err_open_next_file;


                        next_rotation_time = now + rotate_seconds;
                    }
                }

                int written = file_format == FORMAT_PCAP
                    ? write_pcap_packet(rx_buf, rx_size, &tsps, nsec_pcap, snaplen, savefp)
                    : write_erf_packet(rx_buf, rx_size, &tsps, port_number, snaplen, savefp);
                if (written < 0) goto err_open_next_file;
                if ((unsigned long)written > ULONG_MAX - file_size) {
                    fprintf(stderr, "Capture size overflow\n"); goto err_open_next_file;
                }
                file_size += (unsigned long)written;
                ptp_audit_packet(&ptp);
                if (flush && fflush(savefp) != 0) {
                    perror("capture flush"); goto err_open_next_file;
                }
            }
        } else {
            /* Dump to stdout */
            print_time(&tsps);
            if (rx_size > 0) {
                if (status == EXANIC_RX_FRAME_OK)
                    printf("received %zd bytes\n", rx_size);
                else if (status == EXANIC_RX_FRAME_CORRUPT)
                    printf("received %zd bytes with bad CRC\n", rx_size);
                else
                    printf("received %zd bytes with unknown error id %d\n", rx_size, status);

                print_hexdump(rx_buf, (rx_size > snaplen) ? snaplen : rx_size);
            } else {
                if (status == EXANIC_RX_FRAME_ABORTED)
                    printf("sender aborted frame\n");
                else if (status == EXANIC_RX_FRAME_CORRUPT)
                    printf("frame discarded due to bad CRC\n");
                else if (status == EXANIC_RX_FRAME_HWOVFL)
                    printf("frames lost due to insufficient PCIe/memory bandwidth\n");
                else if (status == EXANIC_RX_FRAME_SWOVFL)
                    printf("frames lost due to capture program too slow (usually a scheduling issue)\n");
                else if (status == EXANIC_RX_FRAME_TRUNCATED)
                    printf("unexpectedly long (>16KB) frame received\n");
                else
                    printf("unknown error\n");
            }
        }

        /* Update counters */
        if (status == EXANIC_RX_FRAME_OK) rx_success++;
        else if (status == EXANIC_RX_FRAME_CORRUPT) rx_corrupt++;
        else if (status == EXANIC_RX_FRAME_ABORTED) rx_aborted++;
        else if (status == EXANIC_RX_FRAME_HWOVFL) rx_hwovfl++;
        else if (status == EXANIC_RX_FRAME_SWOVFL) rx_swovfl++;
        else rx_other++;
    }
    if (set_promisc)
        set_promiscuous_mode(exanic, port_number, 0);

    fprintf(stderr,
            "%s: received=%lu corrupt=%lu aborted=%lu hw_lost=%lu sw_lost=%lu other=%lu\n",
            argv[0], rx_success, rx_corrupt, rx_aborted, rx_hwovfl, rx_swovfl, rx_other);

    exanic_release_rx_buffer(rx);
    exanic_release_handle(exanic);

    int finish_result = finish_file(&savefp, file_name_buf);
    ptp_clock_close(&ptp);
    return finish_result != 0;

err_open_next_file:
    if (set_promisc) set_promiscuous_mode(exanic, port_number, 0);
err_apply_filters:
    exanic_release_rx_buffer(rx);
err_acquire_rx:
    exanic_release_handle(exanic);
err_acquire_handle:
    ptp_clock_close(&ptp);
    if (savefp != NULL && fclose(savefp) != 0) perror("capture close after failure");
    if (*file_name_buf) fprintf(stderr, "Capture failed; inspect remaining .part files for %s\n", file_name_buf);
    return 1;

usage_error:
    fprintf(stderr, "Usage: %s -i interface\n", argv[0]);
    fprintf(stderr, " [-w savefile] [-s snaplen] [-C file_size]\n");
    fprintf(stderr, " [-F file_format] [-p] [-H] [-N] [filter...]\n");
    fprintf(stderr, " -i: specify Linux interface (e.g. eth0) or ExaNIC port name (e.g. exanic0:0)\n");
    fprintf(stderr, " -w: dump frames to given file in specified format (- for stdout)\n");
    fprintf(stderr, " -s: maximum data length to capture\n");
    fprintf(stderr, " -C: file size at which to start a new save file (in millions of bytes)\n");
    fprintf(stderr, " -F: file format [pcap|erf] (default is pcap)\n");
    fprintf(stderr, " -p: do not attempt to put interface in promiscuous mode\n");
    fprintf(stderr, " -H: use hardware timestamps (refer to documentation on how to sync clock)\n");
    fprintf(stderr, " -N: write nanosecond-resolution pcap format\n\n");
    fprintf(stderr, " -G: rotate to a new save file every N seconds (time-based rotation)\n\n");
    fprintf(stderr, " -R: output directory when -w has no directory\n");
    fprintf(stderr, " -D: fsync capture and directory when publishing (may delay reception)\n");
    fprintf(stderr, " --ptp --hw-clock-scale utc|tai: hardware timestamps, nanosecond PCAP, advisory monitoring\n");
    fprintf(stderr, " --tai-offset kernel|SECONDS: TAI-UTC correction (default: kernel, TAI input only)\n");
    fprintf(stderr, " --ptp-status-socket PATH: local nonblocking status input (see docs/ptp.md)\n");
    fprintf(stderr, " --ptp-audit on|off: per-file JSONL audit (default on); monitoring/warnings stay enabled\n");
    fprintf(stderr, " --ptp-max-offset-ns N: warning threshold (default 1000 ns)\n");
    fprintf(stderr, " --ptp-stale-seconds N: telemetry expiry (default 5 s)\n");
    fprintf(stderr, " --ptp-clock-id ID --ptp-expected-gm ID --ptp-domain N: telemetry identity checks\n");

    fprintf(stderr, "Filter examples:\n");
    fprintf(stderr, " tcp port 80 (to/from tcp port 80)\n");
    fprintf(stderr, " host 192.168.0.1 tcp port 80 (to/from 192.168.0.1:80)\n");
    fprintf(stderr, " dst 192.168.0.1 dport 53 (to 192.168.0.1:53, either tcp or udp)\n");
    fprintf(stderr, " src 192.168.0.5 sport 80 or dst 192.168.0.1 (combine clauses with 'or')\n");

    return 1;
}
