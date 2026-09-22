#ifndef CAPTURE_PTP_CLOCK_H
#define CAPTURE_PTP_CLOCK_H

#include <stdint.h>
#include <stdio.h>
#include <sys/types.h>

/* Monitoring is advisory. It must never stop reception or steer any clock. */
enum ptp_state { PTP_UNKNOWN, PTP_SYNCED, PTP_UNSYNCED, PTP_HOLDOVER, PTP_DEGRADED };
struct ptp_config {
    int enabled;
    int disable_audit;           /* Monitoring and stderr warnings remain enabled. */
    int tai;                     /* Explicit input scale: 0 UTC, 1 TAI. */
    int tai_offset;              /* -1: kernel adjtimex, otherwise operator supplied. */
    int64_t max_offset_ns;
    unsigned stale_seconds;
    const char *socket_path;
    const char *clock_id;
    const char *expected_gm;
    int expected_domain;         /* -1: any domain. */
};
struct ptp_clock {
    struct ptp_config config;
    int fd;
    dev_t socket_dev;
    ino_t socket_ino;
    int correction;
    int correction_stale;
    uint64_t next_poll_ns;
    uint64_t observed_ns;
    enum ptp_state reported;
    enum ptp_state state;
    int64_t offset_ns;
    int have_offset;
    char gm[65];
    int domain;
    int scale_matches;
    uint64_t revision;
    FILE *audit;
    uint64_t audit_revision;
    uint64_t packets;
    uint64_t untrusted_packets;
    int audit_failed;
};

int ptp_clock_init(struct ptp_clock *clock, const struct ptp_config *config);
void ptp_clock_close(struct ptp_clock *clock);
void ptp_clock_poll(struct ptp_clock *clock);
/* Public pure helpers also exercised by the hardware-independent tests. */
int ptp_clock_ingest(struct ptp_clock *clock, char *message, uint64_t now_ns);
void ptp_clock_evaluate(struct ptp_clock *clock, uint64_t now_ns);
int ptp_to_utc(int64_t input_sec, int correction, int64_t *output_sec);
const char *ptp_state_name(enum ptp_state state);
int ptp_token_valid(const char *text);
void ptp_audit_open(struct ptp_clock *clock, const char *capture_path);
void ptp_audit_packet(struct ptp_clock *clock);
void ptp_audit_event(struct ptp_clock *clock);
void ptp_audit_close(struct ptp_clock *clock, int capture_complete);

#endif
