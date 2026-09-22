#include "ptp_clock.h"

#include <ctype.h>
#include <errno.h>
#include <inttypes.h>
#include <limits.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/timex.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define NS_PER_SECOND UINT64_C(1000000000)

const char *ptp_state_name(enum ptp_state state) {
    static const char *names[] = {"unknown", "synced", "unsynced", "holdover", "degraded"};
    return names[state];
}

int ptp_token_valid(const char *text) {
    if (!text || !*text || strlen(text) > 64) return 0;
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p)
        if (!isalnum(*p) && !strchr("_.:-", *p)) return 0;
    return 1;
}

static int integer(const char *s, int64_t min, int64_t max, int64_t *out) {
    if (!s || !*s || (!isdigit((unsigned char)*s) && *s != '-')) return -1;
    char *end;
    errno = 0;
    intmax_t n = strtoimax(s, &end, 10);
    if (errno || end == s || *end || n < min || n > max) return -1;
    *out = n;
    return 0;
}

int ptp_to_utc(int64_t input_sec, int correction, int64_t *output_sec) {
    if (correction < 0 || input_sec < correction || input_sec - correction > UINT32_MAX)
        return -1;
    *output_sec = input_sec - correction;
    return 0;
}

static int kernel_tai_offset(void) {
    struct timex tx = {0}; /* modes=0: read-only, never discipline the clock. */
    if (adjtimex(&tx) < 0 || tx.tai <= 0 || tx.tai > 1000) return -1;
    return tx.tai;
}

void ptp_clock_evaluate(struct ptp_clock *clock, uint64_t now_ns) {
    enum ptp_state state = clock->reported;
    if (!clock->observed_ns || now_ns < clock->observed_ns ||
        now_ns - clock->observed_ns > (uint64_t)clock->config.stale_seconds * NS_PER_SECOND)
        state = PTP_UNKNOWN;
    else if (state == PTP_SYNCED &&
             (!clock->have_offset || !clock->scale_matches || clock->correction_stale ||
              clock->offset_ns > clock->config.max_offset_ns ||
              clock->offset_ns < -clock->config.max_offset_ns ||
              (clock->config.expected_gm && strcmp(clock->gm, clock->config.expected_gm)) ||
              (clock->config.expected_domain >= 0 && clock->domain != clock->config.expected_domain)))
        state = PTP_DEGRADED;
    if (state != clock->state) {
        clock->state = state;
        ++clock->revision;
        if (clock->have_offset)
            fprintf(stderr, "PTP: %s; capture continues (last reported offset=%" PRId64 " ns)\n",
                    ptp_state_name(state), clock->offset_ns);
        else
            fprintf(stderr, "PTP: %s; capture continues (offset unknown)\n", ptp_state_name(state));
    }
}

/* Local bridge protocol, NOT a Timebeat wire format. See docs/ptp.md. */
int ptp_clock_ingest(struct ptp_clock *clock, char *message, uint64_t now_ns) {
    char *field[9], *save = NULL;
    size_t count = 0;
    for (char *p = strtok_r(message, " \t\r\n", &save); p; p = strtok_r(NULL, " \t\r\n", &save)) {
        if (count == 9) return -1;
        field[count++] = p;
    }
    if (count != 9 || strcmp(field[0], "v1") ||
        !ptp_token_valid(field[1]) || strcmp(field[1], clock->config.clock_id) ||
        !ptp_token_valid(field[5])) return -1;
    int64_t observed, offset = 0, domain, tai;
    if (integer(field[8], 1, INT64_MAX, &observed) || (uint64_t)observed > now_ns ||
        now_ns - (uint64_t)observed > (uint64_t)clock->config.stale_seconds * NS_PER_SECOND ||
        (uint64_t)observed < clock->observed_ns ||
        integer(field[6], 0, 255, &domain) || integer(field[7], 0, 1000, &tai)) return -1;
    int have_offset = strcmp(field[3], "unknown") != 0;
    if (have_offset && integer(field[3], INT64_MIN, INT64_MAX, &offset)) return -1;
    enum ptp_state state;
    if (!strcmp(field[2], "synced")) state = PTP_SYNCED;
    else if (!strcmp(field[2], "holdover")) state = PTP_HOLDOVER;
    else if (!strcmp(field[2], "unsynced")) state = PTP_UNSYNCED;
    else if (!strcmp(field[2], "unknown")) state = PTP_UNKNOWN;
    else return -1;
    if (strcmp(field[4], "tai") && strcmp(field[4], "utc")) return -1;
    int matches = ((strcmp(field[4], "tai") == 0) == clock->config.tai) &&
                  (!clock->config.tai || tai == clock->correction);
    if (state == PTP_SYNCED && !strcmp(field[5], "unknown")) state = PTP_UNKNOWN;
    clock->reported = state;
    clock->observed_ns = (uint64_t)observed;
    clock->offset_ns = offset;
    clock->have_offset = have_offset;
    clock->scale_matches = matches;
    strcpy(clock->gm, field[5]);
    clock->domain = (int)domain;
    ++clock->revision;
    ptp_clock_evaluate(clock, now_ns);
    return 0;
}

int ptp_clock_init(struct ptp_clock *clock, const struct ptp_config *config) {
    memset(clock, 0, sizeof(*clock));
    clock->fd = -1;
    clock->config = *config;
    clock->domain = -1;
    strcpy(clock->gm, "unknown");
    if (!config->enabled) return 0;
    if (!ptp_token_valid(config->clock_id) || config->max_offset_ns < 0 ||
        !config->stale_seconds || config->tai_offset < -1 || config->tai_offset > 1000 ||
        (config->tai && config->tai_offset == 0) ||
        (config->expected_gm && !ptp_token_valid(config->expected_gm))) {
        fprintf(stderr, "Invalid PTP configuration/clock identity\n"); return -1;
    }
    clock->correction = config->tai ? config->tai_offset : 0;
    if (clock->correction < 0) clock->correction = kernel_tai_offset();
    if (clock->correction < 0) {
        fprintf(stderr, "PTP: kernel TAI-UTC offset unavailable; supply a verified --tai-offset before capture\n");
        return -1;
    }
    if (config->socket_path) {
        struct sockaddr_un address = {.sun_family = AF_UNIX};
        if (strlen(config->socket_path) >= sizeof(address.sun_path)) {
            fprintf(stderr, "PTP socket path too long\n"); return -1;
        }
        strcpy(address.sun_path, config->socket_path);
        clock->fd = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
        if (clock->fd < 0) { perror("PTP socket"); return -1; }
        mode_t old_mask = umask(0077);
        int rc = bind(clock->fd, (struct sockaddr *)&address, sizeof(address));
        int error = errno;
        umask(old_mask);
        if (rc < 0) {
            errno = error; perror("PTP bind (existing paths are never removed)");
            close(clock->fd); clock->fd = -1; return -1;
        }
        struct stat st;
        if (lstat(config->socket_path, &st) == 0) {
            clock->socket_dev = st.st_dev; clock->socket_ino = st.st_ino;
        }
    }
    fprintf(stderr, "PTP: clock=%s input=%s correction=%d s; sync unknown, capture will not wait\n",
            config->clock_id, config->tai ? "tai" : "utc", clock->correction);
    clock->revision = 1;
    return 0;
}

void ptp_clock_poll(struct ptp_clock *clock) {
    if (!clock->config.enabled) return;
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
        clock->reported = PTP_UNKNOWN; clock->observed_ns = 0;
        ptp_clock_evaluate(clock, 0); return;
    }
    uint64_t now = (uint64_t)ts.tv_sec * NS_PER_SECOND + ts.tv_nsec;
    if (now < clock->next_poll_ns) return;
    clock->next_poll_ns = now + NS_PER_SECOND;
    if (clock->config.tai && clock->config.tai_offset < 0) {
        int offset = kernel_tai_offset();
        int stale = offset < 0;
        if (stale != clock->correction_stale || (!stale && offset != clock->correction)) {
            clock->correction_stale = stale;
            if (!stale) clock->correction = offset;
            ++clock->revision;
            /* Await another provider sample to confirm a changed correction. */
            clock->scale_matches = 0;
            fprintf(stderr, "PTP: TAI-UTC correction=%d s%s; capture continues\n",
                    clock->correction, stale ? " (last known value)" : "");
        }
    }
    /* Bounded work, no DNS, HTTP, shell commands or waiting in the RX thread. */
    for (int i = 0; clock->fd >= 0 && i < 16; ++i) {
        char message[513];
        ssize_t n = recv(clock->fd, message, sizeof(message) - 1, MSG_DONTWAIT | MSG_TRUNC);
        if (n < 0) break;
        if (n == 0 || n >= (ssize_t)sizeof(message) - 1 || memchr(message, 0, (size_t)n)) continue;
        message[n] = 0;
        (void)ptp_clock_ingest(clock, message, now);
    }
    ptp_clock_evaluate(clock, now);
}

static void audit_error(struct ptp_clock *clock) {
    if (!clock->audit_failed)
        fprintf(stderr, "PTP: metadata write failed; capture continues, audit is incomplete\n");
    clock->audit_failed = 1;
    if (clock->audit) fclose(clock->audit);
    clock->audit = NULL;
}

void ptp_audit_event(struct ptp_clock *clock) {
    if (!clock->audit || clock->audit_revision == clock->revision) return;
    if (fprintf(clock->audit,
        "{\"event\":\"clock\",\"next_packet\":%" PRIu64 ",\"state\":\"%s\","
        "\"reported_state\":\"%s\",\"observed_monotonic_ns\":%" PRIu64 ","
        "\"offset_ns\":%" PRId64 ",\"offset_known\":%s,\"gm\":\"%s\",\"domain\":%d,"
        "\"tai_utc_offset\":%d,\"correction_stale\":%s,\"scale_matches\":%s}\n",
        clock->packets + 1, ptp_state_name(clock->state), ptp_state_name(clock->reported),
        clock->observed_ns, clock->offset_ns, clock->have_offset ? "true" : "false",
        clock->gm, clock->domain, clock->correction,
        clock->correction_stale ? "true" : "false", clock->scale_matches ? "true" : "false") < 0 ||
        fflush(clock->audit)) audit_error(clock);
    clock->audit_revision = clock->revision;
}

void ptp_audit_open(struct ptp_clock *clock, const char *capture_path) {
    if (!clock->config.enabled || clock->config.disable_audit || !capture_path || !*capture_path) return;
    char path[4128];
    clock->packets = clock->untrusted_packets = 0;
    clock->audit_revision = 0;
    clock->audit_failed = 0;
    if (snprintf(path, sizeof(path), "%s.ptp.jsonl", capture_path) >= (int)sizeof(path)) {
        audit_error(clock); return;
    }
    clock->audit = fopen(path, "wx");
    if (!clock->audit) { audit_error(clock); return; }
    if (fprintf(clock->audit,
        "{\"event\":\"start\",\"schema\":1,\"clock_id\":\"%s\",\"input_scale\":\"%s\","
        "\"output_scale\":\"utc\",\"offset_source\":\"%s\",\"max_offset_ns\":%" PRId64 ","
        "\"stale_seconds\":%u,\"expected_gm\":\"%s\",\"expected_domain\":%d}\n",
        clock->config.clock_id, clock->config.tai ? "tai" : "utc",
        !clock->config.tai ? "none" : clock->config.tai_offset < 0 ? "kernel" : "configured",
        clock->config.max_offset_ns, clock->config.stale_seconds,
        clock->config.expected_gm ? clock->config.expected_gm : "any",
        clock->config.expected_domain) < 0) { audit_error(clock); return; }
    ptp_audit_event(clock);
}

void ptp_audit_packet(struct ptp_clock *clock) {
    if (!clock->config.enabled || clock->config.disable_audit) return;
    ++clock->packets;
    if (clock->state != PTP_SYNCED) ++clock->untrusted_packets;
}

void ptp_audit_close(struct ptp_clock *clock, int complete) {
    if (!clock->audit) return;
    int failed = fprintf(clock->audit,
        "{\"event\":\"end\",\"capture_complete\":%s,\"packets\":%" PRIu64
        ",\"packets_without_confirmed_sync\":%" PRIu64 "}\n",
        complete ? "true" : "false", clock->packets, clock->untrusted_packets) < 0;
    if (fclose(clock->audit)) failed = 1;
    clock->audit = NULL;
    if (failed) audit_error(clock);
}

void ptp_clock_close(struct ptp_clock *clock) {
    ptp_audit_close(clock, 0);
    if (clock->fd < 0) return;
    close(clock->fd); clock->fd = -1;
    struct stat st;
    if (clock->config.socket_path && lstat(clock->config.socket_path, &st) == 0 &&
        st.st_dev == clock->socket_dev && st.st_ino == clock->socket_ino)
        unlink(clock->config.socket_path);
}
