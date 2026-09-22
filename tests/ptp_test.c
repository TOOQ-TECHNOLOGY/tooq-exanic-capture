#undef NDEBUG
#include <assert.h>
#include <inttypes.h>
#include <sys/un.h>
#include <sys/timex.h>
#define main capture_main
#include "../src/main.c"
#undef main

static int fake_tai = 37;
int __wrap_adjtimex(struct timex *tx) {
    assert(tx->modes == 0); /* The monitor must never adjust the system clock. */
    if (fake_tai < 0) { errno = EIO; return -1; }
    tx->tai = fake_tai;
    return TIME_OK;
}

static int ingest(struct ptp_clock *clock, const char *text, uint64_t now) {
    char buffer[512];
    assert(strlen(text) < sizeof(buffer));
    strcpy(buffer, text);
    return ptp_clock_ingest(clock, buffer, now);
}

int main(void) {
    int64_t utc;
    assert(ptp_to_utc(1700000037, 37, &utc) == 0 && utc == 1700000000);
    assert(ptp_to_utc(1700000000, 0, &utc) == 0 && utc == 1700000000);
    assert(ptp_to_utc(36, 37, &utc) == -1);
    assert(ptp_to_utc(INT64_MIN, 37, &utc) == -1);
    assert(ptp_to_utc(INT64_MAX, 37, &utc) == -1);
    assert(ptp_to_utc((int64_t)UINT32_MAX + 37, 37, &utc) == 0 && utc == UINT32_MAX);
    assert(ptp_to_utc((int64_t)UINT32_MAX + 38, 37, &utc) == -1);

    struct ptp_config config = {
        .enabled = 1, .tai = 1, .tai_offset = 37, .max_offset_ns = 1000,
        .stale_seconds = 5, .clock_id = "exanic0", .expected_gm = "gm1", .expected_domain = 50,
    };
    struct ptp_clock clock;
    config.tai_offset = -1;
    fake_tai = 0;
    assert(ptp_clock_init(&clock, &config) == -1); /* Never silently subtract zero for TAI. */
    fake_tai = 37;
    assert(ptp_clock_init(&clock, &config) == 0 && clock.correction == 37);
    fake_tai = -1;
    ptp_clock_poll(&clock);
    assert(clock.correction == 37 && clock.correction_stale);
    fake_tai = 38;
    clock.next_poll_ns = 0;
    ptp_clock_poll(&clock);
    assert(clock.correction == 38 && !clock.correction_stale);
    ptp_clock_close(&clock);
    config.tai_offset = 37;
    assert(ptp_clock_init(&clock, &config) == 0 && clock.state == PTP_UNKNOWN);
    uint64_t now = UINT64_C(10000000000);
    assert(ingest(&clock, "v1 exanic0 synced 1000 tai gm1 50 37 10000000000", now) == 0);
    assert(clock.state == PTP_SYNCED);
    assert(ingest(&clock, "v1 exanic0 synced -1001 tai gm1 50 37 10000000000", now) == 0);
    assert(clock.state == PTP_DEGRADED);
    assert(ingest(&clock, "v1 exanic0 synced -1000 tai gm1 50 37 10000000000", now) == 0);
    assert(clock.state == PTP_SYNCED);
    assert(ingest(&clock, "v1 exanic0 holdover unknown tai gm1 50 37 10000000000", now) == 0);
    assert(clock.state == PTP_HOLDOVER && clock.correction == 37);
    assert(ingest(&clock, "v1 exanic0 unsynced unknown tai gm1 50 37 10000000000", now) == 0);
    assert(clock.state == PTP_UNSYNCED);
    assert(ingest(&clock, "v1 exanic0 synced 5 utc gm1 50 0 10000000000", now) == 0);
    assert(clock.state == PTP_DEGRADED && clock.correction == 37);
    assert(ingest(&clock, "v1 exanic0 synced 5 tai gm2 50 37 10000000000", now) == 0);
    assert(clock.state == PTP_DEGRADED);
    assert(ingest(&clock, "v1 exanic0 synced 5 tai gm1 49 37 10000000000", now) == 0);
    assert(clock.state == PTP_DEGRADED);
    assert(ingest(&clock, "v1 exanic0 synced unknown tai gm1 50 37 10000000000", now) == 0);
    assert(clock.state == PTP_DEGRADED);
    assert(ingest(&clock, "v1 exanic0 synced 5 tai unknown 50 37 10000000000", now) == 0);
    assert(clock.state == PTP_UNKNOWN);
    assert(ingest(&clock, "v1 exanic0 synced 5 tai gm1 50 37 10000000000", now) == 0);
    clock.correction_stale = 1;
    ptp_clock_evaluate(&clock, now);
    assert(clock.state == PTP_DEGRADED && clock.correction == 37);
    clock.correction_stale = 0;
    ptp_clock_evaluate(&clock, now + UINT64_C(5000000001));
    assert(clock.state == PTP_UNKNOWN);
    /* Invalid, wrong-clock, stale, future and overflowing telemetry cannot establish lock. */
    const char *bad[] = {
        "v1 exanic1 synced 5 tai gm1 50 37 10000000000",
        "v1 exanic0 synced 5 tai gm1 50 37 10000000001",
        "v1 exanic0 synced 5 tai gm1 50 37 1",
        "v1 exanic0 synced 999999999999999999999999 tai gm1 50 37 10000000000",
        "v1 exanic0 synced 5 tai gm1 50 37 10000000000 extra",
        "v1 exanic0 synced 5 tai gm1 500 37 10000000000",
        "v1 exanic0 synced 5 tai gm\"1 50 37 10000000000",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i)
        assert(ingest(&clock, bad[i], now) == -1 && clock.state == PTP_UNKNOWN);

    char directory[] = "/tmp/exanic-ptp-test-XXXXXX";
    assert(mkdtemp(directory));
    char socket_path[108]; snprintf(socket_path, sizeof(socket_path), "%s/status.sock", directory);
    config.socket_path = socket_path;
    assert(ptp_clock_init(&ptp, &config) == 0);
    struct ptp_clock duplicate;
    assert(ptp_clock_init(&duplicate, &config) == -1);
    assert(access(socket_path, F_OK) == 0); /* Never delete another capture's socket. */
    struct stat st;
    assert(stat(socket_path, &st) == 0 && (st.st_mode & 0777) == 0700);
    int sender = socket(AF_UNIX, SOCK_DGRAM, 0); assert(sender >= 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    strcpy(address.sun_path, socket_path);
    struct timespec mono; assert(clock_gettime(CLOCK_MONOTONIC, &mono) == 0);
    now = (uint64_t)mono.tv_sec * UINT64_C(1000000000) + mono.tv_nsec;
    char message[512];
    snprintf(message, sizeof(message), "v1 exanic0 synced 10 tai gm1 50 37 %" PRIu64, now);
    assert(sendto(sender, message, strlen(message), 0, (struct sockaddr *)&address, sizeof(address)) > 0);
    ptp_clock_poll(&ptp);
    assert(ptp.state == PTP_SYNCED);

    /* Write records through loss, stale telemetry, recovery and rotation. */
    char base[4096], name[4096] = "", first[4096];
    snprintf(base, sizeof(base), "%s/capture.pcap", directory);
    FILE *fp = NULL; unsigned long size; int index = 0;
    assert(rotate_file(&fp, base, name, sizeof(name), FORMAT_PCAP, 1, 64, &size, &index, NULL) == 0);
    strcpy(first, name);
    char payload[64] = {0};
    for (int i = 0; i < 4; ++i) {
        if (i == 1) {
            snprintf(message, sizeof(message), "v1 exanic0 holdover unknown tai gm1 50 37 %" PRIu64, now);
            assert(ingest(&ptp, message, now) == 0);
        }
        if (i == 2) ptp_clock_evaluate(&ptp, now + UINT64_C(6000000000));
        if (i == 3) {
            now += UINT64_C(7000000000);
            snprintf(message, sizeof(message), "v1 exanic0 synced 10 tai gm1 50 37 %" PRIu64, now);
            assert(ingest(&ptp, message, now) == 0);
        }
        ptp_audit_event(&ptp);
        struct exanic_timespecps ts = {.tv_sec = 1700000037 + i, .tv_psec = 123456789000};
        assert(ptp_to_utc(ts.tv_sec, ptp.correction, &ts.tv_sec) == 0);
        assert(write_pcap_packet(payload, sizeof(payload), &ts, 1, 64, fp) == 80);
        ptp_audit_packet(&ptp);
    }
    assert(ptp.packets == 4 && ptp.untrusted_packets == 2 && run == 1);
    assert(rotate_file(&fp, base, name, sizeof(name), FORMAT_PCAP, 1, 64, &size, &index, NULL) == 0);
    assert(ptp.packets == 0 && ptp.state == PTP_SYNCED);
    assert(finish_file(&fp, name) == 0);
    FILE *readback = fopen(first, "rb"); assert(readback);
    struct pcap_file_header global;
    assert(fread(&global, sizeof(global), 1, readback) == 1 && global.magic == NSEC_TCPDUMP_MAGIC);
    for (unsigned i = 0; i < 4; ++i) {
        struct pcap_pkthdr record;
        assert(fread(&record, sizeof(record), 1, readback) == 1);
        assert(record.ts_sec == 1700000000 + i && record.ts_usec == 123456789 && record.caplen == 64);
        assert(fseek(readback, record.caplen, SEEK_CUR) == 0);
    }
    assert(fgetc(readback) == EOF && fclose(readback) == 0);
    char audit_path[4128]; snprintf(audit_path, sizeof(audit_path), "%s.ptp.jsonl", first);
    readback = fopen(audit_path, "r"); assert(readback);
    char audit[8192] = {0}; assert(fread(audit, 1, sizeof(audit) - 1, readback) > 0);
    assert(strstr(audit, "\"packets\":4") && strstr(audit, "\"packets_without_confirmed_sync\":2"));
    assert(strstr(audit, "\"capture_complete\":true") && strstr(audit, "\"state\":\"holdover\""));
    assert(fclose(readback) == 0 && unlink(audit_path) == 0);
    snprintf(audit_path, sizeof(audit_path), "%s.ptp.jsonl", name);
    assert(unlink(audit_path) == 0 && unlink(first) == 0 && unlink(name) == 0);
    /* Disabling audit must preserve packet output, conversion and monitoring. */
    ptp.config.disable_audit = 1;
    assert(rotate_file(&fp, base, name, sizeof(name), FORMAT_PCAP, 1, 64, &size, &index, NULL) == 0);
    assert(ptp.audit == NULL);
    snprintf(message, sizeof(message), "v1 exanic0 synced 2000 tai gm1 50 37 %" PRIu64, now);
    assert(ingest(&ptp, message, now) == 0 && ptp.state == PTP_DEGRADED);
    ptp_audit_event(&ptp);
    struct exanic_timespecps ts = {.tv_sec = 1700000037, .tv_psec = 123456789000};
    assert(ptp_to_utc(ts.tv_sec, ptp.correction, &ts.tv_sec) == 0 && ts.tv_sec == 1700000000);
    assert(write_pcap_packet(payload, sizeof(payload), &ts, 1, 64, fp) == 80);
    ptp_audit_packet(&ptp);
    assert(finish_file(&fp, name) == 0);
    snprintf(audit_path, sizeof(audit_path), "%s.ptp.jsonl", name);
    assert(access(audit_path, F_OK) == -1 && errno == ENOENT);
    assert(unlink(name) == 0);
    ptp_clock_close(&ptp);
    assert(access(socket_path, F_OK) == -1 && close(sender) == 0 && rmdir(directory) == 0);
    puts("PTP tests passed (capture continued through holdover and telemetry loss)");
    return 0;
}
