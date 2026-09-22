#define _GNU_SOURCE
#undef NDEBUG
#include <assert.h>
#define main capture_main
#include "../src/main.c"
#undef main

static void check_pcap(const char *path, const char *payload, size_t captured, size_t original) {
    FILE *fp = fopen(path, "rb");
    assert(fp);
    struct pcap_file_header global;
    struct pcap_pkthdr packet;
    char data[128];
    assert(fread(&global, sizeof(global), 1, fp) == 1);
    assert(global.magic == TCPDUMP_MAGIC && global.linktype == DLT_EN10MB);
    assert(fread(&packet, sizeof(packet), 1, fp) == 1);
    assert(packet.caplen == captured && packet.len == original);
    assert(fread(data, 1, captured, fp) == captured);
    assert(memcmp(data, payload, captured) == 0);
    assert(fgetc(fp) == EOF && !ferror(fp));
    assert(fclose(fp) == 0);
}

static int fail_close(void *cookie) {
    (void)cookie;
    errno = EIO;
    return -1;
}

int main(void) {
    assert(!rotation_due(24, 24, 80, 50, 0, 0, 0)); /* One oversized record stays whole. */
    assert(!rotation_due(104, 24, 80, 184, 0, 0, 0));
    assert(rotation_due(104, 24, 80, 183, 0, 0, 0));
    assert(rotation_due(184, 24, 80, 184, 0, 0, 0));
    assert(!rotation_due(104, 24, 80, 0, 60, 59, 60));
    assert(rotation_due(104, 24, 80, 0, 60, 60, 60));
    assert(rotation_due(ULONG_MAX, 24, 80, ULONG_MAX, 0, 0, 0));
    /* Exercise the real library on a synthetic receive ring, without hardware. */
    struct rx_chunk *ring = calloc(EXANIC_RX_NUM_CHUNKS, sizeof(*ring));
    assert(ring);
    char received[128]; uint32_t timestamp; int status;
    const int frame_states[] = {EXANIC_RX_FRAME_OK, EXANIC_RX_FRAME_CORRUPT, EXANIC_RX_FRAME_ABORTED};
    for (size_t i = 0; i < sizeof(frame_states) / sizeof(frame_states[0]); ++i) {
        exanic_rx_t rx = {0};
        rx.buffer = ring; rx.generation = 1;
        rx.sentinel_chunk = EXANIC_RX_NUM_CHUNKS - 1;
        ring[0].u.info.generation = 1; ring[0].u.info.length = 64;
        ring[0].u.info.frame_status = frame_states[i];
        memset(ring[0].payload, 0xcd, 64);
        ssize_t n = exanic_receive_frame_ex(&rx, received, sizeof(received), &timestamp, &status);
        assert(status == frame_states[i]);
        assert(frame_states[i] == EXANIC_RX_FRAME_OK ? n == 64 : n < 0);
    }
    free(ring);
    char directory[] = "/tmp/exanic-test-XXXXXX";
    assert(mkdtemp(directory));
    char base[4096], name[4096] = "", first[4096], part[4101];
    assert(snprintf(base, sizeof(base), "%s/capture.pcap", directory) > 0);
    FILE *fp = NULL;
    unsigned long size;
    int index = 0;
    char data[64]; memset(data, 0xab, sizeof(data));
    struct exanic_timespecps ts = {0}; ts.tv_sec = 123; ts.tv_psec = 456000000;

    FILE *erf = tmpfile(); assert(erf);
    assert(write_erf_packet(data, 64, &ts, 1, 32, erf) == 50);
    rewind(erf);
    unsigned char erf_bytes[50];
    assert(fread(erf_bytes, 1, sizeof(erf_bytes), erf) == sizeof(erf_bytes));
    assert(erf_bytes[8] == 2 && erf_bytes[9] == 5);
    assert(erf_bytes[10] == 0 && erf_bytes[11] == 50);
    assert(erf_bytes[14] == 0 && erf_bytes[15] == 64);
    assert(memcmp(erf_bytes + 18, data, 32) == 0);
    assert(fgetc(erf) == EOF && fclose(erf) == 0);

    FILE *nano = tmpfile(); assert(nano);
    assert(write_pcap_header(nano, 1, 64) == 24);
    assert(write_pcap_packet(data, 64, &ts, 1, 64, nano) == 80);
    rewind(nano);
    struct pcap_file_header nano_global;
    struct pcap_pkthdr nano_packet;
    assert(fread(&nano_global, sizeof(nano_global), 1, nano) == 1);
    assert(fread(&nano_packet, sizeof(nano_packet), 1, nano) == 1);
    assert(nano_global.magic == NSEC_TCPDUMP_MAGIC && nano_packet.ts_usec == 456000);
    assert(fclose(nano) == 0);

    assert(rotate_file(&fp, base, name, sizeof(name), FORMAT_PCAP, 0, 64, &size, &index, NULL) == 0);
    assert(access(name, F_OK) == -1);
    snprintf(part, sizeof(part), "%s.part", name);
    assert(access(part, F_OK) == 0);
    assert(write_pcap_packet(data, 64, &ts, 0, 64, fp) == 80);
    strcpy(first, name);
    durable = 1;
    assert(rotate_file(&fp, base, name, sizeof(name), FORMAT_PCAP, 0, 32, &size, &index, NULL) == 0);
    check_pcap(first, data, 64, 64);
    assert(access(part, F_OK) == -1);
    assert(write_pcap_packet(data, 64, &ts, 0, 32, fp) == 48);
    assert(finish_file(&fp, name) == 0 && fp == NULL);
    check_pcap(name, data, 32, 64);
    assert(unlink(name) == 0);

    /* Restart skips completed files and preserves abandoned partial files. */
    index = 0; name[0] = 0;
    assert(rotate_file(&fp, base, name, sizeof(name), FORMAT_PCAP, 0, 64, &size, &index, NULL) == 0);
    assert(index == 2);
    assert(fclose(fp) == 0); fp = NULL;
    char abandoned[4101]; snprintf(abandoned, sizeof(abandoned), "%s.part", name);
    index = 0; name[0] = 0;
    assert(rotate_file(&fp, base, name, sizeof(name), FORMAT_PCAP, 0, 64, &size, &index, NULL) == 0);
    assert(index == 3);

    /* A destination appearing during capture must never be overwritten. */
    FILE *existing = fopen(name, "wbx"); assert(existing);
    assert(fputs("keep", existing) >= 0 && fclose(existing) == 0);
    assert(finish_file(&fp, name) == -1 && fp == NULL);
    existing = fopen(name, "rb"); assert(existing);
    char marker[4]; assert(fread(marker, 1, 4, existing) == 4);
    assert(memcmp(marker, "keep", 4) == 0 && fclose(existing) == 0);
    snprintf(part, sizeof(part), "%s.part", name);
    assert(access(part, F_OK) == 0);
    assert(unlink(part) == 0 && unlink(name) == 0);

    durable = 0;
    /* Deferred disk-full errors must prevent publication. */
    fp = fopen("/dev/full", "wb"); assert(fp);
    char buffer[4096]; assert(setvbuf(fp, buffer, _IOFBF, sizeof(buffer)) == 0);
    assert(write_pcap_header(fp, 0, 64) == 24);
    assert(finish_file(&fp, name) == -1 && fp == NULL);
    assert(access(name, F_OK) == -1);
    fp = fopen("/dev/full", "wb"); assert(fp);
    assert(setvbuf(fp, NULL, _IONBF, 0) == 0);
    assert(write_pcap_packet(data, 64, &ts, 0, 64, fp) == -1);
    assert(finish_file(&fp, name) == -1);
    cookie_io_functions_t io = {.close = fail_close};
    fp = fopencookie(NULL, "w", io); assert(fp);
    assert(finish_file(&fp, name) == -1 && access(name, F_OK) == -1);

    unsigned long value;
    assert(parse_number("64", 1, 16384, &value) == 0 && value == 64);
    assert(parse_number("-1", 1, 16384, &value) == -1);
    assert(parse_number("0", 1, 16384, &value) == -1);
    assert(parse_number("16385", 1, 16384, &value) == -1);
    assert(parse_number("12junk", 1, 16384, &value) == -1);
    assert(parse_number("999999999999999999999999999", 1, ULONG_MAX, &value) == -1);
    assert(unlink(first) == 0 && unlink(abandoned) == 0 && rmdir(directory) == 0);
    puts("capture tests passed");
    return 0;
}
