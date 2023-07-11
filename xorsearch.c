#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <string.h>

#define die_perror(reason)  \
    do {                    \
        perror(reason);     \
        exit(EXIT_FAILURE); \
    } while (0)

#define die(reason)                      \
    do {                                 \
        fprintf(stderr, "%s\n", reason); \
        exit(EXIT_FAILURE);              \
    } while (0)

#define debugf(format, args...)   \
    do {                          \
        if (verbose)              \
            printf(format, args); \
    } while (0)

#define debug(format)       \
    do {                    \
        if (verbose)        \
            printf(format); \
    } while (0)


int verbose = 0;
typedef struct {
    uint8_t* start;
    uint8_t* end;
    size_t length;
} span;


/*
# Case1: enc[i] = ((key + i*c2) ^ data[i]) + i*c3
data[i] = (enc[i] - i*c3) ^ (key+i*c2)
key+i*c2 = (enc[i]- i*c3) ^ data[i]
if pattern[i] == data[i]: (key+i*c2) ^ pattern[i] = (enc[i] - i*c3) ^ data[i] ^ pattern[i] -> (key+i*c2) ^ pattern[i] = (enc[i] - i*c3)
key = enc[0] ^ pattern[0] | calculate key
c2 = ((enc[1] -c3) ^ pattern[1]) - key | brute force all values for c3 -> get corresponding c2
key+i*c2 ^ pattern[i] ?= (enc[i] - i*c3) | check if it holds true
*/
void xorsearch1(span const* pattern_span, span const* data_span) {
    debug("xorsearch1\n");

    uint8_t* data_current = data_span->start;
    uint8_t* pattern_current = pattern_span->start;

    uint8_t key = *data_current ^ *pattern_current;

    while (data_current <= data_span->end) {
        debugf("data_current: %02x - pos: %ld\n", *data_current, data_current - data_span->start);
        if (pattern_span->length > (size_t)(data_span->end - data_current)) {
            break;
        }
        for (uint16_t c3 = 0; c3 <= 0xff; ++c3) {
            uint8_t c2 = ((data_current[1] - c3) ^ pattern_current[1]) - key;
            for (size_t i = 2; i < pattern_span->length; ++i) {
                if ((uint8_t)((key + i * c2) ^ pattern_current[i]) != (uint8_t)(data_current[i] - i * c3)) {
                    goto next_c3;
                }
            }
            printf("Found Match at offset: 0x%lx | enc[i] = ((0x%02x + i*0x%02x) ^ data[i]) + i*0x%02x\n", data_current - data_span->start, key, c2, c3);
        next_c3:
        }
        key = *++data_current ^ *pattern_current;
    }
}


/*
# Case2: enc[i] = ((key + i*c2) ^ data[i]) + c
data[i] = (enc[i] - c) ^ (key + i*c2)
key+i*c2 = (enc[i] - c) ^ data[i]
if pattern[i] == data[i]: (key+i*c2) ^ pattern[i] = (enc[i] - c) ^ data[i] ^ pattern[i] -> (key+i*c2) ^ pattern[i] = enc[i] - c
enc[0] - (key^pattern[0]) = c | brute force all values for key -> get corresponding c
c2 = ((enc[1] - c) ^ pattern[1]) - key | calculate corresponding c2
(key+2*c2) ?= enc[2] - c ^ pattern[2] | check if it holds true
*/
void xorsearch2(span const* pattern_span, span const* data_span) {
    debug("xorsearch2\n");

    uint8_t* data_current = data_span->start;
    uint8_t* pattern_current = pattern_span->start;

    while (data_current <= data_span->end) {
        debugf("data_current: %02x - pos: %ld\n", *data_current, data_current - data_span->start);
        if (pattern_span->length > (size_t)(data_span->end - data_current)) {
            break;
        }
        for (uint16_t key = 0; key <= 0xff; ++key) {
            uint8_t c = data_current[0] - (key ^ pattern_current[0]);
            uint8_t c2 = ((data_current[1] - c) ^ pattern_current[1]) - key;
            for (size_t i = 2; i < pattern_span->length; ++i) {
                if ((uint8_t)(key + i * c2) != (uint8_t)((data_current[i] - c) ^ pattern_current[i])) {
                    goto next_key;
                }
            }
            printf("Found Match at offset: 0x%lx | enc[i] = ((0x%02x + i*0x%02x) ^ data[i]) + 0x%02x\n", data_current - data_span->start, key, c2, c);
        next_key:
        }
        ++data_current;
    }
}



/*
# Case3: enc[i] = key ^ (data[i] + i*c2)
data[i] = (enc[i] ^ key) - i*c2
key = (data[i] + i*c2) ^ enc[i]
if pattern[i] == data[i]: 
key = pattern[0] ^ enc[0] | calculate key
c2 = (key ^ enc[1]) - pattern[1] | calculate corresponding c2
2*c2 ?= (key ^ enc[2]) - pattern[2] | check if it holds true
*/
void xorsearch3(span const* pattern_span, span const* data_span) {
    debug("xorsearch3\n");

    uint8_t* data_current = data_span->start;
    uint8_t* pattern_current = pattern_span->start;

    uint8_t key = *data_current ^ *pattern_current;

    while (data_current <= data_span->end) {
        debugf("data_current: %02x - pos: %ld\n", *data_current, data_current - data_span->start);
        if (pattern_span->length > (size_t)(data_span->end - data_current)) {
            break;
        }
        uint8_t c2 = (key ^ data_current[1]) - pattern_current[1];
        for (size_t i = 2; i < pattern_span->length; ++i) {
            if ((uint8_t)(i * c2) != (uint8_t)((key ^ data_current[i]) - pattern_current[i])) {
                goto next_key;
            }
        }
        printf("Found Match at offset: 0x%lx | enc[i] = 0x%02x ^ (data[i] + i*0x%02x)\n", data_current - data_span->start, key, c2);
    next_key:
        key = *++data_current ^ *pattern_current;
    }
}


/*
# Case4: enc[i] = key ^ (data[i] + c)
data[i] = (enc[i] ^ key) - c
key = (data[i] + c) ^ enc[i]
if pattern[i] == data[i]: 
c = (key ^ enc[i]) - pattern[i] | brute force all values for key -> get corresponding c
key ^ enc[i] = pattern[i] + c | check if it holds true
*/
void xorsearch4(span const* pattern_span, span const* data_span) {
    debug("xorsearch4\n");

    uint8_t* data_current = data_span->start;
    uint8_t* pattern_current = pattern_span->start;

    while (data_current <= data_span->end) {
        debugf("data_current: %02x - pos: %ld\n", *data_current, data_current - data_span->start);
        if (pattern_span->length > (size_t)(data_span->end - data_current)) {
            break;
        }
        for (uint16_t key = 0; key <= 0xff; ++key) {
            uint8_t c = (key ^ data_current[0]) - pattern_current[0];
            for (size_t i = 2; i < pattern_span->length; ++i) {
                if ((uint8_t)(key ^ data_current[i]) != (uint8_t)(pattern_current[i] + c)) {
                    goto next_key;
                }
            }
            printf("Found Match at offset: 0x%lx | enc[i] = 0x%02x ^ (data[i] + 0x%02x)\n", data_current - data_span->start, key, c);
        next_key:
        }
        ++data_current;
    }
}


void print_usage_and_exit(char** argv) {
    printf("Usage: %s [-v1234] -p <PATTERN> <FILENAME>\n", argv[0]);
    exit(EXIT_FAILURE);
}

// TODO: print more data encrypted in the found scheme following the pattern (e.g. pattern:flag{ -> print:flag{xxxxxxxxxx})
//       -> maybe until next newline or nullbyte if in specified range (e.g. must be in the next 20 bytes)
// TODO: filter for matches that end with a newline or null byte
int main(int argc, char** argv) {
    int case1 = 0;
    int case2 = 0;
    int case3 = 0;
    int case4 = 0;
    char* pattern = NULL;
    int c;

    while ((c = getopt(argc, argv, "v1234p:")) != -1) {
        switch (c) {
            case 'v': verbose = 1; break;
            case '1': case1 = 1; break;
            case '2': case2 = 1; break;
            case '3': case3 = 1; break;
            case '4': case4 = 1; break;
            case 'p': pattern = optarg; break;
            default: die("getopt");
        }
    }

    char* filename = NULL;
    if (optind < argc) {
        filename = argv[optind++];
    }

    if (filename == NULL || pattern == NULL) {
        print_usage_and_exit(argv);
    }

    if (optind != argc) {
        print_usage_and_exit(argv);
    }

    size_t pattern_length = strlen((char*)pattern);
    struct stat sb;

    int fd = open(filename, O_RDWR | O_CLOEXEC);
    if (fd == -1)
        die_perror("open");

    if (fstat(fd, &sb) == -1)
        die_perror("fstat");

    size_t length = sb.st_size;
    void* addr = mmap(NULL, length, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    if (addr == MAP_FAILED)
        die_perror("mmap");

    const span pattern_span = {.start = (uint8_t*)pattern, .end = (uint8_t*)pattern + pattern_length, .length = pattern_length};
    const span data_span = {.start = addr, .end = addr + length, .length = length};

    if (case1)
        xorsearch1(&pattern_span, &data_span);
    if (case2)
        xorsearch2(&pattern_span, &data_span);
    if (case3)
        xorsearch3(&pattern_span, &data_span);
    if (case4)
        xorsearch4(&pattern_span, &data_span);


    munmap(addr, length);
    close(fd);

    exit(EXIT_SUCCESS);
}