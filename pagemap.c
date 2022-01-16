// SPDX-License-Identifier: GPL-2.0-only
/*
 *   This tool is for obtianing PFN, page flags and mapcount of pages in a
 *   process.
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 *
 *   Author: Xiongwei Song <sxwjean@gmail.com>
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>
#include <limits.h>

#include "kernel-page-flags.h"

#define pagemap_entry 8

#define PFN_SHIFT ((1UL << 55) - 1)
#define SWAP_TYPE (0x1f)
#define SWAP_OFFSET(x) ((x & PFN_SHIFT) >> 5)
#define SOFT_DIRTY (1UL << 55)
#define EXCL_MAP (1UL << 56)
#define PAGE_FILE_ANON (1UL << 61)
#define PAGE_SWAPPED (1UL << 62)
#define PAGE_PRESENT (1UL << 63)

#define pagemap "/proc/%u/pagemap"
#define kpageflags "/proc/kpageflags"
#define kpagecount "/proc/kpagecount"

#define data_to_pfn(x) (PFN_SHIFT & x)

struct page_page {
	unsigned long data;
	unsigned long pfn;
	unsigned long pageflags;
	unsigned long count;
};

struct page_data_chunk {
	pid_t pid;
	unsigned long start_addr;
	unsigned long index;
	unsigned page_size;
	unsigned count;
	struct page_page pps[];
};

static struct page_data_chunk *pdc = NULL;
static char pagemap_path[100];

#define ARRAY_SIZE(x) (sizeof(x) / sizeof((x)[0]))

static unsigned long get_pagemaps(struct page_data_chunk *pdc, const char *path)
{
	int fd, i;
	unsigned long start_index, len;
	struct page_page *pp;

	fd = open(path, O_RDONLY);
	if (fd < 0) {
	        printf("A failure on %s\n", path);
	        return 0;
	}

	start_index = pdc->index;
	for (i = 0; i < pdc->count; i++) {
	        pp = &pdc->pps[i];
	        len = pread(fd, (void *)&pp->data, sizeof(pp->data), start_index + i*8);
	        if (!len) {
	                printf("Failed to get page data of 0x%lx\n", start_index);
	                continue;
	        }
	        pp->pfn = data_to_pfn(pp->data);
	}
	close(fd);

	return i;
}

static unsigned long get_pageflags(int fd, unsigned long pfn)
{
	unsigned long flags;
	int len;

	len = pread(fd, &flags, sizeof(flags), pfn*8);
	if (len < 0) {
	        printf("read page flags error: pfn %lu\n", pfn);
		exit(EXIT_FAILURE);
	}

	return flags;
}

static unsigned long get_count(int fd, unsigned long pfn)
{
	unsigned long count;
	int len;

	len = pread(fd, &count, sizeof(count), pfn*8);
	if (len < 0) {
	        printf("read page map count error: pfn %lu\n", pfn);
		exit(EXIT_FAILURE);
	}

	return count;
}

#define IS_SET(x) ((x) ? 1 : 0)

static inline int is_flag_set(unsigned long flags, unsigned long bit)
{
	return !!(flags & (1UL << bit));
}

static const char * const page_flags[] =
{
	[KPF_LOCKED] = "LOCKED",
	[KPF_ERROR] = "ERROR",
	[KPF_REFERENCED] = "REFERENCED",
	[KPF_UPTODATE] = "UPTODATE",
	[KPF_DIRTY] = "DIRTY",
	[KPF_LRU] = "LRU",
	[KPF_ACTIVE] = "ACTIVE",
	[KPF_SLAB] = "SLAB",
	[KPF_WRITEBACK] = "WRITEBACK",
	[KPF_RECLAIM] = "RECLAIM",
	[KPF_BUDDY] = "BUDDY",
	[KPF_MMAP] = "MMAP",
	[KPF_ANON] = "ANON",
	[KPF_SWAPCACHE] = "SWAPCACHE",
	[KPF_SWAPBACKED] = "SWAPBACKED",
	[KPF_COMPOUND_HEAD] = "COMPOUND_HEAD",
	[KPF_COMPOUND_TAIL] = "COMPOUND_TAIL",
	[KPF_HUGE] = "HUGE",
	[KPF_UNEVICTABLE] = "UNEVICTABLE",
	[KPF_HWPOISON] = "HWPOISON",
	[KPF_NOPAGE] = "NOPAGE",
	[KPF_KSM] = "KSM",
	[KPF_THP] = "THP",
	[KPF_OFFLINE] = "OFFLINE",
	[KPF_ZERO_PAGE] = "ZERO_PAGE",
	[KPF_IDLE] = "IDLE",
	[KPF_PGTABLE] = "PGTABLE",
	[KPF_RESERVED] = "RESERVED",
	[KPF_MLOCKED] = "MLOCKED",
	[KPF_MAPPEDTODISK] = "MAPPEDTODISK",
	[KPF_PRIVATE] = "PRIVATE",
	[KPF_PRIVATE_2] = "PRIVATE_2",
	[KPF_OWNER_PRIVATE] = "OWNER_PRIVATE",
	[KPF_ARCH] = "ARCH",
	[KPF_UNCACHED] = "UNCACHED",
	[KPF_SOFTDIRTY] = "SOFTDIRTY",
	[KPF_ARCH_2] = "ARCH_2",
	[KPF_READAHEAD] = "READAHEAD",
	[KPF_SLOB_FREE] = "SLOB_FREE",
	[KPF_SLUB_FROZEN] = "SLUB_FROZEN",
	[KPF_SLUB_DEBUG] = "SLUB_DEBUG",
	[KPF_FILE] = "FILE",
	[KPF_SWAP] = "SWAP",
	[KPF_MMAP_EXCLUSIVE] = "MMAP_EXCLUSIVE",
};

static const unsigned int pageflags_names_index[] =
{
	KPF_LOCKED,
	KPF_ERROR,
	KPF_REFERENCED,
	KPF_UPTODATE,
	KPF_DIRTY,
	KPF_LRU,
	KPF_ACTIVE,
	KPF_SLAB,
	KPF_WRITEBACK,
	KPF_RECLAIM,
	KPF_BUDDY,
	KPF_MMAP,
	KPF_ANON,
	KPF_SWAPCACHE,
	KPF_SWAPBACKED,
	KPF_COMPOUND_HEAD,
	KPF_COMPOUND_TAIL,
	KPF_HUGE,
	KPF_UNEVICTABLE,
	KPF_HWPOISON,
	KPF_NOPAGE,
	KPF_KSM,
	KPF_THP,
	KPF_OFFLINE,
	KPF_ZERO_PAGE,
	KPF_IDLE,
	KPF_PGTABLE,
	KPF_RESERVED,
	KPF_MLOCKED,
	KPF_MAPPEDTODISK,
	KPF_PRIVATE,
	KPF_PRIVATE_2,
	KPF_OWNER_PRIVATE,
	KPF_ARCH,
	KPF_UNCACHED,
	KPF_SOFTDIRTY,
	KPF_ARCH_2,
	KPF_READAHEAD,
	KPF_SLOB_FREE,
	KPF_SLUB_FROZEN,
	KPF_SLUB_DEBUG,
	KPF_FILE,
	KPF_SWAP,
	KPF_MMAP_EXCLUSIVE,
};

#define PAGE_FLAGS_OUT(x) \
        if (is_flag_set(pp->pageflags, x)) \
		snprintf(strchr(str_flags, '\0'), strlen(page_flags[x]) + 2, \
		"%s|", page_flags[x]);

static void print_result(const struct page_data_chunk *pdc)
{
	const struct page_page *pp;
	unsigned long start_addr = pdc->start_addr;
	unsigned page_size = pdc->page_size;
	int i, n;
	static char str_flags[200];


	for (i = 0; i < pdc->count; i++) {
	        pp = &pdc->pps[i];
		printf("VA: %lx\n", start_addr + i*page_size);
#ifdef DEBUG
		printf("  DATA: %lx\n", pp->data);
#endif
	        printf("  PFN: %lx ", pp->pfn);
		printf("MAPCOUNT: %lu ", pp->count);
		printf("PRESENT: %d ", IS_SET(pp->data & PAGE_PRESENT));
		printf("SWAPPED: %d ", IS_SET(pp->data & PAGE_SWAPPED));
		if (IS_SET(pp->data & PAGE_SWAPPED)) {
			printf("SWAP-TYPE: %lu SWAP-OFF %lx ",
				pp->data & SWAP_TYPE, SWAP_OFFSET(pp->data));
		}
		printf("FILE: %d ", IS_SET(pp->data & PAGE_FILE_ANON));
		printf("EXCL_MAP: %d ", IS_SET(pp->data & EXCL_MAP));
		printf("SOFT-DIRTY: %d\n", IS_SET(pp->data & SOFT_DIRTY));
		printf("  FLAGS: %lx  ", pp->pageflags);

		memset(str_flags, 0, 200);
		if (is_flag_set(pp->pageflags, KPF_LOCKED))
			snprintf(str_flags, strlen(page_flags[KPF_LOCKED]) + 2,
					"%s|", page_flags[KPF_LOCKED]);
		for (n = 1; n < ARRAY_SIZE(pageflags_names_index); n++)
			PAGE_FLAGS_OUT(pageflags_names_index[n]);
		str_flags[strlen(str_flags)-1] = '\0';
		printf("%s\n\n", str_flags);
	}
}

unsigned long parse_add_range(const char *optarg, unsigned long *size)
{
	char *c;
	unsigned long start_addr, end_addr;
	unsigned long page_size;

	c = strchr(optarg, '+');
	if (!c)
		c = strchr(optarg, '-');

	if (c == optarg) {
		fprintf(stderr, "Address range error!!!");
		return ULONG_MAX;
	} else if (c == NULL) {
		start_addr = strtoul(optarg, NULL, 16);
		*size = 1;
	} else if (*c == '+') {
		start_addr = strtoul(optarg, NULL, 16);
		*size = strtoul(c + 1, NULL, 16);
	} else if (*c == '-') {
		start_addr = strtoul(optarg, NULL, 16);
		end_addr = strtoul(c + 1, NULL, 16);
		if (end_addr < start_addr) {
			fprintf(stderr, "Address range error!!!");
			return ULONG_MAX;
		}

		page_size = (unsigned long)sysconf(_SC_PAGESIZE);
		*size = (end_addr - start_addr) / page_size;
	} else {
		fprintf(stderr, "Address range error!!!");
		return ULONG_MAX;
	}

	return start_addr;
}

void usage(void)
{
	fprintf(stdout, "pagepage - Get page usage information of a process.\n"
		"    -h pagepage help\n"
		"    -p pid the user want to check\n"
		"    -r Address range, start virtual address + size\n"
		"\n"
		"    example 1: Get page status from address 0x1000 and 10 pages.\n"
		"    pagepage -p 123 -r 0x1000+10\n"
		"\n"
		"    example 2: Get page status from address 0x1000 and address 0x2000.\n"
		"    pagepage -p 123 -r 0x1000-0x2000\n"
		"\n");
}

int main(int argc, char *argv[])
{
	pid_t pid;
	unsigned long start_addr = 0, page_count;
	int i;
	struct page_page *pp;
	int opt;

	while ((opt = getopt(argc, argv, "p:r:h")) != -1) {
	        switch (opt) {
	        case 'p':
	                pid = strtoul(optarg, NULL, 10);
	        break;
	        case 'r':
	                start_addr = parse_add_range(optarg, &page_count);
	        break;
		case 'h':
	        default:
			usage();
	                exit(EXIT_FAILURE);
	        }
	}

	if (pid == 0) {
		printf("Please provide correct pid number!!!");
		exit(EXIT_FAILURE);
	}

	pdc = malloc(sizeof(*pdc) + page_count*sizeof(struct page_page));
	if (!pdc) {
	        printf("Out of memory!!!");
	        exit(EXIT_FAILURE);
	}

	pdc->pid = pid;
	pdc->start_addr = start_addr;
	pdc->count = page_count;
	pdc->page_size = (unsigned long)sysconf(_SC_PAGESIZE);

	memset(pagemap_path, 0, sizeof(pagemap_path));
	sprintf(pagemap_path, "/proc/%u/pagemap", pdc->pid);

	pdc->index = (pdc->start_addr/pdc->page_size)*pagemap_entry;

	unsigned long len;
	len = get_pagemaps(pdc, pagemap_path);
	if (!len) {
	        fprintf(stderr, "Failed to get pagemap content!!!\n");
		free(pdc);
	        exit(EXIT_FAILURE);
	}

	int fd_pf;
	fd_pf = open(kpageflags, O_RDONLY);
	if (fd_pf < 0) {
		fprintf(stderr, "Failed to open %s fd %d\n", kpageflags, fd_pf);
		free(pdc);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < pdc->count; i++) {
	        pp = &pdc->pps[i];
	        pp->pageflags = get_pageflags(fd_pf, pp->pfn);
	}
	close(fd_pf);

	int fd_mc;
	fd_mc = open(kpagecount, O_RDONLY);
	if (fd_mc < 0) {
		fprintf(stderr, "Failed to open %s fd %d\n", kpageflags, fd_mc);
		free(pdc);
		exit(EXIT_FAILURE);
	}

	for (i = 0; i < pdc->count; i++) {
	        pp = &pdc->pps[i];
		pp->count = get_count(fd_mc, pp->pfn);
	}
	close(fd_mc);

	print_result(pdc);

	return 0;
}
