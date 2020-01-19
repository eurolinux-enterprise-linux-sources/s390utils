/*
 * zgetdump - Tool for copying and converting System z dumps
 *
 * Generic input dump format functions (DFI - Dump Format Input)
 *
 * Copyright IBM Corp. 2001, 2011
 * Author(s): Michael Holzheu <holzheu@linux.vnet.ibm.com>
 */

#include <time.h>
#include "zgetdump.h"

#define TIME_FMT_STR "%a, %d %b %Y %H:%M:%S %z"
#define PROGRESS_HASH_CNT 50

/*
 * DFI vector - ensure that tape is the first in the list and devmem the second!
 */
static struct dfi *dfi_vec[] = {
	&dfi_s390tape,
	&dfi_devmem,
	&dfi_s390mv,
	&dfi_s390,
	&dfi_lkcd,
	&dfi_elf,
	&dfi_kdump,
	&dfi_kdump_flat,
	NULL,
};

/*
 * Live dump magic
 */
u64 dfi_live_dump_magic = 0x4c49564544554d50ULL; /* LIVEDUMP */

/*
 * CPU information
 */
struct cpus {
	struct util_list	list;
	enum dfi_cpu_content	content;
	unsigned int		cnt;
};

/*
 * Memory information
 */
struct mem {
	struct dfi_mem_chunk	*chunk_cache;
	u64			start_addr;
	u64			end_addr;
	unsigned int		chunk_cnt;
	struct util_list	chunk_list;
};

/*
 * Dump header attribute information
 */
struct attr {
	unsigned int		*dfi_version;
	struct timeval		*time;
	struct timeval		*time_end;
	u64			*cpu_id;
	u64			*mem_size_real;
	enum dfi_arch		*build_arch;
	unsigned int		*vol_nr;
	u32			*real_cpu_cnt;
	struct new_utsname	*utsname;
	char			*dump_method;
};

/*
 * File local static data
 */
static struct {
	enum dfi_arch	arch;
	struct attr	attr;
	struct mem	mem;
	struct cpus	cpus;
	struct dfi	*dfi;
	unsigned long	kdump_base;
	unsigned long	kdump_size;
} l;

/*
 * Print Dump date
 */
static void date_print(void)
{
	char time_str[80];
	struct tm *tmp;

	if (l.attr.time) {
		tmp = localtime(&l.attr.time->tv_sec);
		strftime(time_str, sizeof(time_str), TIME_FMT_STR, tmp);
		STDERR("  Dump created.......: %s\n", time_str);
	}
	if (l.attr.time_end) {
		tmp = localtime(&l.attr.time_end->tv_sec);
		strftime(time_str, sizeof(time_str), TIME_FMT_STR, tmp);
		STDERR("  Dump ended.........: %s\n", time_str);
	}
}

/*
 * Initialize DFI mem
 */
static void mem_init(void)
{
	l.mem.start_addr = U64_MAX;
	l.mem.end_addr = 0;
	util_list_init(&l.mem.chunk_list, struct dfi_mem_chunk, list);
}

/*
 * Print memory map
 */
static void mem_map_print(void)
{
	struct dfi_mem_chunk *mem_chunk;

	STDERR("\nMemory map:\n");
	dfi_mem_chunk_iterate(mem_chunk) {
		STDERR("  %016llx - %016llx (%llu MB)\n", mem_chunk->start,
		       mem_chunk->end, TO_MIB(mem_chunk->size));
	}
}

/*
 * Is memory range valid?
 */
int dfi_mem_range_valid(u64 addr, u64 len)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 addr_end = addr + len;

	do {
		mem_chunk = dfi_mem_chunk_find(addr);
		if (!mem_chunk)
			return 0;
		addr += MIN(len, mem_chunk->end - addr + 1);
	} while (addr < addr_end);
	return 1;
}

/*
 * Print dump information (--info option)
 */
void dfi_info_print(void)
{
	STDERR("General dump info:\n");
	STDERR("  Dump format........: %s\n", l.dfi->name);
	if (l.attr.dfi_version)
		STDERR("  Version............: %d\n", *l.attr.dfi_version);
	date_print();
	if (l.attr.dump_method)
		STDERR("  Dump method........: %s\n", l.attr.dump_method);
	if (l.attr.cpu_id)
		STDERR("  Dump CPU ID........: %llx\n", *l.attr.cpu_id);
	if (l.attr.utsname) {
		STDERR("  UTS node name......: %s\n", l.attr.utsname->nodename);
		STDERR("  UTS kernel release.: %s\n", l.attr.utsname->release);
		STDERR("  UTS kernel version.: %s\n", l.attr.utsname->version);
	}
	if (l.attr.vol_nr)
		STDERR("  Volume number......: %d\n", *l.attr.vol_nr);
	if (l.attr.build_arch)
		STDERR("  Build arch.........: %s\n",
		      dfi_arch_str(*l.attr.build_arch));
	STDERR("  System arch........: %s\n", dfi_arch_str(l.arch));
	if (l.cpus.cnt)
		STDERR("  CPU count (online).: %d\n", l.cpus.cnt);
	if (l.attr.real_cpu_cnt)
		STDERR("  CPU count (real)...: %d\n", *l.attr.real_cpu_cnt);
	if (dfi_mem_range())
		STDERR("  Dump memory range..: %lld MB\n",
		       TO_MIB(dfi_mem_range()));
	if (l.attr.mem_size_real)
		STDERR("  Real memory range..: %lld MB\n",
		      TO_MIB(*l.attr.mem_size_real));
	if (dfi_mem_range())
		mem_map_print();
	if (l.dfi->info_dump) {
		STDERR("\nDump device info:\n");
		l.dfi->info_dump();
	}
}

/*
 * Add memory chunk
 */
void dfi_mem_chunk_add(u64 start, u64 size, void *data,
		       dfi_mem_chunk_read_fn read_fn)
{
	struct dfi_mem_chunk *mem_chunk;

	mem_chunk = zg_alloc(sizeof(*mem_chunk));
	mem_chunk->start = start;
	mem_chunk->end = start + size - 1;
	mem_chunk->size = size;
	mem_chunk->read_fn = read_fn;
	mem_chunk->data = data;

	util_list_entry_add_tail(&l.mem.chunk_list, mem_chunk);
	l.mem.start_addr = MIN(l.mem.start_addr, mem_chunk->start);
	l.mem.end_addr = MAX(l.mem.end_addr, mem_chunk->end);
	l.mem.chunk_cache = mem_chunk;
	l.mem.chunk_cnt++;
}

/*
 * Return mem_chunk list head
 */
struct util_list *dfi_mem_chunk_list(void)
{
	return &l.mem.chunk_list;
}

/*
 * Return number of memory chunks in input dump
 */
unsigned int dfi_mem_chunk_cnt(void)
{
	return l.mem.chunk_cnt;
}

/*
 * Return maximum memory range
 */
u64 dfi_mem_range(void)
{
	if (l.mem.start_addr == U64_MAX)
		return 0;
	return l.mem.end_addr - l.mem.start_addr + 1;
}

/*
 * Return first memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_first(void)
{
	if (util_list_is_empty(&l.mem.chunk_list))
		return NULL;
	return util_list_entry_start(&l.mem.chunk_list);
}

/*
 * Return next memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_next(struct dfi_mem_chunk *mem_chunk)
{
	return util_list_entry_next(&l.mem.chunk_list, mem_chunk);
}

/*
 * Return previous memory chunk
 */
struct dfi_mem_chunk *dfi_mem_chunk_prev(struct dfi_mem_chunk *mem_chunk)
{
	return util_list_entry_prev(&l.mem.chunk_list, mem_chunk);
}

/*
 * Check if memory chunk contains address
 */
static int mem_chunk_has_addr(struct dfi_mem_chunk *mem_chunk, u64 addr)
{
	return (addr >= mem_chunk->start && addr <= mem_chunk->end);
}

/*
 * Find memory chunk for given address
 */
struct dfi_mem_chunk *dfi_mem_chunk_find(u64 addr)
{
	struct dfi_mem_chunk *mem_chunk;

	if (mem_chunk_has_addr(l.mem.chunk_cache, addr))
		return l.mem.chunk_cache;
	dfi_mem_chunk_iterate(mem_chunk) {
		if (mem_chunk_has_addr(mem_chunk, addr)) {
			l.mem.chunk_cache = mem_chunk;
			return mem_chunk;
		}
	}
	return NULL;
}

/*
 * Initialize CPU info
 */
void dfi_cpu_info_init(enum dfi_cpu_content cpu_content)
{
	l.cpus.content = cpu_content;
	util_list_init(&l.cpus.list, struct dfi_cpu, list);
	l.cpus.cnt = 0;
}

/*
 * Allocate new DFI CPU
 */
struct dfi_cpu *dfi_cpu_alloc(void)
{
	return zg_alloc(sizeof(struct dfi_cpu));
}

/*
 * Add DFI CPU
 */
void dfi_cpu_add(struct dfi_cpu *cpu)
{
	util_list_entry_add_tail(&l.cpus.list, cpu);
	l.cpus.cnt++;
}

/*
 * Return CPU with number cpu_nr
 */
struct dfi_cpu *dfi_cpu(unsigned int cpu_nr)
{
	struct dfi_cpu *cpu;
	unsigned int i = 0;

	dfi_cpu_iterate(cpu) {
		if (i == cpu_nr)
			return cpu;
		i++;
	}
	return NULL;
}

/*
 * Return CPU count
 */
unsigned int dfi_cpu_cnt(void)
{
	return l.cpus.cnt;
}

/*
 * Return CPU content
 */
enum dfi_cpu_content dfi_cpu_content(void)
{
	return l.cpus.content;
}

/*
 * Set DFI architecture
 */
void dfi_arch_set(enum dfi_arch arch)
{
	l.arch = arch;
}

/*
 * Return DFI architecture
 */
enum dfi_arch dfi_arch(void)
{
	return l.arch;
}

/*
 * Return DFI CPU list
 */
struct util_list *dfi_cpu_list(void)
{
	return &l.cpus.list;
}

/*
 * Read memory at given address
 */
static void dfi_mem_read_raw(u64 addr, void *buf, size_t cnt)
{
	struct dfi_mem_chunk *mem_chunk;
	u64 size, copied = 0;

	while (copied != cnt) {
		mem_chunk = dfi_mem_chunk_find(addr);
		size = MIN(cnt - copied, mem_chunk->end - addr + 1);
		mem_chunk->read_fn(mem_chunk, addr - mem_chunk->start,
				   buf + copied, size);
		copied += size;
		addr += size;
	}
}

/*
 * Read memory at given address and do kdump swap if necessary
 */
void dfi_mem_read(u64 addr, void *buf, size_t cnt)
{
	u64 copied = 0;

	if (!g.opts.kdump_swap)
		return dfi_mem_read_raw(addr, buf, cnt);

	if (addr < l.kdump_size) {
		copied = MIN(cnt, l.kdump_size - addr);
		dfi_mem_read_raw(addr + l.kdump_base, buf, copied);
	}
	dfi_mem_read_raw(addr + copied, buf + copied, cnt - copied);
}

/*
 * Read memory at given address with return code
 */
static int dfi_mem_read_raw_rc(u64 addr, void *buf, size_t cnt)
{
	if (!dfi_mem_range_valid(addr, cnt))
		return -EINVAL;
	dfi_mem_read(addr, buf, cnt);
	return 0;
}

/*
 * Read memory at given address with return code and do kdump swap if necessary
 * rc = 0: Read was successful
 */
int dfi_mem_read_rc(u64 addr, void *buf, size_t cnt)
{
	u64 copied = 0;
	int rc;

	if (!g.opts.kdump_swap)
		return dfi_mem_read_raw_rc(addr, buf, cnt);

	if (addr < l.kdump_size) {
		copied = MIN(cnt, l.kdump_size - addr);
		rc = dfi_mem_read_raw_rc(addr + l.kdump_base, buf, copied);
		if (rc)
			return rc;
	}
	return dfi_mem_read_raw_rc(addr + copied, buf + copied, cnt - copied);
}

/*
 * Get input dump format name
 */
const char *dfi_name(void)
{
	return l.dfi->name;
}

/*
 * Can input dump format seek?
 */
int dfi_feat_seek(void)
{
	return l.dfi->feat_bits & DFI_FEAT_SEEK;
};

/*
 * Can input dump format be used for copying?
 */
int dfi_feat_copy(void)
{
	return l.dfi->feat_bits & DFI_FEAT_COPY;
};

/*
 * Return DFI arch string
 */
const char *dfi_arch_str(enum dfi_arch arch)
{
	switch (arch) {
	case DFI_ARCH_32:
		return "s390 (32 bit)";
	case DFI_ARCH_64:
		return "s390x (64 bit)";
	case DFI_ARCH_UNKNOWN:
		return "unknown";
	}
	ABORT("dfi_arch_str: Invalid dfi arch: %d", arch);
}

/*
 * Initialize attributes
 */
static void attr_init(void)
{
	memset(&l.attr, 0, sizeof(l.attr));
}

/*
 * Attribute: Dump time
 */
void dfi_attr_time_set(struct timeval *time)
{
	if (time->tv_sec == 0)
		return;
	l.attr.time = zg_alloc(sizeof(*l.attr.time));
	*l.attr.time = *time;
}

struct timeval *dfi_attr_time(void)
{
	return l.attr.time;
}

/*
 * Attribute: Dump end time
 */
void dfi_attr_time_end_set(struct timeval *time_end)
{
	if (time_end->tv_sec == 0)
		return;
	l.attr.time_end = zg_alloc(sizeof(*l.attr.time_end));
	*l.attr.time_end = *time_end;
}

struct timeval *dfi_attr_time_end(void)
{
	return l.attr.time_end;
}

/*
 * Attribute: Volume number
 */
void dfi_attr_vol_nr_set(unsigned int vol_nr)
{
	l.attr.vol_nr = zg_alloc(sizeof(*l.attr.vol_nr));
	*l.attr.vol_nr = vol_nr;
}

/*
 * Attribute: DFI version
 */
void dfi_attr_version_set(unsigned int dfi_version)
{
	l.attr.dfi_version = zg_alloc(sizeof(*l.attr.dfi_version));
	*l.attr.dfi_version = dfi_version;
}

/*
 * Attribute: CPU ID
 */
void dfi_attr_cpu_id_set(u64 cpu_id)
{
	l.attr.cpu_id = zg_alloc(sizeof(*l.attr.cpu_id));
	*l.attr.cpu_id = cpu_id;
}

u64 *dfi_attr_cpu_id(void)
{
	return l.attr.cpu_id;
}

/*
 * Attribute: utsname
 */
void dfi_attr_utsname_set(struct new_utsname *utsname)
{
	l.attr.utsname = zg_alloc(sizeof(*utsname));
	memcpy(l.attr.utsname, utsname, sizeof(*utsname));
}

struct new_utsname *dfi_attr_utsname(void)
{
	return l.attr.utsname;
}

/*
 * Attribute: dump method
 */
void dfi_attr_dump_method_set(char *dump_method)
{
	l.attr.dump_method = zg_strdup(dump_method);
}

char *dfi_attr_dump_method(void)
{
	return l.attr.dump_method;
}

/*
 * Attribute: Real memory size
 */
void dfi_attr_mem_size_real_set(u64 mem_size_real)
{
	l.attr.mem_size_real = zg_alloc(sizeof(*l.attr.mem_size_real));
	*l.attr.mem_size_real = mem_size_real;
}

u64 *dfi_attr_mem_size_real(void)
{
	return l.attr.mem_size_real;
}

/*
 * Attribute: Build architecture
 */
void dfi_attr_build_arch_set(enum dfi_arch build_arch)
{
	l.attr.build_arch = zg_alloc(sizeof(*l.attr.build_arch));
	*l.attr.build_arch = build_arch;
}

enum dfi_arch *dfi_attr_build_arch(void)
{
	return l.attr.build_arch;
}

/*
 * Attribute: Real CPU count
 */
void dfi_attr_real_cpu_cnt_set(unsigned int real_cnt_cnt)
{
	l.attr.real_cpu_cnt = zg_alloc(sizeof(*l.attr.real_cpu_cnt));
	*l.attr.real_cpu_cnt = real_cnt_cnt;
}

unsigned int *dfi_attr_real_cpu_cnt(void)
{
	return l.attr.real_cpu_cnt;
}

/*
 * Convert 32 bit CPU register set to 64 bit
 */
static void cpu_32_to_64(struct dfi_cpu *cpu_64, struct dfi_cpu_32 *cpu_32)
{
	int i;

	for (i = 0; i < 16; i++) {
		cpu_64->gprs[i] = cpu_32->gprs[i];
		cpu_64->ctrs[i] = cpu_32->ctrs[i];
		cpu_64->acrs[i] = cpu_32->acrs[i];
		if (i < 4)
			cpu_64->fprs[i] = cpu_32->fprs[i];
	}
	cpu_64->psw[0] = cpu_32->psw[0];
	cpu_64->psw[1] = cpu_32->psw[1];
	cpu_64->prefix = cpu_32->prefix;
	cpu_64->timer = cpu_32->timer;
	cpu_64->todcmp = cpu_32->todcmp;
}

/*
 * Convert 64 bit CPU register set to 32 bit
 */
void dfi_cpu_64_to_32(struct dfi_cpu_32 *cpu_32, struct dfi_cpu *cpu_64)
{
	int i;

	for (i = 0; i < 16; i++) {
		cpu_32->gprs[i] = (u32) cpu_64->gprs[i];
		cpu_32->ctrs[i] = (u32) cpu_64->ctrs[i];
		cpu_32->acrs[i] = (u32) cpu_64->acrs[i];
		if (i < 4)
			cpu_32->fprs[i] = (u32) cpu_64->fprs[i];
	}
	cpu_32->psw[0] = (u32) cpu_64->psw[0];
	cpu_32->psw[1] = (u32) cpu_64->psw[1];
	cpu_32->prefix = cpu_64->prefix;
	cpu_32->timer = cpu_64->timer;
	cpu_32->todcmp = cpu_64->todcmp;
}

/*
 * Copy 64 bit lowcore to internal register set
 */
static void lc2cpu_64(struct dfi_cpu *cpu, struct dfi_lowcore_64 *lc)
{
	memcpy(&cpu->gprs, lc->gpregs_save_area, sizeof(cpu->gprs));
	memcpy(&cpu->ctrs, lc->cregs_save_area, sizeof(cpu->ctrs));
	memcpy(&cpu->acrs, lc->access_regs_save_area, sizeof(cpu->acrs));
	memcpy(&cpu->fprs, lc->floating_pt_save_area, sizeof(cpu->fprs));
	memcpy(&cpu->fpc, &lc->fpt_creg_save_area, sizeof(cpu->fpc));
	memcpy(&cpu->psw, lc->st_status_fixed_logout, sizeof(cpu->psw));
	memcpy(&cpu->prefix, &lc->prefixreg_save_area, sizeof(cpu->prefix));
	memcpy(&cpu->timer, lc->timer_save_area, sizeof(cpu->timer));
	memcpy(&cpu->todpreg, &lc->tod_progreg_save_area, sizeof(cpu->todpreg));
	memcpy(&cpu->todcmp, lc->clock_comp_save_area, sizeof(cpu->todcmp));
}

/*
 * Copy 32 bit lowcore to internal 32 bit cpu
 */
static void lc2cpu_32(struct dfi_cpu_32 *cpu, struct dfi_lowcore_32 *lc)
{
	memcpy(&cpu->gprs, lc->gpregs_save_area, sizeof(cpu->gprs));
	memcpy(&cpu->ctrs, lc->cregs_save_area, sizeof(cpu->ctrs));
	memcpy(&cpu->acrs, lc->access_regs_save_area, sizeof(cpu->acrs));
	memcpy(&cpu->fprs, lc->floating_pt_save_area, sizeof(cpu->fprs));
	memcpy(&cpu->psw, lc->st_status_fixed_logout, sizeof(cpu->psw));
	memcpy(&cpu->prefix, &lc->prefixreg_save_area, sizeof(cpu->prefix));
	memcpy(&cpu->timer, lc->timer_save_area, sizeof(cpu->timer));
	memcpy(&cpu->todcmp, lc->clock_comp_save_area, sizeof(cpu->todcmp));
}

/*
 * Initialize and add a new CPU with given lowcore pointer
 *
 * Note: When this function is called, the memory chunks have to be already
 *       defined by the DFI dump specific code.
 */
void dfi_cpu_add_from_lc(u32 lc_addr)
{
	struct dfi_cpu *cpu = dfi_cpu_alloc();

	switch (l.cpus.content) {
	case DFI_CPU_CONTENT_LC:
		cpu->prefix = lc_addr;
		break;
	case DFI_CPU_CONTENT_ALL:
		if (l.arch == DFI_ARCH_32) {
			struct dfi_cpu_32 cpu_32;
			struct dfi_lowcore_32 lc;
			dfi_mem_read(lc_addr, &lc, sizeof(lc));
			lc2cpu_32(&cpu_32, &lc);
			cpu_32_to_64(cpu, &cpu_32);
		} else {
			struct dfi_lowcore_64 lc;
			dfi_mem_read(lc_addr, &lc, sizeof(lc));
			lc2cpu_64(cpu, &lc);
		}
		break;
	case DFI_CPU_CONTENT_NONE:
		ABORT("dfi_cpu_add_from_lc() called for CONTENT_NONE");
	}
	dfi_cpu_add(cpu);
}

/*
 * Return kdump base
 */
unsigned long dfi_kdump_base(void)
{
	return l.kdump_base;
}

/*
 * Check if dump contains a kdump dump and initialize kdump_base and kdump_size
 */
static void kdump_init(void)
{
	unsigned long base, size;

	dfi_mem_read_raw(0x10418, &base, sizeof(base));
	dfi_mem_read_raw(0x10420, &size, sizeof(size));
	if (base == 0 || size == 0)
		return;
	if (base % MIB || size % MIB)
		return;
	if (!dfi_mem_range_valid(base, size))
		return;
	l.kdump_base = base;
	l.kdump_size = size;
}

/*
 * If "--select prod" is set, modify DFI to show production system dump
 */
static void kdump_swap_init(void)
{
	unsigned long prefix, ptr, count, tv_sec, i;
	struct timeval timeval;

	if (g.opts.select_specified && !l.kdump_base)
		ERR_EXIT("The \"--select\" option is not possible with this "
			 "dump");
	if (!g.opts.kdump_swap)
		return;

	attr_init();
	dfi_arch_set(DFI_ARCH_64);
	dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
	if (dfi_vmcoreinfo_symbol(&ptr, "lowcore_ptr"))
		return;
	if (dfi_vmcoreinfo_length(&count, "lowcore_ptr"))
		return;
	if (dfi_vmcoreinfo_val(&tv_sec, "CRASHTIME") == 0) {
		timeval.tv_sec = tv_sec;
		timeval.tv_usec = 0;
		dfi_attr_time_set(&timeval);
	}
	dfi_cpu_info_init(DFI_CPU_CONTENT_ALL);
	for (i = 0; i < count; i++) {
		if (dfi_mem_read_rc(ptr + i * sizeof(long), &prefix,
				   sizeof(prefix)))
			continue;
		if (prefix == 0)
			continue;
		if (prefix % 0x1000)
			continue;
		dfi_cpu_add_from_lc(prefix);
	}
}

/*
 * Try to get utsname info from dump
 */
static void utsname_init(void)
{
	struct new_utsname *utsname;
	unsigned long ptr;
	char buf[1024];

	if (dfi_vmcoreinfo_symbol(&ptr, "init_uts_ns"))
		return;
	if (dfi_mem_read_rc(ptr, buf, sizeof(buf)))
		return;
	utsname = memchr(buf, 'L', sizeof(buf) - sizeof(*utsname));
	if (!utsname)
		return;
	if (strncmp(utsname->sysname, "Linux", sizeof(utsname->version) != 0))
		return;
	dfi_attr_utsname_set(utsname);
}

/*
 * Try to get livedump magic
 */
static void livedump_init(void)
{
	u64 magic;

	if (dfi_mem_read_rc(0, &magic, sizeof(magic)))
		return;
	if (magic == dfi_live_dump_magic)
		dfi_attr_dump_method_set(DFI_DUMP_METHOD_LIVE);
}

/*
 * Initialize input dump format.
 */
int dfi_init(void)
{
	struct dfi *dfi;
	int i = 0, rc;

	l.arch = DFI_ARCH_UNKNOWN;
	mem_init();
	attr_init();
	dfi_cpu_info_init(DFI_CPU_CONTENT_NONE);
	while ((dfi = dfi_vec[i])) {
		l.dfi = dfi;
		g.fh = zg_open(g.opts.device, O_RDONLY, ZG_CHECK);
		rc = dfi->init();
		if (rc == 0 && dfi_feat_seek()) {
			kdump_init();
			dfi_vmcoreinfo_init();
			kdump_swap_init();
			utsname_init();
			livedump_init();
		}
		if (rc == 0 || rc == -EINVAL)
			return rc;
		zg_close(g.fh);
		i++;
	}
	ERR_EXIT("No valid dump found on \"%s\"", g.opts.device);
}

/*
 * Cleanup input dump format.
 */
void dfi_exit(void)
{
	if (l.dfi && l.dfi->exit)
		l.dfi->exit();
}
