/*
 * File...........: s390-tools/fdasd/fdasd.c
 * Author(s)......: Volker Sameske   <sameske@de.ibm.com>
 *                  Horst Hummel     <horst.hummel@de.ibm.com>
 *                  Gerhard Tonn     <ton@de.ibm.com>
 *                  Stefan Weinhuber <wein@de.ibm.com>
 * Copyright IBM Corp. 2001,2012
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <getopt.h>
#include <stdio.h>

#include "zt_common.h"
#include "vtoc.h"
#include "fdasd.h"

/* global variables */
struct hd_geometry geo;
char line_buffer[LINE_LENGTH];
char *line_ptr = line_buffer;

/* Full tool name */
static const char tool_name[] = "fdasd: zSeries DASD partitioning program";

/* Copyright notice */
static const char copyright_notice[] = "Copyright IBM Corp. 2001, 2011";

/*
 * Print version information.
 */
static void
print_version (void)
{
	printf ("%s version %s\n", tool_name, RELEASE_STRING);
	printf ("%s\n", copyright_notice);
}

static int
getpos (fdasd_anchor_t *anc, int dsn)
{
	return anc->partno[dsn];
}

static int
getdsn (fdasd_anchor_t *anc, int pos)
{
	int i;

	for (i=0; i<USABLE_PARTITIONS; i++) {
		if (anc->partno[i] == pos)
			return i;
	}

	return -1;
}

static void
setpos (fdasd_anchor_t *anc, int dsn, int pos)
{
	anc->partno[dsn] = pos;
}

static u_int32_t get_usable_cylinders(fdasd_anchor_t *anc)
{
	u_int32_t cyl;

	/* large volume */
	if (anc->f4->DS4DEVCT.DS4DSCYL == LV_COMPAT_CYL &&
	    anc->f4->DS4DCYL > anc->f4->DS4DEVCT.DS4DSCYL)
		return anc->f4->DS4DCYL;
	/* normal volume */
	if (anc->f4->DS4DEVCT.DS4DEVFG & ALTERNATE_CYLINDERS_USED)
		cyl = anc->f4->DS4DEVCT.DS4DSCYL -
			(u_int16_t) anc->f4->DS4DEVAC;
	else
		cyl = anc->f4->DS4DEVCT.DS4DSCYL;
	return cyl;
}

static void get_addr_of_highest_f1_f8_label(fdasd_anchor_t *anc, cchhb_t *addr)
{

	u_int8_t record;
	/* We have to count the follwing labels:
	 * one format 4
	 * one format 5
	 * format 7 only if we have moren then BIG_DISK_SIZE tracks
	 * one for each format 1 or format 8 label == one for each partition
	 * one for each format 9 label before the last format 8
	 * We assume that all partitions use format 8 labels when
	 *  anc->formatted_cylinders > LV_COMPAT_CYL
	 * Note: Record zero is special, so block 0 on our disk is record 1!
	 */

	record = anc->used_partitions + 2;
	if (anc->big_disk)
		record++;
	if (anc->formatted_cylinders > LV_COMPAT_CYL)
		record += anc->used_partitions - 1;
	vtoc_set_cchhb(addr, VTOC_START_CC, VTOC_START_HH, record);
}

/* 
 * Check for valid volume serial characters (max. 6) - remove invalid.
 * If volser is empty, fill with default volser. 
 */
static void 
fdasd_check_volser(char *volser, int devno)
{
	int from, to;

	for (from=0, to=0; volser[from] && from < VOLSER_LENGTH; from++)
		if ((volser[from] >= 0x23 && 
		     volser[from] <= 0x25) || /* # $ % */
		    (volser[from] >= 0x30 && 
		     volser[from] <= 0x39) || /* 0-9 */
		    (volser[from] >= 0x40 &&
		     volser[from] <= 0x5a) || /* @ A-Z */
		    (volser[from] >= 0x61 &&
		     volser[from] <= 0x7a))   /* a-z */
			volser[to++] = toupper(volser[from]);

	volser[to] = 0x00;
	
	if (volser[0] == 0x00) {
		sprintf(volser, "0X%04x", devno);
	}
}


/*
 * Free memory of fdasd anchor struct.
 */
static void 
fdasd_cleanup (fdasd_anchor_t *anchor) 
{
        partition_info_t *part_info, *next;
        int i;

        if (anchor == NULL) return;

	if (anchor->f4 != NULL) free(anchor->f4);
	if (anchor->f5 != NULL) free(anchor->f5);
	if (anchor->f7 != NULL) free(anchor->f7);
	if (anchor->vlabel != NULL) free(anchor->vlabel);
	
	part_info = anchor->first;
	for (i = 1; i <= USABLE_PARTITIONS && part_info != NULL; i++) {
		next = part_info->next;
		free(part_info->f1);
		free(part_info);
		part_info = next;
	}
}


/*
 * Exit fdasd.
 */
static void 
fdasd_exit (fdasd_anchor_t *anchor, int rc) 
{
        fdasd_cleanup(anchor);
	exit(rc);
}


/*
 *
 */
static void 
fdasd_error(fdasd_anchor_t *anc, enum fdasd_failure why, char *str)
{
        char err_str[ERROR_STRING_SIZE];

	switch (why) {
	case parser_failed:
		snprintf(err_str, ERROR_STRING_SIZE,
			 "%s parser error\n%s\n", FDASD_ERROR, str);
		break;
        case unable_to_open_disk:
	        snprintf(err_str, ERROR_STRING_SIZE,
			"%s open error\n%s\n", FDASD_ERROR, str);
		break;
        case unable_to_seek_disk:
	        snprintf(err_str, ERROR_STRING_SIZE, 
			"%s seek error\n%s\n", FDASD_ERROR, str);
		break;
        case unable_to_read_disk:
	        snprintf(err_str, ERROR_STRING_SIZE, 
			"%s read error\n%s\n", FDASD_ERROR, str);
		break;
        case read_only_disk:
	        snprintf(err_str, ERROR_STRING_SIZE, 
			"%s write error\n%s\n", FDASD_ERROR, str);
		break;
        case unable_to_ioctl:
	        snprintf(err_str, ERROR_STRING_SIZE,
			"%s IOCTL error\n%s\n", FDASD_ERROR, str);
		break;
        case wrong_disk_type:
                snprintf(err_str, ERROR_STRING_SIZE,
			"%s Unsupported disk type\n%s\n",
                        FDASD_ERROR, str);
                break;           
        case wrong_disk_format:
                snprintf(err_str, ERROR_STRING_SIZE,
			"%s Unsupported disk format\n%s\n",
                        FDASD_ERROR, str);
                break;   
        case disk_in_use:
                snprintf(err_str, ERROR_STRING_SIZE,
			"%s Disk in use\n%s\n", FDASD_ERROR, str);
                break;      
        case config_syntax_error:
                snprintf(err_str, ERROR_STRING_SIZE,
			"%s Config file syntax error\n%s\n",
                        FDASD_ERROR, str);
                break;       
        case vlabel_corrupted:
	        snprintf(err_str, ERROR_STRING_SIZE, 
			"%s Volume label is corrupted.\n%s\n", 
			FDASD_ERROR, str);
		break;
        case dsname_corrupted:
	        snprintf(err_str, ERROR_STRING_SIZE,
			"%s a data set name is corrupted.\n%s\n", 
			FDASD_ERROR, str);
		break;
        case malloc_failed:
	        snprintf(err_str, ERROR_STRING_SIZE, 
			"%s space allocation\n%s\n", FDASD_ERROR, str);
		break;
        case device_verification_failed:
	        snprintf(err_str, ERROR_STRING_SIZE,
			 "%s device verification failed\n%s\n",
			 FDASD_ERROR, str);
		break;
	case volser_not_found:
		snprintf(err_str, ERROR_STRING_SIZE,
			 "%s VOLSER not found on device %s\n",
			 FDASD_ERROR, str);
		break;
	default: 
	        snprintf(err_str, ERROR_STRING_SIZE,
			"%s Fatal error\n%s\n",
			FDASD_ERROR, str);
	}

	fputc('\n', stderr);
	fputs(err_str, stderr);

	fdasd_exit(anc, -1);
}


/*
 * Read line from stdin into global line_buffer
 * and set global line_ptr to first printing character except space.
 */
static int
read_line(void) 
{
	bzero(line_buffer, LINE_LENGTH);
	line_ptr = line_buffer;
        if (!fgets(line_buffer, LINE_LENGTH, stdin))
		return 0;
	while (*line_ptr && !isgraph(*line_ptr))
		line_ptr++;
	return *line_ptr;
}


/*
 * 
 */
static char
read_char(char *mesg) 
{
        fputs(mesg, stdout);
	read_line();

        return *line_ptr;
}


/*
 * Print question string an enforce y/n answer.
 */
static int
yes_no(char *question_str)
{
	char *answer;
	size_t size;
	ssize_t bytes_read;

	size = 0;
	answer = NULL;
	while (1) {
		printf("%s (y/n): ", question_str);
		bytes_read = getline(&answer, &size, stdin);
		if (bytes_read < 0)
			return -1;
		if (answer[0] == 'y')
			return 0;
		if (answer[0] == 'n')
			return 1;
	}
	free(answer);
}


/*
 *
 */
static char *
fdasd_partition_type (char *str) 
{
	if (strncmp("NATIVE", str, 6) == 0)
		strcpy(str, "Linux native");
	else if (strncmp("NEW   ", str, 6) == 0)
		strcpy(str, "Linux native");
	else if (strncmp("SWAP  ", str, 6) == 0)
		strcpy(str, "Linux swap");
	else if (strncmp("RAID  ", str, 6) == 0)
		strcpy(str, "Linux raid");
	else if (strncmp("LVM   ", str, 6) == 0)
		strcpy(str, "Linux lvm");
	else
		strcpy(str, "unknown");

	return str;
}


/*
 * prints out the usage text
 */
static void
fdasd_usage (void) 
{
	printf ("\nUsage: fdasd [OPTIONS] [DEVICE]\n"
		"\n"
		"Partition a DASD device either in interactive mode or "
		"automatically.\n"
		"DEVICE is the node of the device (e.g. '/dev/dasda')\n"
		"\n"
		"-h, --help               Print this help, then exit\n"
		"-v, --version            Print version information, "
		                          "then exit\n"
		"-s, --silent             Suppress messages\n"
		"-r, --verbose            Provide more verbose output\n"
		"-a, --auto               Automatically create a partition "
		                          "using the entire disk\n"
		"-k, --keep_volser        Keep current volume serial when "
		                          "performing automatic\n"
		"                         partitioning\n"
		"-l, --label VOLSER       Set the volume serial to VOLSER "
		                          "when performing\n"
		"                         automatic partitioning\n"
		"-c, --config CONFIGFILE  Automatically create partition(s) "
		                          "using information\n"
                "                         found in CONFIGFILE\n"
		"-i, --volser             Print volume serial\n"
		"-p, --table              Print partition table\n"
		"-f, --force              Force fdasd to work on non DASD devices\n");
}


/*
 * prints the menu
 */
static void
fdasd_menu (void) 
{
	printf("Command action\n"
	       "   m   print this menu\n"
	       "   p   print the partition table\n"
	       "   n   add a new partition\n"
	       "   d   delete a partition\n"
	       "   v   change volume serial\n"
	       "   t   change partition type\n"
	       "   r   re-create VTOC and delete all partitions\n"
	       "   u   re-create VTOC re-using existing partition sizes\n"
	       "   s   show mapping (partition number - data set name)\n"
	       "   q   quit without saving changes\n"
	       "   w   write table to disk and exit\n");
}


/*
 * initializes the anchor structure and allocates some
 * memory for the labels
 */
static void
fdasd_initialize_anchor (fdasd_anchor_t *anc) 
{
	partition_info_t *part_info, *prev_part_info = NULL;
	volume_label_t *vlabel;
	int i;

	bzero(anc, sizeof(fdasd_anchor_t));

	for (i=0; i<USABLE_PARTITIONS; i++)
		setpos(anc, i, -1);

	anc->f4 = malloc(sizeof(format4_label_t));
	if (anc->f4 == NULL) 
		fdasd_error(anc, malloc_failed,
			    "FMT4 DSCB memory allocation failed.");

	anc->f5 = malloc(sizeof(format5_label_t));
	if (anc->f5 == NULL) 
		fdasd_error(anc, malloc_failed,
			    "FMT5 DSCB memory allocation failed.");

	anc->f7 = malloc(sizeof(format7_label_t));
	if (anc->f7 == NULL) 
		fdasd_error(anc, malloc_failed,
			    "FMT7 DSCB memory allocation failed.");

	/* template for all format 9 labels */
	anc->f9 = malloc(sizeof(format9_label_t));
	if (anc->f9 == NULL)
		fdasd_error(anc, malloc_failed,
			    "FMT9 DSCB memory allocation failed.");

	bzero(anc->f4, sizeof(format4_label_t));
	bzero(anc->f5, sizeof(format5_label_t));
	bzero(anc->f7, sizeof(format7_label_t));
	bzero(anc->f9, sizeof(format9_label_t));
	vtoc_init_format9_label(anc->f9);

	vlabel = malloc(sizeof(volume_label_t));
	if (vlabel == NULL) 
		fdasd_error(anc, malloc_failed,
			    "Volume label memory allocation failed.");
	bzero(vlabel, sizeof(volume_label_t));
	anc->vlabel = vlabel;

	for (i=1; i<=USABLE_PARTITIONS; i++) {
		part_info = malloc(sizeof(partition_info_t));
		if (part_info == NULL) 
			fdasd_error(anc, malloc_failed,
				   "Partition info memory allocation failed.");
		memset(part_info, 0, sizeof(partition_info_t));

		/* add part_info to double pointered list */
		if (i == 1) {
			anc->first = part_info;
		} else if (i == USABLE_PARTITIONS) {
			anc->last = part_info;
			part_info->next = NULL;
		}

		part_info->f1 = malloc(sizeof(format1_label_t));
		if (part_info->f1 == NULL) 
			fdasd_error(anc, malloc_failed,
				    "FMT1 DSCB memory allocation failed.");
		bzero(part_info->f1, sizeof(format1_label_t));

		if (prev_part_info) {
			prev_part_info->next = part_info;
			part_info->prev = prev_part_info;
		} else {
			part_info->prev = NULL;
		}
		prev_part_info = part_info;
	}
	anc->hw_cylinders = 0;
	anc->formatted_cylinders = 0;
}

static void fdasd_parse_force_options(fdasd_anchor_t *anc, char *optarg)
{
	unsigned int devtype, blksize;
	char err_str[ERROR_STRING_SIZE];
	int rc;

	if (optarg) {
		rc = sscanf(optarg, "%x,%d", &devtype, &blksize);
		if (rc != 2) {
			snprintf(err_str, ERROR_STRING_SIZE,
				 "Force parameter '%s' could not be parsed.\n",
				 optarg);
			fdasd_error(anc, parser_failed, err_str);
		}
		if (devtype == DASD_3390_TYPE || devtype == DASD_3380_TYPE ||
		    devtype == DASD_9345_TYPE)
			anc->dev_type = devtype;
		else {
			snprintf(err_str, ERROR_STRING_SIZE,
				 "Force parameter '%x' is not a supported"
				 " device type.\n", devtype);
			fdasd_error(anc, parser_failed, err_str);
		}
		if (blksize == 4096 || blksize == 2048 ||
		    blksize == 1024 || blksize ==  512)
			anc->blksize = blksize;
		else {
			snprintf(err_str, ERROR_STRING_SIZE,
				 "Force parameter '%d' is not a supported"
				 " block size.\n", blksize);
			fdasd_error(anc, parser_failed, err_str);
		}
	} else {
		/* force option was used without the optional argument */
		anc->dev_type = DASD_3390_TYPE;
		anc->blksize = 4096;
	}
}

/*
 * parses the command line options
 */
static void
fdasd_parse_options (fdasd_anchor_t *anc, struct fdasd_options *options, 
		     int argc, char *argv[]) 
{
	int opt, index;

	do {
		opt = getopt_long(argc, argv, option_string, 
				  fdasd_long_options, &index);
		switch (opt) {
		case 'v':
			print_version();
			fdasd_exit(anc, 0);
		case 'h':
			fdasd_usage ();
			fdasd_exit(anc, 0);
		case 'l':
			if (options->volser)
				fdasd_error(anc, parser_failed,
					    "Option 'label' specified more "
					    "than once.\n");
			options->volser = optarg;
			break;
		case 'a':
			anc->auto_partition++;
			break;
		case 's':
			anc->silent++;
			break;
		case 'r':
			anc->verbose++;
			break;
		case 'p':
			anc->print_table++;
			break;
		case 'i':
			anc->print_volser++;
			anc->silent++;
			break;
		case 'c':
			if (options->conffile)
				fdasd_error(anc, parser_failed,
					    "Option 'config' specified more"
					    " than once.\n");
			options->conffile = optarg;
			break;
		case 'k':
			anc->keep_volser++;
			break;
		case 'f':
			anc->force_virtual++;
			fdasd_parse_force_options(anc, optarg);
			break;
		case -1:
			/* End of options string - start of devices list */
			break;
		default:
			fprintf(stderr, "Try 'fdasd --help' for more"
					" information.\n");
			fdasd_exit(anc, 1);
		}
	} while (opt != -1);

	/* save device */
	if (optind >= argc)
		fdasd_error(anc, parser_failed, 
			    "No device specified.\n");
	if (optind + 1 < argc)
		fdasd_error(anc, parser_failed, 
			    "More than one device specified.\n");
	options->device = argv[optind]; 	
}

int gettoken(char *str, char *ch, char *token[], int max)
{
	int i;

	token[0] = strtok(str, ch);
	if (!token[0])
		return 0;

	for (i = 1; i < max; i++) {
		token[i] = strtok(NULL, ch);
		if (!token[i])
			break;
	}
	return i;
}

/*
 * parses config file
 */
static int
fdasd_parse_conffile(fdasd_anchor_t *anc, struct fdasd_options *options) 
{
	char buffer[CONFIG_FILE_SIZE + 1];
	char err_str[ERROR_STRING_SIZE], *c1, *c2, *token[CONFIG_MAX];
	int fd, rc;
	int i;

	/* if name of config file was not specified, select the default */
	if (options->conffile == NULL)
		options->conffile = DEFAULT_FDASD_CONF;

	if (!anc->silent)
		printf("parsing config file '%s'...\n", options->conffile);
	fd = open(options->conffile, O_RDONLY);
	if (fd < 0) {
		snprintf(err_str, ERROR_STRING_SIZE,
			"Could not open config file '%s' "
			"in read-only mode!\n", options->conffile);
		fdasd_error(anc, unable_to_open_disk, err_str);
	}

	memset(buffer, 0, sizeof(buffer));
	rc = read(fd, buffer, sizeof(buffer) - 1);
	if (rc < 0)
		return -1;
	close(fd);


	for (i = 0; i < rc; i++)
		buffer[i] = toupper(buffer[i]);

	c1 = buffer;

	for (i=0; i<USABLE_PARTITIONS; i++) {
		c1 = strchr(c1, '[');
		if (c1 == NULL) {
			if (!anc->silent)
				printf("no config file entry for " \
				       "partition %d found...\n", i+1);
			break;
		}
		c1 += 1;

		c2 = strchr(c1, ']');
		if (c2 == NULL) {
			snprintf(err_str, ERROR_STRING_SIZE,
				"']' missing in config file " \
				"%s\n", options->conffile);
			fdasd_error(anc, config_syntax_error, err_str);
		}
		strcpy(c2, "");

		memset(token, 0, sizeof(token));
		if (gettoken(c1, ",", token, CONFIG_MAX) < 2) {
			snprintf(err_str, ERROR_STRING_SIZE,
				 "Missing parameter in config file "	\
				 "%s\n", options->conffile);
			fdasd_error(anc, config_syntax_error, err_str);
		}

		if (strstr(token[0], "FIRST") != NULL)
			anc->confdata[i].start = FIRST_USABLE_TRK;
		else {
			errno = 0;
			anc->confdata[i].start = strtol(token[0],
							(char **) NULL, 10);
			if (errno != 0 || anc->confdata[i].start == 0) {
				snprintf(err_str, ERROR_STRING_SIZE,
					 "invalid partition start in config"
					 "file %s\n", options->conffile);
				fdasd_error(anc, config_syntax_error, err_str);
			}
		}

		if (strstr(token[1], "LAST") != NULL)
			anc->confdata[i].stop = anc->formatted_cylinders
				* geo.heads - 1;
		else {
			errno = 0;
			anc->confdata[i].stop = strtol(token[1],
						       (char **) NULL, 10);
			if (errno != 0 || anc->confdata[i].stop == 0) {
				snprintf(err_str, ERROR_STRING_SIZE,
					 "invalid partition end in config"
					 "file %s\n", options->conffile);
				fdasd_error(anc, config_syntax_error, err_str);
			}
		}

		if (token[2] == NULL || strstr(token[2], "NATIVE") != NULL)
			anc->confdata[i].type = PARTITION_NATIVE;
		else if (strstr(token[2], "SWAP") != NULL)
			anc->confdata[i].type = PARTITION_SWAP;
		else if (strstr(token[2], "RAID") != NULL)
			anc->confdata[i].type = PARTITION_RAID;
		else if (strstr(token[2], "LVM") != NULL)
			anc->confdata[i].type = PARTITION_LVM;
		else {
			snprintf(err_str, ERROR_STRING_SIZE,
				 "invalid partition type in config file %s\n",
				 options->conffile);
			fdasd_error(anc, config_syntax_error, err_str);
		}
		c1 = c2 + 1;
	}

	return 0;
}


/*
 * checks input from config file
 */
static void
fdasd_check_conffile_input (fdasd_anchor_t *anc,
			    struct fdasd_options *options)
{
	partition_info_t *part_info = anc->first;
	int i;

	if (anc->verbose) printf("checking config file data...\n");
	for (i=0; i<USABLE_PARTITIONS; i++) {
		unsigned long start, stop, first_trk, last_trk;
		char err_str[ERROR_STRING_SIZE];
	   
		start = anc->confdata[i].start;
		stop = anc->confdata[i].stop;

		if ((start == 0) || (stop == 0)) break;

		first_trk = FIRST_USABLE_TRK;
		last_trk = anc->formatted_cylinders * geo.heads - 1;

		if ((start < first_trk) || (start > last_trk)) {
			snprintf(err_str, ERROR_STRING_SIZE,
				"One of the lower partition limits "
				"(%ld) is not within the range of \n "
				"available tracks on disk (%ld-%ld)!\n", 
				start, first_trk, last_trk);
			fdasd_error(anc, config_syntax_error, err_str);
		}

		if ((stop < first_trk) || (stop > last_trk)) {
			snprintf(err_str, ERROR_STRING_SIZE,
				"One of the upper partition limits "
				"(%ld) is not within the range of \n "
				"available tracks on disk (%ld-%ld)!\n", 
				stop, first_trk, last_trk);
			fdasd_error(anc, config_syntax_error, err_str);
		}

		if (start >= stop) {
			snprintf(err_str, ERROR_STRING_SIZE,
				"Lower partition limit (%ld) is not "
				"less than upper partition \nlimit (%ld) "
				"in config file %s!\n", 
				 start, stop, options->conffile);
			fdasd_error(anc, config_syntax_error, err_str);
		}

		if ((i > 0) && (start <= anc->confdata[i-1].stop)) {
			snprintf(err_str, ERROR_STRING_SIZE,
				"Partitions overlap or are not in "
				"ascending order!\n");
			fdasd_error(anc, config_syntax_error, err_str);
		}

		if ((i < (USABLE_PARTITIONS - 1)) && 
		    (anc->confdata[i+1].start > 0) && 
		    (stop >= anc->confdata[i+1].start)) {
			snprintf(err_str, ERROR_STRING_SIZE,
				"Partitions overlap or are not in "
				"ascending order!\n");
			fdasd_error(anc, config_syntax_error, err_str);
		}

		part_info->used      = 0x01;
		part_info->start_trk = start;
		part_info->end_trk   = stop;
		part_info->len_trk   = stop - start + 1;
		part_info->type      = anc->confdata[i].type;

		/* update the current free space counter */
		if (i == 0)
			anc->fspace_trk = start - FIRST_USABLE_TRK;
		
		if (i < USABLE_PARTITIONS - 1) {
			if (anc->confdata[i+1].start != 0)
				part_info->fspace_trk = 
					anc->confdata[i+1].start-stop-1; 
			else
				part_info->fspace_trk = last_trk - stop; 
		}
		else if (i == USABLE_PARTITIONS - 1)
			part_info->fspace_trk = last_trk - stop; 

		part_info = part_info->next;
	}
	return;
}


/*
 * Verifies the specified block device.
 */
static void
fdasd_verify_device (fdasd_anchor_t *anc, char *name) 
{
	struct stat dst;
	char err_str[ERROR_STRING_SIZE];

	if ((stat(name, &dst)) < 0 ) {
		snprintf(err_str, ERROR_STRING_SIZE,
			 "Unable to get device status for device '%s'\n",
			 name);
		fdasd_error(anc, device_verification_failed, err_str);
	}

	if (!(S_ISBLK (dst.st_mode))) {
		snprintf(err_str, ERROR_STRING_SIZE,
			 "Device '%s' (%d/%d) is not a block device\n", name,
			 (unsigned short) major(dst.st_rdev),
			 (unsigned short) minor(dst.st_rdev));
		fdasd_error(anc, device_verification_failed, err_str);
	}

	if (minor (dst.st_rdev) & PARTN_MASK) {
		snprintf(err_str, ERROR_STRING_SIZE,
			 "Partition '%s' (%d/%d) detected where device is "
			 "required\n", name,
			 (unsigned short) major(dst.st_rdev),
			 (unsigned short) minor(dst.st_rdev));

		fdasd_error(anc, device_verification_failed, err_str);
	}

	if (anc->verbose)
		printf("Verification successful for '%s' (%d/%d)\n", name,
		       (unsigned short) major(dst.st_rdev),
		       (unsigned short) minor(dst.st_rdev));
}


/*
 * Verifies the specified fdasd command line option
 * combinations.
 *
 * Note: 
 *  - 'version' and 'help' are priority options. 
 *       All other paramters are ignored in that case.
 *  - 'silent' and 'verbose' are allways allowed in any
 *       combination.
 * 
 */
static void 
fdasd_verify_options (fdasd_anchor_t *anc) 
{
	/* Checked option combinations                       */
	/* (inv = invalid / req = required / opt = optional) */
	/*                                                   */
	/*              vols labe keep auto conf tabl        */
	/*              er   l    _vol      if   e           */
	/*                        ser                        */
	/*                                                   */
	/* volser       -    inv  INV  inv  inv  inv         */
	/* label             -    inv  REQ  REQ  inv         */
	/* keep_volser            -    REQ  REQ  inv         */
	/* auto              opt  opt  -    inv  inv         */
	/* config            opt  opt       -    inv         */
	/* table                                 -           */

	if (anc->print_volser &&
	    (options.volser || anc->keep_volser || anc->auto_partition ||
	     options.conffile || anc->print_table)) {
		fdasd_error(anc, parser_failed,
			    "Option 'volser' cannot be used with other"
			    " options.\n");
	}

	if (options.volser) {
		if (!anc->auto_partition && !options.conffile) {
			fdasd_error(anc, parser_failed,
				    "Option 'auto' or 'config' required when"
				    " specifying 'label'\n");
		}
		if ((anc->keep_volser || anc->print_table)) {
			fdasd_error(anc, parser_failed,
				    "Option 'label' cannot be used with "
				    "'keep_volser' and 'table'.\n");
		}
	}

	if (anc->keep_volser) {
		if (!anc->auto_partition && !options.conffile) {
			fdasd_error(anc, parser_failed,
				    "Option 'auto' or 'config' required when"
				    " specifying 'keep_volser'\n");
		}
		if (anc->print_table) {
			fdasd_error(anc, parser_failed,
				    "Option 'keep_volser' cannot be used"
				    " with 'table'.\n");
		}
	}
	if (anc->auto_partition &&
	    (options.conffile || anc->print_table)) {
		fdasd_error(anc, parser_failed,
			    "Option 'auto' cannot be used with "
			    "'config' and 'table'.\n");
	}

	if (options.conffile  &&
	    (anc->print_table)) {
		fdasd_error(anc, parser_failed,
			    "Option 'config' cannot be used with"
			    " 'table'.\n");
	}
}


/*
 * print mapping: partition number - data set name
 */
static void
fdasd_show_mapping (fdasd_anchor_t *anc) 
{
	char str[20], *dev, dsname[45], *strp;
        partition_info_t *part_info;
	int i=0, j=0, dev_len;

        printf("\ndevice .........: %s\n",options.device);
	bzero(str, sizeof(str));
	vtoc_volume_label_get_label(anc->vlabel, str);
        printf("volume label ...: %.4s\n", str);
	bzero(str, sizeof(str));
	vtoc_volume_label_get_volser(anc->vlabel, str);
        printf("volume serial ..: %s\n\n", str);

	dev_len = strlen(options.device);
	dev = malloc(dev_len + 10);
	if (!dev)
                fdasd_error(anc, malloc_failed,
			    "Show mapping: memory allocation failed.");
        strcpy(dev, options.device);
        if (((strp = strstr(dev,DISC)) != NULL) ||
	    ((strp = strstr(dev,DEVICE)) != NULL))
                strcpy(strp, PART);

	printf("WARNING: This mapping may be NOT up-to-date,\n"
	       "         if you have NOT saved your last changes!\n\n");

	for (part_info = anc->first ; part_info != NULL;
	     part_info = part_info->next) {
                i++;
                if (part_info->used != 0x01)
			continue;

		bzero(dsname, sizeof(dsname));
		strncpy(dsname, part_info->f1->DS1DSNAM, 44);
		vtoc_ebcdic_dec(dsname, dsname, 44);
	
		if (getdsn(anc, i-1) < 0)
			sprintf(dsname, "new data set");

		printf("%s%-2d -  %-44s\n", dev, i, dsname);
		j++;
        }

	if (j == 0) printf("No partitions defined.\n");
	free(dev);
}


/*
 * prints only the volume serial
 */
static void 
fdasd_print_volser (fdasd_anchor_t *anc)
{
	char volser[VOLSER_LENGTH + 1];

	bzero(volser, VOLSER_LENGTH);
	vtoc_ebcdic_dec(anc->vlabel->volid, volser, VOLSER_LENGTH);
	printf("%6.6s\n", volser);
}


/*
 * print partition table
 */
static void
fdasd_list_partition_table (fdasd_anchor_t *anc) 
{
        partition_info_t *part_info;
        char str[20], *dev, *strp, *ch;
        int i=0, dev_len = strlen(options.device);

	if (!anc->silent) {
		printf("\nDisk %s: \n"
		       "  cylinders ............: %d\n"
		       "  tracks per cylinder ..: %d\n"
		       "  blocks per track .....: %d\n"
		       "  bytes per block ......: %d\n",
		       options.device, anc->formatted_cylinders, geo.heads,
		       geo.sectors, anc->blksize);

		vtoc_volume_label_get_label(anc->vlabel, str);
		printf("  volume label .........: %s\n", str);

		vtoc_volume_label_get_volser(anc->vlabel, str);

		printf("  volume serial ........: %s\n", str);
		printf("  max partitions .......: %d\n\n", USABLE_PARTITIONS);
	}

        if (dev_len < 20)
                dev_len = 20;

	if (!anc->silent) {
		printf(" ------------------------------- tracks"
		       " -------------------------------\n");
		printf("%*s      start      end   length   Id  System\n",
		       dev_len + 1, "Device");
	}

	dev = malloc(dev_len + 10);
	if (!dev)
                fdasd_error(anc, malloc_failed,
			    "Print partition table: memory allocation failed.");
        strcpy(dev, options.device);
        if (((strp = strstr(dev,DISC)) != NULL) ||
	    ((strp = strstr(dev,DEVICE)) != NULL))
                strcpy(strp, PART);

        for (part_info = anc->first; part_info != NULL;
	     part_info = part_info->next) {
		i++;

                if ((part_info == anc->first) && (anc->fspace_trk > 0)) 
                        printf("%*s   %9ld%9ld%9ld       unused\n",dev_len,"",
                                (unsigned long) FIRST_USABLE_TRK,
                                (unsigned long) FIRST_USABLE_TRK +
                                anc->fspace_trk - 1,
                                anc->fspace_trk);

                if (part_info->used != 0x01)
			continue;

		vtoc_ebcdic_dec(part_info->f1->DS1DSNAM,
				part_info->f1->DS1DSNAM, 44);
		ch = strstr(part_info->f1->DS1DSNAM, "PART");
		if (ch != NULL) {
			strncpy(str, ch + 9, 6);
			str[6] = '\0';
		} else
			strcpy(str, "error");

		vtoc_ebcdic_enc(part_info->f1->DS1DSNAM,
				part_info->f1->DS1DSNAM, 44);

		printf("%*s%-2d %9ld%9ld%9ld   %2x  %6s\n", 
		       dev_len, dev, i, part_info->start_trk,
		       part_info->end_trk, part_info->len_trk, i,
		       fdasd_partition_type(str));

		if (part_info->fspace_trk > 0) 
			printf("%*s   %9ld%9ld%9ld       unused\n",
			       dev_len , "" , part_info->end_trk + 1,
			       part_info->end_trk + part_info->fspace_trk,
			       part_info->fspace_trk);
        }
	free(dev);
}

/*
 * get volser from vtoc
 */
static int
fdasd_get_volser(fdasd_anchor_t *anc, char *devname, char *volser)
{
	volume_label_t vlabel;

	vtoc_read_volume_label(options.device, anc->label_pos, &vlabel);
	vtoc_volume_label_get_volser(&vlabel, volser);
	return 0;
}

/*
 * call IOCTL to re-read the partition table
 */
static void
fdasd_reread_partition_table (fdasd_anchor_t *anc)
{
	char err_str[ERROR_STRING_SIZE];
	int fd;

	if (!anc->silent) printf("rereading partition table...\n");

	if ((fd = open(options.device, O_RDONLY)) < 0) {
		snprintf(err_str, ERROR_STRING_SIZE,
			"Could not open device '%s' "
			"in read-only mode!\n", options.device);
		fdasd_error(anc, unable_to_open_disk, err_str);
	} 

	if (ioctl(fd, BLKRRPART, NULL) != 0) {
		close(fd);
		fdasd_error(anc, unable_to_ioctl, "Error while rereading "
			    "partition table.\nPlease reboot!");
	}
	close(fd);
} 


/*
 * writes all changes to dasd
 */
static void
fdasd_write_vtoc_labels (fdasd_anchor_t *anc) 
{
        partition_info_t *part_info;
	unsigned long blk, maxblk;
	char dsno[6], volser[VOLSER_LENGTH + 1], s2[45], *c1, *c2, *ch;
	int i=0, k=0;
	cchhb_t f9addr;
	format1_label_t emptyf1;

	if (!anc->silent) printf("writing VTOC...\n");
	if (anc->verbose) printf("DSCBs: ");

	blk = (cchhb2blk(&anc->vlabel->vtoc, &geo) - 1) * anc->blksize;
	if (blk <= 0) 
		fdasd_error(anc, vlabel_corrupted, "");
	maxblk = blk + anc->blksize * 9; /* f4+f5+f7+3*f8+3*f9 */

	/* write FMT4 DSCB */
	vtoc_write_label(options.device, blk, NULL, anc->f4, NULL, NULL, NULL);
	if (anc->verbose) printf("f4 ");
	blk += anc->blksize;

	/* write FMT5 DSCB */
	vtoc_write_label(options.device, blk, NULL, NULL, anc->f5, NULL, NULL);
	if (anc->verbose) printf("f5 ");
	blk += anc->blksize;

	/* write FMT7 DSCB */
	if (anc->big_disk) {
		vtoc_write_label(options.device, blk,  NULL, NULL,
				 NULL, anc->f7, NULL);
		if (anc->verbose) printf("f7 ");
		blk += anc->blksize;
	}

	/* loop over all partitions (format 1 or format 8 DCB) */
	for (part_info = anc->first; part_info != NULL;
	     part_info = part_info->next) {

		if (part_info->used != 0x01) {
			continue;
		}

		i++;
		strncpy((char *)part_info->f1->DS1DSSN,	anc->vlabel->volid,
			VOLSER_LENGTH);

		ch = part_info->f1->DS1DSNAM;
		vtoc_ebcdic_dec(ch, ch, 44);
		c1 = ch + 7;

		if (getdsn(anc, i-1) > -1) {
			/* re-use the existing data set name */
			c2 = strchr(c1, '.');
			if (c2 != NULL)
				strncpy(s2, c2, 31);
			else
				fdasd_error(anc, dsname_corrupted, "");

			strncpy(volser, anc->vlabel->volid, VOLSER_LENGTH);
			vtoc_ebcdic_dec(volser, volser, VOLSER_LENGTH);
			volser[VOLSER_LENGTH] = ' ';
			strncpy(c1, volser, VOLSER_LENGTH + 1);
			c1 = strchr(ch, ' ');
			strncpy(c1, s2, 31);
		}
		else {
			if (strstr(ch, "SWAP") != NULL)
				part_info->type = PARTITION_SWAP;
			else if (strstr(ch, "RAID") != NULL)
				part_info->type = PARTITION_RAID;
			else if (strstr(ch, "LVM") != NULL)
				part_info->type = PARTITION_LVM;
			else
				part_info->type = PARTITION_NATIVE;

			/* create a new data set name */
			while (getpos(anc, k) > -1)
				k++;

			setpos(anc, k, i-1);
			
			strncpy(ch, "LINUX.V               "
				"                      ", 44);

			strncpy(volser, anc->vlabel->volid, VOLSER_LENGTH);
			vtoc_ebcdic_dec(volser, volser, VOLSER_LENGTH);
			strncpy(c1, volser, VOLSER_LENGTH);
				
			c1 = strchr(ch, ' ');
			strncpy(c1, ".PART", 5);
			c1 += 5;

			sprintf(dsno,"%04d", k+1);
			strncpy(c1, dsno, 4);

			c1 += 4;

			switch (part_info->type) {
			case PARTITION_NATIVE:
				strncpy(c1, ".NATIVE", 7);
				break;
			case PARTITION_SWAP:
				strncpy(c1, ".SWAP", 5);
				break;
			case PARTITION_RAID:
				strncpy(c1, ".RAID", 5);
				break;
			case PARTITION_LVM:
				strncpy(c1, ".LVM", 4);
				break;
			}
		}
		vtoc_ebcdic_enc(ch, ch, 44);
		if (anc->verbose) printf("%2x ", part_info->f1->DS1FMTID);

		if (part_info->f1->DS1FMTID == 0xf8) {
			/* Now as we know where which label will be written, we
			 * can add the address of the format 9 label to the
			 * format 8 label. The f9 record will be written to the
			 * block after the current blk. Remember: records are of
			 * by one, so we have to add 2 and not just one.
			 */
			vtoc_set_cchhb(&f9addr, VTOC_START_CC, VTOC_START_HH,
				       ((blk / anc->blksize) % geo.sectors)
				       + 2);
			vtoc_update_format8_label(&f9addr, part_info->f1);
			vtoc_write_label(options.device, blk, part_info->f1,
					 NULL, NULL, NULL, NULL);
			blk += anc->blksize;
			vtoc_write_label(options.device, blk,  NULL, NULL,
					 NULL, NULL, anc->f9);
			if (anc->verbose) printf("f9 ");
			blk += anc->blksize;
		} else {
			vtoc_write_label(options.device, blk, part_info->f1,
					 NULL, NULL, NULL, NULL);
			blk += anc->blksize;
		}
	}

	/* write empty labels to the rest of the blocks */
	bzero(&emptyf1, sizeof(emptyf1));
	while (blk < maxblk) {
		vtoc_write_label(options.device, blk, &emptyf1, NULL,
				 NULL, NULL, NULL);
		if (anc->verbose) printf("empty ");
		blk += anc->blksize;
	}

	if (anc->verbose) printf("\n");
}


/*
 * writes all changes to dasd
 */
static void
fdasd_write_labels (fdasd_anchor_t *anc) 
{
        if (anc->vlabel_changed) {
		if (!anc->silent) printf("writing volume label...\n");
	        vtoc_write_volume_label(options.device, anc->label_pos,
					anc->vlabel);
	}

	if (anc->vtoc_changed) 
		fdasd_write_vtoc_labels(anc);

        if ((anc->vtoc_changed)||(anc->vlabel_changed)) 
		fdasd_reread_partition_table(anc);
}


/*
 * re-creates the VTOC and deletes all partitions
 */
static void fdasd_recreate_vtoc_unconditional(fdasd_anchor_t *anc)
{
	partition_info_t *part_info = anc->first;
	int i;

	vtoc_init_format4_label(anc->f4, USABLE_PARTITIONS,
				geo.cylinders, anc->formatted_cylinders,
				geo.heads, geo.sectors,
				anc->blksize, anc->dev_type);

	vtoc_init_format5_label(anc->f5);
	vtoc_init_format7_label(anc->f7);
	vtoc_set_freespace(anc->f4,anc->f5, anc->f7, '+', anc->verbose,
			   FIRST_USABLE_TRK,
			   anc->formatted_cylinders * geo.heads - 1,
			   anc->formatted_cylinders, geo.heads);

	while (part_info != NULL) {

		bzero(part_info->f1, sizeof(format1_label_t));

		if (part_info->used == 0x01) {
			part_info->used       = 0x00;
			part_info->start_trk  = 0;
			part_info->end_trk    = 0;
			part_info->len_trk    = 0;
			part_info->fspace_trk = 0;
		}

		part_info = part_info->next;
	}

	anc->used_partitions = 0;
	anc->fspace_trk = anc->formatted_cylinders * geo.heads
		- FIRST_USABLE_TRK;

	for (i=0; i<USABLE_PARTITIONS; i++)
		setpos(anc, i, -1);

	anc->vtoc_changed++;
}

/*
 * asks user for confirmation before recreating the vtoc
 */
static void fdasd_recreate_vtoc(fdasd_anchor_t *anc)
{
	char str[INPUT_BUF_SIZE];

	if (!anc->silent) {
		snprintf(str, INPUT_BUF_SIZE,
			 "WARNING: All partitions on device '%s' will be "
			 "deleted!\nDo you want to continue?",
			 options.device);

		if (yes_no(str) != 0)
			return;

		printf("creating new VTOC... ");
	}
	fdasd_recreate_vtoc_unconditional(anc);
	if (!anc->silent) printf("ok\n");
}


/*
 * re-create all VTOC labels, but use the partition information
 * from existing VTOC
 */
static void
fdasd_reuse_vtoc(fdasd_anchor_t *anc)
{
	partition_info_t *part_info = anc->first;
	format1_label_t f1;
	format4_label_t f4;
	format5_label_t f5;
	format7_label_t f7;
	char str[INPUT_BUF_SIZE];

	if (!anc->silent) {
		snprintf(str, INPUT_BUF_SIZE, 
			"WARNING: this will re-create your VTOC "
			"entries using the partition\n           "
			"information of your existing VTOC. Continue?");

		if (yes_no(str) != 0)
			return;
	}

	if (!anc->silent) printf("re-creating VTOC... ");

	vtoc_init_format4_label(&f4, USABLE_PARTITIONS,
				geo.cylinders, anc->formatted_cylinders,
				geo.heads, geo.sectors,
				anc->blksize, anc->dev_type);

	/* reuse some FMT4 values */
	f4.DS4HPCHR = anc->f4->DS4HPCHR;
	f4.DS4DSREC = anc->f4->DS4DSREC;

	/* re-initialize both free-space labels */
	vtoc_init_format5_label(&f5);
	vtoc_init_format7_label(&f7);

	if (anc->fspace_trk > 0)
		vtoc_set_freespace(&f4, &f5, &f7, '+', anc->verbose,
				   FIRST_USABLE_TRK, 
				   FIRST_USABLE_TRK + anc->fspace_trk - 1,
				   anc->formatted_cylinders, geo.heads);

	while (part_info != NULL) {
		if (part_info->used != 0x01) {
			part_info = part_info->next;
			continue;
		}

		if (anc->formatted_cylinders > LV_COMPAT_CYL)
			vtoc_init_format8_label(anc->vlabel->volid,
						anc->blksize,
						&part_info->f1->DS1EXT1, &f1);
		else
			vtoc_init_format1_label(anc->vlabel->volid,
						anc->blksize,
						&part_info->f1->DS1EXT1, &f1);


		strncpy(f1.DS1DSNAM, part_info->f1->DS1DSNAM, 44);
		strncpy((char *)f1.DS1DSSN, (char *)part_info->f1->DS1DSSN, 6);
		f1.DS1CREDT = part_info->f1->DS1CREDT;

		memcpy(part_info->f1, &f1, sizeof(format1_label_t));

		if (part_info->fspace_trk > 0)
			vtoc_set_freespace(&f4, &f5, &f7, '+', anc->verbose,
					   part_info->end_trk + 1, 
					   part_info->end_trk +
					   part_info->fspace_trk,
					   anc->formatted_cylinders, geo.heads);

		part_info = part_info->next;
	}

	/* over-write old labels with new ones */
	memcpy(anc->f4, &f4, sizeof(format4_label_t));
	memcpy(anc->f5, &f5, sizeof(format5_label_t));
	memcpy(anc->f7, &f7, sizeof(format7_label_t));

	if (!anc->silent) printf("ok\n");
	anc->vtoc_changed++;

	return;
}


/*
 * Changes the volume serial (menu option)
 */
static void
fdasd_change_volser (fdasd_anchor_t *anc) 
{
	char volser[VOLSER_LENGTH + 1];

	vtoc_volume_label_get_volser(anc->vlabel, volser);
	printf("Please specify new volume serial (6 characters).\n");
	printf("current     : %-6.6s\nnew [0X%04x]: ", volser, anc->devno);

	read_line();
	fdasd_check_volser(line_ptr, anc->devno);

	printf("\nvolume identifier changed to '%-6s'\n",line_ptr);
	vtoc_volume_label_set_volser(anc->vlabel, line_ptr);

	vtoc_set_cchhb(&anc->vlabel->vtoc, VTOC_START_CC, VTOC_START_HH, 0x01);
	anc->vlabel_changed++;
	anc->vtoc_changed++;
}


/*
 * changes the partition type
 */
static void
fdasd_change_part_type (fdasd_anchor_t *anc)
{
        unsigned int part_id, part_type, i;
	char str[20], *ch;
        partition_info_t *part_info;

	fdasd_list_partition_table(anc);

	/* ask for partition number */
	printf("\nchange partition type\n");
        while (!isdigit(part_id = read_char("partition id (use 0 to exit): ")))
		printf("Invalid partition id '%c' detected.\n", part_id);

        part_id -= 48;
	printf("\n");
        if (part_id == 0) 
		return;
        if (part_id > anc->used_partitions) {
                printf("'%d' is not a valid partition id!\n", part_id);
                return;
        }

	part_info = anc->first;
        for (i=1; i < part_id; i++) 
		part_info = part_info->next;

	/* ask for partition type */
	vtoc_ebcdic_dec(part_info->f1->DS1DSNAM, part_info->f1->DS1DSNAM, 44);
	ch = strstr(part_info->f1->DS1DSNAM, "PART") + 9;
	if (ch != NULL) {
		strncpy(str, ch, 6);
		str[6] = '\0';
	} else
		strcpy(str, "error");

	printf("current partition type is: %s\n\n", fdasd_partition_type(str));
	printf("   1  Linux native\n" \
	       "   2  Linux swap\n" \
	       "   3  Linux raid\n" \
	       "   4  Linux lvm\n\n");
	part_type = 0;
	while ((part_type < 1) || (part_type > 4)) {
        	while (!isdigit(part_type =
				read_char("new partition type: ")));
        	part_type -= 48;
	}

        switch (part_type) {
	case PARTITION_NATIVE:
		strncpy(str, "NATIVE", 6);
		break;
	case PARTITION_SWAP:
		strncpy(str, "SWAP  ", 6);
		break;
	case PARTITION_RAID:
		strncpy(str, "RAID  ", 6);
		break;
	case PARTITION_LVM:
		strncpy(str, "LVM   ", 6);
		break;

	default:
                printf("'%d' is not supported!\n", part_type);
        }

	ch = strstr(part_info->f1->DS1DSNAM, "PART") + 9;
	if (ch != NULL)	
		strncpy(ch, str, 6);
	vtoc_ebcdic_enc(part_info->f1->DS1DSNAM, part_info->f1->DS1DSNAM, 44);
        anc->vtoc_changed++;
}



/*
 * initialize the VOL1 volume label
 */
static void
fdasd_init_volume_label(fdasd_anchor_t *anc)
{
	volume_label_t *vlabel = anc->vlabel;
	char volser[VOLSER_LENGTH + 1];

	vtoc_volume_label_init(vlabel);
	vtoc_volume_label_set_key(vlabel, "VOL1");
	vtoc_volume_label_set_label(vlabel, "VOL1");

	if (anc->keep_volser) {
		if(fdasd_get_volser(anc, options.device, volser) == 0)
			vtoc_volume_label_set_volser(vlabel, volser);
		else
			fdasd_error(anc, volser_not_found, options.device);
	} else if (options.volser) {
		fdasd_check_volser(options.volser, anc->devno);
		vtoc_volume_label_set_volser(vlabel, options.volser);
	} else if (anc->auto_partition || options.conffile) {
		sprintf(volser, "0X%04x", anc->devno);
		vtoc_volume_label_set_volser(vlabel, volser);
	} else {
		printf("\nPlease specify volume serial (6 characters)"
		       "[0X%04x]: ",
		       anc->devno);
		read_line();
		fdasd_check_volser(line_ptr, anc->devno);
		vtoc_volume_label_set_volser(vlabel, line_ptr);
	}

	vtoc_set_cchhb(&vlabel->vtoc, VTOC_START_CC, VTOC_START_HH, 0x01);
	anc->vlabel_changed++;
}


/*
 * sets some important partition data
 * (like used, start_trk, end_trk, len_trk)
 * by calculating these values with the
 * information provided in the labels
 */
static void
fdasd_update_partition_info (fdasd_anchor_t *anc) 
{
        partition_info_t *prev_part_info = NULL, *part_info = anc->first;
	unsigned long max = anc->formatted_cylinders * geo.heads - 1;
        int i;

	anc->used_partitions = geo.sectors - 2 - anc->f4->DS4DSREC;

        for (i=1; i<=USABLE_PARTITIONS; i++) {
		if (part_info->f1->DS1FMTID != 0xf1 &&
		    part_info->f1->DS1FMTID != 0xf8) {
		        if (i == 1)
				/* there is no partition at all */
				anc->fspace_trk = max - FIRST_USABLE_TRK + 1;
			else
			        /* previous partition was the last one */
			        prev_part_info->fspace_trk = 
					max - prev_part_info->end_trk;
			break;
		}
		
		/* this is a valid format 1 label */
		part_info->used = 0x01;
		part_info->start_trk = cchh2trk(&part_info->f1->DS1EXT1.llimit,
						&geo);
		part_info->end_trk = cchh2trk(&part_info->f1->DS1EXT1.ulimit,
					      &geo);

		part_info->len_trk = part_info->end_trk -
			part_info->start_trk + 1;
		
		if (i == 1) 
		        /* first partition, there is at least one */
			anc->fspace_trk = 
				part_info->start_trk - FIRST_USABLE_TRK;
		else {
		        if (i == USABLE_PARTITIONS) 
			        /* last possible partition */
			        part_info->fspace_trk = 
					max - part_info->end_trk;

			/* set free space values of previous partition */
		        prev_part_info->fspace_trk = part_info->start_trk - 
				prev_part_info->end_trk - 1;
		}

	        prev_part_info = part_info;
	        part_info = part_info->next;
	}
}

/*
 * reorganizes all FMT1s, move all empty labels to the end 
 */
static void
fdasd_reorganize_FMT1s (fdasd_anchor_t *anc) 
{
	int i, j;
	format1_label_t *f1_label;
	partition_info_t *part_info;

	for (i=1; i<=USABLE_PARTITIONS - 1; i++) {
		part_info = anc->first;
		for (j=1; j<=USABLE_PARTITIONS - i; j++) {
			if (part_info->f1->DS1FMTID < 
			    part_info->next->f1->DS1FMTID) {
				f1_label = part_info->f1;
				part_info->f1 = part_info->next->f1;
				part_info->next->f1 = f1_label;
			}
			part_info = part_info->next;
		}
	}
}


/*
 * we have a invalid FMT4 DSCB and therefore we will re-create the VTOC
 */
static void
fdasd_process_invalid_vtoc(fdasd_anchor_t *anc)
{
	printf(" invalid\ncreating new VTOC...\n");
	if (anc->hw_cylinders > LV_COMPAT_CYL) {
		printf("Warning: Device has more then %u cylinders!\n",
			       LV_COMPAT_CYL);
		if (yes_no("Are you sure it was completely"
			   " formatted with dasdfmt?") == 1) {
			if (!anc->silent) printf("exiting...\n");
			fdasd_exit(anc, 0);
		}
	}
	anc->formatted_cylinders = anc->hw_cylinders;
	anc->fspace_trk = anc->formatted_cylinders * geo.heads
		- FIRST_USABLE_TRK;
	vtoc_init_format4_label(anc->f4, USABLE_PARTITIONS,
				geo.cylinders, anc->formatted_cylinders,
				geo.heads, geo.sectors,
				anc->blksize, anc->dev_type);

	vtoc_init_format5_label(anc->f5);
	vtoc_init_format7_label(anc->f7);
	vtoc_set_freespace(anc->f4, anc->f5, anc->f7, '+', anc->verbose,
			   FIRST_USABLE_TRK,
			   anc->formatted_cylinders * geo.heads - 1,
			   anc->formatted_cylinders, geo.heads);

	anc->vtoc_changed++;
}


/*
 *
 */
static void
fdasd_process_valid_vtoc(fdasd_anchor_t *anc, unsigned long blk)
{
	int f1_counter = 0, f7_counter = 0, f5_counter = 0;
	int i, part_no, f1_size = sizeof(format1_label_t);
	partition_info_t *part_info = anc->first;
	format1_label_t f1_label;
	char part_no_str[5], *part_pos;

	if (!anc->silent) printf(" ok\n");

	if (anc->f4->DS4DEVCT.DS4DSCYL == LV_COMPAT_CYL &&
	    anc->f4->DS4DCYL > anc->f4->DS4DEVCT.DS4DSCYL)
		anc->formatted_cylinders = anc->f4->DS4DCYL;
	else
		anc->formatted_cylinders = anc->f4->DS4DEVCT.DS4DSCYL;
	anc->fspace_trk = anc->formatted_cylinders * geo.heads
		- FIRST_USABLE_TRK;
	/* skip f4 label, already read before */
	blk += anc->blksize;

	if (anc->formatted_cylinders < anc->hw_cylinders)
		printf("WARNING: This device is not fully formatted! "
		       "Only %u of %u cylinders are available.\n",
		       anc->formatted_cylinders, anc->hw_cylinders);

	if (anc->verbose) printf("VTOC DSCBs          : ");

	/* go through remaining labels, f4 label already done */
	for (i = 1; i < geo.sectors; i++) {
		bzero(&f1_label, f1_size);
		vtoc_read_label(options.device, blk, &f1_label, NULL, NULL,
				NULL);

		switch (f1_label.DS1FMTID) {
		case 0xf1:
		case 0xf8:
			if (anc->verbose)
				printf("%s ",
				       f1_label.DS1FMTID == 0xf1 ? "f1" : "f8");
			if (part_info == NULL)
				break;
			memcpy(part_info->f1, &f1_label, f1_size);

			part_no = -1;
			vtoc_ebcdic_dec(part_info->f1->DS1DSNAM,
					part_info->f1->DS1DSNAM, 44);
			part_pos = strstr(part_info->f1->DS1DSNAM, "PART");
			if (part_pos != NULL) {
				strncpy(part_no_str, part_pos + 4, 4);
				part_no_str[4] = '\0';
				part_no = atoi(part_no_str) - 1;
			}

			vtoc_ebcdic_enc(part_info->f1->DS1DSNAM,
					part_info->f1->DS1DSNAM, 44);

			if ((part_no < 0) || (part_no >= USABLE_PARTITIONS))
				printf("WARNING: partition number (%i) found "
				       "in data set name of an existing "
				       "partition\ndoes not match range of "
				       "possible partition numbers (1-%d)\n\n",
				       part_no + 1, USABLE_PARTITIONS);
			else
				setpos(anc, part_no, f1_counter);

			part_info = part_info->next;
			f1_counter++;
			break;
		case 0xf5:
			if (anc->verbose) printf("f5 ");
			memcpy(anc->f5, &f1_label, f1_size);
			f5_counter++;
			break;
		case 0xf7:
			if (anc->verbose) printf("f7 ");
			if (f7_counter == 0)
				memcpy(anc->f7, &f1_label, f1_size);
			f7_counter++;
			break;
		case 0xf9:
			/* each format 8 lable has an associated format 9 lable,
			 * but they are of no further use to us.
			 */
			if (anc->verbose) printf("f9 ");
			break;
		default: 
			if (f1_label.DS1FMTID > 0)
				printf("'%d' is not supported!\n", 
				       f1_label.DS1FMTID);
		}
		blk += anc->blksize;
	}
		
	if (anc->verbose) printf("\n");

	if ((f5_counter == 0) || (anc->big_disk)) 
		vtoc_init_format5_label(anc->f5);
		
	if (f7_counter == 0) 
		vtoc_init_format7_label(anc->f7);

	fdasd_reorganize_FMT1s(anc);
	fdasd_update_partition_info(anc);
}


/*
 * we have a valid VTOC pointer, let's go and read the VTOC labels
 */
static int
fdasd_valid_vtoc_pointer(fdasd_anchor_t *anc, unsigned long blk)
{
	/* VOL1 label contains valid VTOC pointer */
	if (!anc->silent)
		printf("reading vtoc ..........:");

	vtoc_read_label(options.device, blk, NULL, anc->f4, NULL, NULL);

	if (anc->f4->DS4IDFMT != 0xf4) { 
		if (anc->print_table) {
			printf("Your VTOC is corrupted!\n");
			return -1;
		}
		fdasd_process_invalid_vtoc(anc);
	} else
		fdasd_process_valid_vtoc(anc, blk);

	return 0;
}


/*
 *
 */
static void
fdasd_invalid_vtoc_pointer(fdasd_anchor_t *anc)
{
	/* VOL1 label doesn't contain valid VTOC pointer */
	if (yes_no("There is no VTOC yet, should I create one?") == 1) {
		if (!anc->silent) printf("exiting...\n");
		fdasd_exit(anc, 0);
	}

	if (anc->hw_cylinders > LV_COMPAT_CYL) {
		printf("Warning: Device has more then %u cylinders!\n",
			       LV_COMPAT_CYL);
		if (yes_no("Are you sure it was completely"
			   " formatted with dasdfmt?") == 1) {
			if (!anc->silent) printf("exiting...\n");
			fdasd_exit(anc, 0);
		}
	}
	anc->formatted_cylinders = anc->hw_cylinders;
	anc->fspace_trk = anc->formatted_cylinders * geo.heads
		- FIRST_USABLE_TRK;
	vtoc_init_format4_label(anc->f4, USABLE_PARTITIONS,
				geo.cylinders, anc->formatted_cylinders,
				geo.heads, geo.sectors,
				anc->blksize, anc->dev_type);

	vtoc_init_format5_label(anc->f5);
	vtoc_init_format7_label(anc->f7);

	vtoc_set_freespace(anc->f4, anc->f5, anc->f7, '+', anc->verbose,
			   FIRST_USABLE_TRK,
			   anc->formatted_cylinders * geo.heads - 1,
			   anc->formatted_cylinders, geo.heads);

	vtoc_set_cchhb(&anc->vlabel->vtoc, VTOC_START_CC, VTOC_START_HH, 0x01);

	anc->vtoc_changed++;
	anc->vlabel_changed++;
}


/*
 * check the dasd for a volume label
 */
static int
fdasd_check_volume (fdasd_anchor_t *anc) 
{
	volume_label_t *vlabel = anc->vlabel;
	long long blk = -1;
	char str[LINE_LENGTH];
	char inp_buf[INPUT_BUF_SIZE];
	int rc = 1;

	if (!anc->silent)
		printf("reading volume label ..:");

        vtoc_read_volume_label(options.device, anc->label_pos, vlabel);

	if (strncmp(vlabel->vollbl, vtoc_ebcdic_enc("VOL1",str,4),4) == 0) {
	        /* found VOL1 volume label */
		if (!anc->silent)
			printf(" VOL1\n");

		blk = (cchhb2blk(&vlabel->vtoc, &geo) - 1) * anc->blksize;
		if (blk > 0) {
			int rc;
			rc = fdasd_valid_vtoc_pointer(anc, blk);

			if (anc->print_table && (rc < 0))
				return -1;
		}
		else {
			if (anc->print_table) {
				printf("\nFound invalid VTOC pointer.\n");
				return -1;
			}
			fdasd_invalid_vtoc_pointer(anc);
		}
	} else {
	        /* didn't find VOL1 volume label */

 		if (anc->print_table || anc->print_volser) {
			printf("\nCannot show requested information because "
			       "the disk label block is invalid\n");
			return -1;
		}

	        if (strncmp(vlabel->vollbl, 
			    vtoc_ebcdic_enc("LNX1",str,4),4) == 0) {
			if (!anc->silent)
				printf(" LNX1\n");
			strcpy(inp_buf,"Overwrite inapplicable label?");
		} else {
			if (!anc->silent)
				printf(" no known label\n");
			if (!anc->auto_partition && !options.conffile)
				rc = yes_no("Should I create a new one?");
			else
				rc = 0;
		}
                if ((!anc->print_volser) && (!anc->print_table) && (rc == 1)) {
			printf("Disc does not contain a VOL1 label, cannot "
			       "create partitions.\nexiting... \n");
			fdasd_exit(anc, -1);
                }

		if (anc->hw_cylinders > LV_COMPAT_CYL) {
			printf("Warning: Device has more than %u cylinders!\n",
			       LV_COMPAT_CYL);
			if (!anc->auto_partition && !options.conffile &&
			    yes_no("Are you sure it was completely"
				   " formatted with dasdfmt?") == 1) {
				if (!anc->silent) printf("exiting...\n");
				fdasd_exit(anc, 0);
			}
		}
		anc->formatted_cylinders = anc->hw_cylinders;
		anc->fspace_trk = anc->formatted_cylinders * geo.heads
				  - FIRST_USABLE_TRK;

		fdasd_init_volume_label(anc);

		vtoc_init_format4_label(anc->f4, USABLE_PARTITIONS,
					geo.cylinders, anc->formatted_cylinders,
					geo.heads, geo.sectors,
					anc->blksize, anc->dev_type);

		vtoc_init_format5_label(anc->f5);
		vtoc_init_format7_label(anc->f7);

		vtoc_set_freespace(anc->f4, anc->f5, anc->f7, '+',
				   anc->verbose, FIRST_USABLE_TRK,
				   anc->formatted_cylinders * geo.heads - 1,
				   anc->formatted_cylinders, geo.heads);

		anc->vtoc_changed++;
	}

	if (!anc->silent)
		printf("\n");

	return 0;
}


/*
 * check disk access
 */
static void
fdasd_check_disk_access (fdasd_anchor_t *anc)
{
	char err_str[ERROR_STRING_SIZE];
	format1_label_t f1;
	int fd, pos, ro;

        if ((fd = open(options.device, O_RDONLY)) == -1) {
		snprintf(err_str, ERROR_STRING_SIZE,
			"Could not open device '%s' " \
			"in read-only mode!\n", options.device);
		fdasd_error(anc, unable_to_open_disk, err_str);
	}

	pos = anc->blksize * (2 * geo.heads - 1);
	/* last block in the second track */
        if (lseek(fd, pos, SEEK_SET) == -1) {
	        close(fd);
		snprintf(err_str, ERROR_STRING_SIZE, 
			"Could not seek device '%s'.", options.device);
		fdasd_error(anc, unable_to_seek_disk, err_str);
        }

	if (read(fd, &f1, sizeof(format1_label_t)) != 
	    sizeof(format1_label_t)) {
		close(fd);
		snprintf(err_str, ERROR_STRING_SIZE,
			"Could not read from device '%s'.", options.device);
		fdasd_error(anc, unable_to_read_disk, err_str);
	}

        if (lseek(fd, pos, SEEK_SET) == -1) {
	        close(fd);
		snprintf(err_str, ERROR_STRING_SIZE, 
			"Could not seek device '%s'.", options.device);
		fdasd_error(anc, unable_to_seek_disk, err_str);
        }
	
	if (ioctl(fd, BLKROGET, &ro) != 0) {
		snprintf(err_str, ERROR_STRING_SIZE, 
			 "Could not get read-only status for device '%s'.",
			 options.device);
		fdasd_error(anc, unable_to_ioctl, err_str);
	}
	if (ro && !anc->print_volser && !anc->print_table)
		printf("\nWARNING: Device '%s' is a read-only device!\n"
		       "You will not be able to save any changes.\n\n",
		       options.device);

        close(fd);
}     

/*
 * The following two functions match those in the DASD ECKD device driver.
 * They are used to compute how many records of a given size can be stored
 * in one track.
 */
static unsigned int ceil_quot(unsigned int d1, unsigned int d2)
{
	return (d1 + (d2 - 1)) / d2;
}

/* kl: key length, dl: data length */
static unsigned int recs_per_track(unsigned short dev_type, unsigned int kl,
				   unsigned int dl)
{
	int dn, kn;

	switch (dev_type) {
	case DASD_3380_TYPE:
		if (kl)
			return 1499 / (15 + 7 + ceil_quot(kl + 12, 32) +
				       ceil_quot(dl + 12, 32));
		else
			return 1499 / (15 + ceil_quot(dl + 12, 32));
	case DASD_3390_TYPE:
		dn = ceil_quot(dl + 6, 232) + 1;
		if (kl) {
			kn = ceil_quot(kl + 6, 232) + 1;
			return 1729 / (10 + 9 + ceil_quot(kl + 6 * kn, 34) +
				       9 + ceil_quot(dl + 6 * dn, 34));
		} else
			return 1729 / (10 + 9 + ceil_quot(dl + 6 * dn, 34));
	case DASD_9345_TYPE:
		dn = ceil_quot(dl + 6, 232) + 1;
		if (kl) {
			kn = ceil_quot(kl + 6, 232) + 1;
			return 1420 / (18 + 7 + ceil_quot(kl + 6 * kn, 34) +
				       ceil_quot(dl + 6 * dn, 34));
		} else
			return 1420 / (18 + 7 + ceil_quot(dl + 6 * dn, 34));
	}
	return 0;
}

/*
 * Verify that number of tracks (heads) per cylinder and number of
 * sectors per track match the expected values for a given device type
 * and block size.
 * Returns 1 for a valid match and 0 otherwise.
 */
static int fdasd_verify_geometry(unsigned short dev_type, int blksize,
				 struct hd_geometry *geometry)
{
	unsigned int expected_sectors;
	if (geometry->heads != 15)
		return 0;
	expected_sectors = recs_per_track(dev_type, 0, blksize);
	if (geometry->sectors == expected_sectors)
		return 1;
	return 0;
}

/*
 * reads dasd geometry data
 */
static void fdasd_get_geometry (fdasd_anchor_t *anc)
{
        int fd, blksize = 0;
	dasd_information_t dasd_info;
	char err_str[ERROR_STRING_SIZE];
	struct dasd_eckd_characteristics *characteristics;
	unsigned long long size_in_bytes;

	if ((fd = open(options.device,O_RDONLY)) < 0) {
		snprintf(err_str, ERROR_STRING_SIZE,
			"Could not open device '%s' "
			"in read-only mode!\n", options.device);
		fdasd_error(anc, unable_to_open_disk, err_str);
	}
	if (ioctl(fd, BLKGETSIZE64, &size_in_bytes) != 0) {
		close(fd);
		fdasd_error(anc, unable_to_ioctl,
			    "Could not retrieve disk size.");
	}
	/*
	 * If anc->force_virtual is set, we do no real geometry detection.
	 * anc->dev_type and anc->blksize have already been set via command
	 * line parameter, and the rest of the geometry is now computed from
	 * these values.
	 */
	if (anc->force_virtual) {
		geo.heads = 15;
		geo.sectors = recs_per_track(anc->dev_type, 0, anc->blksize);
		anc->hw_cylinders = size_in_bytes /
			(anc->blksize * geo.heads * geo.sectors);
		if (anc->hw_cylinders < LV_COMPAT_CYL)
			geo.cylinders = anc->hw_cylinders;
		else
			geo.cylinders = LV_COMPAT_CYL;
		geo.start = 0;
		anc->label_pos = 2 * anc->blksize;
		anc->devno = 0;
		close(fd);
		if (anc->verbose)
			printf("The force option is active. "
			       "The following geometry will be used:\n"
			       "device type %x, block size %d, cylinders %d,"
			       " heads %d, sectors %d \n",
			       anc->dev_type, anc->blksize, anc->hw_cylinders,
			       geo.heads, geo.sectors);
		return;
	}

	if (ioctl(fd, HDIO_GETGEO, &geo) != 0) {
		close(fd);
		fdasd_error(anc, unable_to_ioctl,
			    "Could not retrieve disk geometry information.");
	}
	if (ioctl(fd, BLKSSZGET, &blksize) != 0) {
		close(fd);
		fdasd_error(anc, unable_to_ioctl,
			    "Could not retrieve blocksize information.");
	}
	/* get disk type */
	if (ioctl(fd, BIODASDINFO, &dasd_info) != 0) {
		if (anc->verbose)
			printf("BIODASDINFO ioctl failed,"
			       " use disk geometry only.\n");
		/* verify that the geometry matches a 3390 DASD */
		if (!fdasd_verify_geometry(DASD_3390_TYPE, blksize, &geo)) {
			close(fd);
			fdasd_error(anc, wrong_disk_type,
				    "Disk geometry does not match a DASD device"
				    " of type 3390.");
		}
		anc->dev_type = DASD_3390_TYPE;
		anc->blksize = blksize;
		anc->hw_cylinders =
			size_in_bytes /	(blksize * geo.heads * geo.sectors);
		/* The VOL1 label on a CDL formatted ECKD DASD is in block 2
		 * It will be verified later, if this position actually holds a
		 * valid label record.
		 */
		anc->label_pos = 2 * blksize;
		/* A devno 0 is actually a valid devno, which could exist
		 * in the system. Since we use this number only to create
		 * a default volume serial, there is no serious conflict.
		 */
		anc->devno = 0;
		if (anc->verbose)
			printf("The following device geometry will be used:\n"
			       "device type %x, block size %d, cylinders %d,"
			       " heads %d, sectors %d \n",
			       anc->dev_type, anc->blksize, anc->hw_cylinders,
			       geo.heads, geo.sectors);


	} else {
		characteristics = (struct dasd_eckd_characteristics *)
			&dasd_info.characteristics;
		if (characteristics->no_cyl == LV_COMPAT_CYL &&
		    characteristics->long_no_cyl)
			anc->hw_cylinders = characteristics->long_no_cyl;
		else
			anc->hw_cylinders = characteristics->no_cyl;

		if (strncmp(dasd_info.type, "ECKD", 4) != 0) {
			snprintf(err_str, ERROR_STRING_SIZE,
				 "%s is not an ECKD disk! This disk type "
				 "is not supported!", options.device);
			fdasd_error(anc,wrong_disk_type, err_str);
		}

		if (anc->verbose) printf("disk type check     : ok\n");

		if (dasd_info.FBA_layout != 0) {
			snprintf(err_str, ERROR_STRING_SIZE,
				 "%s is not formatted with z/OS compatible "
				 "disk layout!", options.device);
			fdasd_error(anc, wrong_disk_format, err_str);
		}

		if (anc->verbose) printf("disk layout check   : ok\n");

		if (dasd_info.open_count > 1) {
			if (anc->auto_partition) {
				snprintf(err_str, ERROR_STRING_SIZE,
					 "DASD '%s' is in use. Unmount it first!",
					 options.device);
				fdasd_error(anc, disk_in_use, err_str);
			} else {
				printf("\nWARNING: Your DASD '%s' is in use.\n"
				       "         If you proceed, you can "
				       "heavily damage your system.\n"
				       "         If possible exit all"
				       " applications using this disk\n"
				       "         and/or unmount it.\n\n",
				       options.device);
			}
		}

		if (anc->verbose) printf("usage count check   : ok\n");

		anc->dev_type   = dasd_info.dev_type;
		anc->blksize    = blksize;
		anc->label_pos  = dasd_info.label_block * blksize;
		anc->devno      = dasd_info.devno;
	}

	close(fd);
}


/*
 * asks for partition boundaries
 */
static unsigned long
fdasd_read_int (unsigned long low, unsigned long dflt, unsigned long high, 
		enum offset base, char *mesg, fdasd_anchor_t *anc) 
{
	unsigned long long trk = 0;
	unsigned int use_default = 1;
	char msg_txt[70];

	switch(base) {
	case lower:
	        sprintf(msg_txt, "%s ([%ld]-%ld): ", mesg, low, high);
		break;
	case upper:
	        sprintf(msg_txt, "%s (%ld-[%ld]): ", mesg, low, high);
		break;
	default:
	        sprintf(msg_txt, "%s (%ld-%ld): ", mesg, low, high);
		break;
	}

	while (1) {
	        while (!isdigit(read_char(msg_txt))
		       && (*line_ptr != '-' && 
			   *line_ptr != '+' &&
			   *line_ptr != '\0'))
		        continue;
		if ((*line_ptr == '+' || *line_ptr == '-') &&
			base != lower) {
		        if (*line_ptr == '+')
			        ++line_ptr;
			trk = atoi(line_ptr);
			while (isdigit(*line_ptr)) {
			        line_ptr++;
				use_default = 0;
			}

                        switch (*line_ptr) {
			case 'c':
			case 'C': 
				trk *= geo.heads;
				break;
			case 'k':
			case 'K': 
				trk *= 1024;
				trk /= anc->blksize;
				trk /= geo.sectors;
				break;
			case 'm':
			case 'M': 
				trk *= (1024*1024);
				trk /= anc->blksize;
				trk /= geo.sectors;
				break;
			case 0x0a:
				break;
			default: 
				printf("WARNING: '%c' is not a "
				       "valid appendix and probably "
				       "not what you want!\n", 
				       *line_ptr);
				break;
                        }
			
			trk += (low - 1);
			
		}
		else if (*line_ptr == '\0') {
			switch(base) {
			case lower: trk = low; break;
			case upper: trk = high; break;
			}
		}
		else {
                        if (*line_ptr == '+' || *line_ptr == '-') {
				printf("\nWARNING: '%c' is not valid in \n"
				       "this case and will be ignored!\n",
				       *line_ptr);
                                ++line_ptr;
			}

		        trk = atoi(line_ptr);
			while (isdigit(*line_ptr)) {
			        line_ptr++;
				use_default = 0;
			}

			if (*line_ptr != 0x0a)
				printf("\nWARNING: '%c' is not a valid "
				       "appendix and probably not what "
				       "you want!\n", *line_ptr);
		}
		if (use_default)
		        printf("Using default value %lld\n", trk = dflt);
		else
		        printf("You have selected track %lld\n", trk);

		if (trk >= low && trk <= high)
		        break;
                else
		        printf("Value out of range.\n");
	}
	return trk;
}


/*
 * returns unused partition info pointer if there
 * is a free partition, otherwise NULL
 */
static partition_info_t *
fdasd_get_empty_f1_label (fdasd_anchor_t * anc) 
{
	if (anc->used_partitions < USABLE_PARTITIONS)	  
	        return anc->last;	      
	else
	        return NULL;
}


/*
 * asks for and sets some important partition data
 */
static int 
fdasd_get_partition_data (fdasd_anchor_t *anc, extent_t *part_extent,
			  partition_info_t *part_info) 
{
	unsigned long start, stop, limit;
	u_int32_t cc, cyl;
	u_int16_t hh, head;
	cchh_t llimit,ulimit;
	partition_info_t *part_tmp;
        char mesg[48];
	u_int8_t b1, b2;

	start = FIRST_USABLE_TRK;

	cyl = get_usable_cylinders(anc);
	head = anc->f4->DS4DEVCT.DS4DSTRK;
	limit = (head * cyl - 1);

	sprintf(mesg, "First track (1 track = %d KByte)", 
		geo.sectors * anc->blksize / 1024);

	/* find default start value */
	for (part_tmp = anc->first; part_tmp->next != NULL;
	     part_tmp = part_tmp->next) {
		if ((start >= part_tmp->start_trk) && 
		    (start <= part_tmp->end_trk))
			start = part_tmp->end_trk + 1;
	}

	if (start > limit) {
	        printf("Not that easy, no free tracks available.\n");
		return -1;
	}

	/* read start value */
	start = fdasd_read_int(start, start, limit, lower, mesg, anc);

	/* check start value from user */
	for (part_tmp = anc->first; part_tmp->next != NULL;
	     part_tmp = part_tmp->next) {
		if (start >= part_tmp->start_trk &&
		    start <= part_tmp->end_trk) {
			/* start is within another partition */
			start = part_tmp->end_trk + 1;
			if (start > limit) {
				start = FIRST_USABLE_TRK;
				part_tmp = anc->first;
			}

			printf("value within another partition, " \
			       "using %ld instead\n", start);
		}

		if (start < part_tmp->start_trk) {
			limit = part_tmp->start_trk - 1;
			break;
		}

	}

	if (start == limit)
	        stop = start;
	else {
	        sprintf(mesg, "Last track or +size[c|k|M]");
		stop = fdasd_read_int(start, limit, limit, upper, mesg, anc);
	}

	/* update partition info */
	part_info->len_trk    = stop - start + 1;
	part_info->start_trk  = start;
	part_info->end_trk    = stop;

	cc = start / geo.heads;
	hh = start - (cc * geo.heads);
	vtoc_set_cchh(&llimit, cc, hh);

	/* check for cylinder boundary */
	if (hh == 0)  
		b1 = 0x81;
	else
		b1 = 0x01;

	cc = stop / geo.heads;
	hh = stop - cc * geo.heads;
	vtoc_set_cchh(&ulimit, cc, hh);

        /* it is always the 1st extent */
	b2 = 0x00;

	vtoc_set_extent(part_extent, b1, b2, &llimit, &ulimit);

	return 0;
}


/*
 *
 */
static void
fdasd_enqueue_new_partition (fdasd_anchor_t *anc) 
{
        partition_info_t *part_tmp = anc->first, *part_info = anc->last;
	int i, k = 0;

	for (i = 1; i < USABLE_PARTITIONS; i++) {
	        if ((part_tmp->end_trk == 0) || 
		    (part_info->start_trk < part_tmp->start_trk))
		        break;
		else { 
		        part_tmp = part_tmp->next;
			k++;
		}
	}

	if (anc->first == part_tmp) anc->first = part_info;
	
	if (part_info != part_tmp) {
	        anc->last->prev->next = NULL;
		anc->last = anc->last->prev;

	        part_info->next = part_tmp;
		part_info->prev = part_tmp->prev;
		part_tmp->prev = part_info;
		
		if (part_info->prev != NULL)
		        part_info->prev->next = part_info;
	}

	part_info->used       = 0x01;

	for (i=0; i<USABLE_PARTITIONS; i++) {
		int j = getpos(anc, i);
		if (j >= k) setpos(anc, i, j + 1);
	}

	/* update free-space counters */
	if (anc->first == part_info) {
	        /* partition is the first used partition */
	        if (part_info->start_trk == FIRST_USABLE_TRK) {
	               /* partition starts right behind VTOC */
	               part_info->fspace_trk = anc->fspace_trk -
			       part_info->len_trk;
		       anc->fspace_trk = 0;
		}
		else {
	               /* there is some space between VTOC and partition */

	               part_info->fspace_trk = anc->fspace_trk -
			       part_info->len_trk - part_info->start_trk +
			       FIRST_USABLE_TRK;
		       anc->fspace_trk = part_info->start_trk -
			       FIRST_USABLE_TRK;
		}
	}
	else {
	        /* there are partitons in front of the new one */
 	        if (part_info->start_trk == part_info->prev->end_trk + 1) {
		        /* new partition is right behind the previous one */
		        part_info->fspace_trk = part_info->prev->fspace_trk -
				part_info->len_trk;
			part_info->prev->fspace_trk = 0;
		}
		else {
		        /* there is some space between new and prev. part. */
		        part_info->fspace_trk = part_info->prev->fspace_trk - 
				part_info->len_trk - part_info->start_trk +
				part_info->prev->end_trk + 1;
			part_info->prev->fspace_trk = part_info->start_trk - 
				part_info->prev->end_trk - 1;
		}
	}
}


/*
 *
 */
static void
fdasd_dequeue_old_partition (fdasd_anchor_t *anc, partition_info_t *part_info,
			     int k) 
{
	int i;

	if (part_info != anc->first && part_info != anc->last) {
	        /* dequeue any non-special element */
	        part_info->prev->next = part_info->next;
	        part_info->next->prev = part_info->prev;
	}        

	if (part_info == anc->first) {
	        /* dequeue first element */
	        anc->first = part_info->next;
		part_info->next->prev = NULL;
	        anc->fspace_trk += (part_info->len_trk +
				    part_info->fspace_trk);
	} else
		part_info->prev->fspace_trk += (part_info->len_trk +
						part_info->fspace_trk);

	if (part_info != anc->last) {
	        part_info->prev = anc->last;
	        part_info->next = NULL;
		anc->last->next = part_info;
		anc->last       = part_info;
	}

	for (i=0; i<USABLE_PARTITIONS; i++) {
		int j = getpos(anc, i);
		if (j >= k) setpos(anc, i, j - 1);
	}

	part_info->used       = 0x00;
	part_info->len_trk    = 0x0;
	part_info->start_trk  = 0x0;
	part_info->end_trk    = 0x0;
	part_info->fspace_trk = 0x0;
	bzero(part_info->f1, sizeof(format1_label_t));
}


/*
 * adds a new partition to the 'partition table'
 */
static void
fdasd_add_partition (fdasd_anchor_t *anc) 
{
	cchhb_t hf1;
	partition_info_t *part_info;
	extent_t ext;
	unsigned long start, stop;

	if ((part_info = fdasd_get_empty_f1_label(anc)) == NULL) {
	        printf("No more free partitions left,\n"
		       "you have to delete one first!");
		return;
	}

	if (fdasd_get_partition_data(anc, &ext, part_info) != 0)
	        return;

	if (anc->formatted_cylinders > LV_COMPAT_CYL) {
		vtoc_init_format8_label(anc->vlabel->volid, anc->blksize, &ext,
					part_info->f1);
	} else
		vtoc_init_format1_label(anc->vlabel->volid, anc->blksize, &ext,
					 part_info->f1);

	fdasd_enqueue_new_partition(anc);
	anc->used_partitions += 1;

	get_addr_of_highest_f1_f8_label(anc, &hf1);
	vtoc_update_format4_label(anc->f4, &hf1, anc->f4->DS4DSREC - 1);

	start = cchh2trk(&ext.llimit, &geo);
	stop = cchh2trk(&ext.ulimit, &geo);

	vtoc_set_freespace(anc->f4, anc->f5, anc->f7, '-', anc->verbose,
			   start, stop, anc->formatted_cylinders, geo.heads);

	anc->vtoc_changed++;
}


/*
 * removes a partition from the 'partition table'
 */
static void
fdasd_remove_partition (fdasd_anchor_t *anc) 
{
	cchhb_t hf1;
        unsigned int part_id, i;
	unsigned long start, stop;
	partition_info_t *part_info = anc->first;

	fdasd_list_partition_table(anc);

	while (!isdigit(part_id = read_char("\ndelete partition with id "
					    "(use 0 to exit): ")))
		printf("Invalid partition id '%c' detected.\n", part_id);

	printf("\n");
	part_id -= 48;
	if (part_id == 0) return;
        if (part_id > anc->used_partitions) {
                printf("'%d' is not a valid partition id!\n", part_id);
                return;
        }

	printf("deleting partition number '%d'...\n", part_id);	

	setpos(anc, part_id-1, -1);
	for (i=1; i<part_id; i++) part_info=part_info->next;

	start = cchh2trk(&part_info->f1->DS1EXT1.llimit, &geo);
	stop  = cchh2trk(&part_info->f1->DS1EXT1.ulimit, &geo);

	fdasd_dequeue_old_partition (anc, part_info, part_id-1);
	anc->used_partitions -= 1;

	if (anc->used_partitions != 0)
		get_addr_of_highest_f1_f8_label(anc, &hf1);
	else
		bzero(&hf1, sizeof(struct cchhb));

	vtoc_update_format4_label(anc->f4, &hf1, anc->f4->DS4DSREC + 1);
	vtoc_set_freespace(anc->f4, anc->f5, anc->f7, '+', anc->verbose,
			   start, stop, anc->formatted_cylinders, geo.heads);

	anc->vtoc_changed++;
}


/*
 * writes a standard volume label and a standard VTOC with
 * only one partition to disc. With this function is it 
 * possible to create one partiton in non-interactive mode,
 * which can be used within shell scripts
 */
static void
fdasd_auto_partition(fdasd_anchor_t *anc)
{
	partition_info_t *part_info = anc->first;
	cchh_t llimit,ulimit;
	cchhb_t hf1;
	extent_t ext;
	u_int32_t cyl;
	u_int16_t head;

	if (!anc->silent)
		printf("auto-creating one partition for the whole disk...\n");

	fdasd_init_volume_label(anc);

	if (anc->verbose) printf("initializing labels...\n");
	vtoc_init_format4_label(anc->f4, USABLE_PARTITIONS,
				geo.cylinders, anc->formatted_cylinders,
				geo.heads, geo.sectors,
				anc->blksize, anc->dev_type);

	vtoc_init_format5_label(anc->f5);
	vtoc_init_format7_label(anc->f7);

	cyl = get_usable_cylinders(anc);
	head = anc->f4->DS4DEVCT.DS4DSTRK;

	part_info->used       = 0x01;
        part_info->fspace_trk = 0;
	part_info->len_trk    = head * cyl - FIRST_USABLE_TRK;
	part_info->start_trk  = FIRST_USABLE_TRK;
	part_info->end_trk    = head * cyl - 1;

	vtoc_set_cchh(&llimit, 0, FIRST_USABLE_TRK);
	vtoc_set_cchh(&ulimit, cyl - 1, head - 1);

	vtoc_set_extent(&ext, 0x01, 0x00, &llimit, &ulimit);

	if (anc->formatted_cylinders > LV_COMPAT_CYL) {
		vtoc_init_format8_label(anc->vlabel->volid, anc->blksize, &ext,
					part_info->f1);
	} else
		vtoc_init_format1_label(anc->vlabel->volid, anc->blksize, &ext,
					part_info->f1);
        anc->fspace_trk      = 0;
	anc->used_partitions = 1;

	get_addr_of_highest_f1_f8_label(anc, &hf1);
	vtoc_update_format4_label(anc->f4, &hf1, anc->f4->DS4DSREC - 1);

	anc->vtoc_changed++;

	fdasd_write_labels(anc);
	fdasd_exit(anc, 0);
}


/*
 * does the partitioning regarding to the config file
 */
static void
fdasd_auto_partition_conffile(fdasd_anchor_t *anc)
{
	volume_label_t *vlabel = anc->vlabel;
	partition_info_t *part_info = anc->first;
	cchh_t llimit,ulimit;
	unsigned long start, stop;
	extent_t ext;
	cchhb_t hf1;
	char *type;

	fdasd_init_volume_label(anc);

	if (anc->verbose) printf("initializing labels...\n");
	vtoc_init_format4_label(anc->f4, USABLE_PARTITIONS,
				geo.cylinders, anc->formatted_cylinders,
				geo.heads, geo.sectors,
				anc->blksize, anc->dev_type);

	vtoc_init_format5_label(anc->f5);
	vtoc_init_format7_label(anc->f7);

	if (anc->fspace_trk != 0) {
		start = FIRST_USABLE_TRK;
		stop  = start + anc->fspace_trk - 1;

		vtoc_set_freespace(anc->f4, anc->f5, anc->f7, '+',
				   anc->verbose, start, stop,
				   anc->formatted_cylinders, geo.heads);
	}

	do {
		if (part_info->used != 0x01)
			continue;

		vtoc_set_cchh(&llimit,
			      part_info->start_trk / geo.heads,
			      part_info->start_trk % geo.heads);
		vtoc_set_cchh(&ulimit,
			      part_info->end_trk / geo.heads,
			      part_info->end_trk % geo.heads);

		vtoc_set_extent(&ext, (vtoc_get_head_from_cchh(&llimit) == 0
				       ? 0x81 : 0x01),
				0x00, &llimit, &ulimit);

		if (anc->formatted_cylinders > LV_COMPAT_CYL) {
			vtoc_init_format8_label(vlabel->volid, anc->blksize,
						&ext, part_info->f1);
		} else
			vtoc_init_format1_label(vlabel->volid, anc->blksize,
						&ext, part_info->f1);
		anc->used_partitions += 1;

		get_addr_of_highest_f1_f8_label(anc, &hf1);
		vtoc_update_format4_label(anc->f4, &hf1,anc->f4->DS4DSREC - 1);

		/* update free space labels */
		if (part_info->fspace_trk != 0) {
			start = part_info->end_trk + 1;
			stop  = start + part_info->fspace_trk -1;

			vtoc_set_freespace(anc->f4, anc->f5, anc->f7, '+', 
					   anc->verbose, start, stop,
					   anc->formatted_cylinders, geo.heads);
		}

		/* write correct partition type */
		vtoc_ebcdic_dec(part_info->f1->DS1DSNAM,
				part_info->f1->DS1DSNAM, 44);
		type = strstr(part_info->f1->DS1DSNAM, ".NEW");
		if (part_info->type == PARTITION_SWAP)
			strncpy(type, ".SWAP", 5);
		else if (part_info->type == PARTITION_RAID)
			strncpy(type, ".RAID", 5);
		else if (part_info->type == PARTITION_LVM)
			strncpy(type, ".LVM", 4);
		else
			strncpy(type, ".NATIVE", 7);
		vtoc_ebcdic_enc(part_info->f1->DS1DSNAM,
				part_info->f1->DS1DSNAM, 44);
	} while ((part_info = part_info->next) != NULL);

	anc->vtoc_changed++;

	fdasd_write_labels(anc);
	fdasd_exit(anc, 0);
}

/*
 * quits fdasd without saving
 */
static void
fdasd_quit(fdasd_anchor_t *anc)
{
	char str[INPUT_BUF_SIZE];

	if ((anc->vtoc_changed)||(anc->vlabel_changed)) {
		snprintf(str, INPUT_BUF_SIZE,
			"All changes will be lost! "
			"Do you really want to quit?");

                if (yes_no(str) == 1)
			return;

		printf("exiting without saving...\n");
	}
	else
		if (!anc->silent) printf("exiting...\n");

	fdasd_exit(anc, 0);
}

/*
 *
 */
int
main(int argc, char *argv[]) 
{
        fdasd_anchor_t anchor;
	int rc=0;

        fdasd_initialize_anchor(&anchor);

        fdasd_parse_options (&anchor, &options, argc, argv);
	fdasd_verify_device (&anchor, options.device);
	fdasd_verify_options (&anchor);
	fdasd_get_geometry(&anchor);
	fdasd_check_disk_access(&anchor);

	/* check dasd for labels and vtoc */
	rc = fdasd_check_volume(&anchor);

	if ((anchor.formatted_cylinders * geo.heads) > BIG_DISK_SIZE)
		anchor.big_disk++;

	if (anchor.auto_partition) {
		fdasd_recreate_vtoc_unconditional(&anchor);
		fdasd_auto_partition(&anchor);
	}

	if (options.conffile) {
		fdasd_recreate_vtoc_unconditional(&anchor);
		fdasd_parse_conffile(&anchor, &options);
		fdasd_check_conffile_input(&anchor, &options);
		fdasd_auto_partition_conffile(&anchor);
	}

	if (anchor.print_volser) {
		fdasd_print_volser(&anchor);
		fdasd_quit(&anchor);
	}

	if (anchor.print_table) {
		if (rc == 0)
			fdasd_list_partition_table(&anchor);
		fdasd_quit(&anchor);
	}

	fdasd_menu();

	while (1) {
	        putchar('\n');
		switch (tolower(read_char("Command (m for help): "))) {
		case 'd':
		        fdasd_remove_partition(&anchor);
			break;
		case 'n':
		        fdasd_add_partition(&anchor);
			break;
                case 'v':
                        fdasd_change_volser(&anchor);
                        break;
                case 't':
                        fdasd_change_part_type(&anchor);
                        break;
		case 'p':
		        fdasd_list_partition_table(&anchor);
			break;
		case 's':
			fdasd_show_mapping(&anchor);
			break;
		case 'u':
			anchor.option_reuse++;
			break;
		case 'r':
			anchor.option_recreate++;
			break;
		case 'm':
		        fdasd_menu();		  
			break;
		case 'q':
			fdasd_quit(&anchor);
			break;
		case 'w':
		        fdasd_write_labels(&anchor);
			fdasd_exit(&anchor, 0);		    
		default:
		        printf("please use one of the following commands:\n");
			fdasd_menu();
		}

		if (anchor.option_reuse) {
			fdasd_reuse_vtoc(&anchor);
			anchor.option_reuse = 0;
		}

		if (anchor.option_recreate) {
			fdasd_recreate_vtoc(&anchor);
			anchor.option_recreate = 0;
		}

	}		

	return -1;
}










