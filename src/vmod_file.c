#include <config.h>

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>

#include "vrt.h"
#include "bin/varnishd/cache.h"

#include "vcc_if.h"

#ifndef NDEBUG
#define dbgprintf(sp, ...) VSL(SLT_VCL_trace, ((sp) == NULL ? 0 : ((struct sess *) (sp))->id), __VA_ARGS__)
#else
#define dbgprintf(sp, ...) ((void) sizeof(sp))
#endif

typedef struct {
	int fd;
	char *name;
	size_t name_len;
} VModFile;

typedef struct {
	VModFile *files;
	size_t nfiles;
	pthread_mutex_t lock;
} VModFileTable;

typedef struct VModFileTableList {
	struct VModFileTableList *next;
	VModFileTable *table;
} VModFileTableList;

static void vmod_perror( struct sess *sp, int err ) {
	char buf[256];
	VSL(SLT_VCL_error, sp == NULL ? 0 : sp->id, "%s", strerror_r(err, buf, 256));
}

static void pthread_error_check( struct sess *sp, int err ) {
	if( err != 0 )
		vmod_perror(sp, err);
}

static VModFileTableList *tables_begin = NULL, *tables_end = NULL;
static pthread_mutex_t tables_lock = PTHREAD_MUTEX_INITIALIZER;

static bool *reopen_flag( struct sess *sp ) {
	static bool *static_shm = NULL;

	bool *shm = __sync_fetch_and_add(&static_shm, 0);
	if( shm != NULL ) return shm;

	static pthread_mutex_t shm_lock = PTHREAD_MUTEX_INITIALIZER;
	pthread_error_check(NULL, pthread_mutex_lock(&shm_lock));

	shm = __sync_fetch_and_add(&static_shm, 0);
	if( shm != NULL ) goto unlock_and_return;

	dbgprintf(sp, "Initializing reopen shm");

	int fd = shm_open("/libvmod-file-reopen-files", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
	if( fd == -1 ) goto error_shm_open;

	if( ftruncate(fd, sizeof(bool)) == -1 ) goto error_ftruncate;

	shm = mmap(NULL, sizeof(bool), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if( shm == MAP_FAILED ) goto error_mmap;

	*shm = false;

	__sync_bool_compare_and_swap(&static_shm, NULL, shm);

	goto unlock_and_return;
error_mmap:
error_ftruncate:
	close(fd);
error_shm_open:
	vmod_perror(NULL, errno);
unlock_and_return:
	pthread_error_check(NULL, pthread_mutex_unlock(&shm_lock));

	return shm;
}

static void tables_insert( VModFileTable *table ) {
	pthread_error_check(NULL, pthread_mutex_lock(&tables_lock));

	VModFileTableList *node = malloc(sizeof(VModFileTableList));
	if( node == NULL ) goto error_malloc;
	node->table = table;
	node->next = NULL;

	if( tables_begin == NULL ) {
		tables_begin = node;
	} else {
		tables_end->next = node;
	}
	tables_end = node;

	goto unlock_and_return;

error_malloc:
	vmod_perror(NULL, errno);
unlock_and_return:
	pthread_error_check(NULL, pthread_mutex_unlock(&tables_lock));
}

static void tables_remove( VModFileTable *table ) {
	pthread_error_check(NULL, pthread_mutex_lock(&tables_lock));

	VModFileTableList *prev = NULL;
	for( VModFileTableList *node = tables_begin; node != NULL; node = node->next ) {
		if( node->table == table ) {
			if( prev == NULL ) {
				tables_begin = node->next;
			} else {
				prev->next = node->next;
			}
			if( node->next == NULL ) tables_end = NULL;
			free(node);
			break;
		}
		prev = node;
	}

	pthread_error_check(NULL, pthread_mutex_unlock(&tables_lock));
}

static void reopen_if_needed( struct sess *sp ) {
	bool *reopen = reopen_flag(sp);

	// This is GCC specific. Sorry.
	if( reopen == NULL || !__sync_fetch_and_add(reopen, 0) )
		return;

	pthread_error_check(sp, pthread_mutex_lock(&tables_lock));

	if( !__sync_bool_compare_and_swap(reopen, true, false) )
		goto unlock_and_return;

	dbgprintf(sp, "Reopening log files");

	for( VModFileTableList *node = tables_begin; node != NULL; node = node->next ) {
		VModFileTable *table = node->table;
		pthread_error_check(sp, pthread_mutex_lock(&table->lock));
		for( size_t i = 0; i < table->nfiles; i++ ) {
			VModFile *file = &table->files[i];

			int flags = fcntl(file->fd, F_GETFL);
			if( flags == -1 ) goto error_fcntl;

			int newfd = open(file->name, flags | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
			if( newfd == -1 ) goto error_open;

			do {
				errno = 0;
				close(file->fd);
			} while( errno == EINTR );
			if( errno != 0 ) goto error_close;

			file->fd = newfd;

			continue;
error_close:
			close(newfd);
error_open:
error_fcntl:
			vmod_perror(sp, errno);
		}
		pthread_error_check(sp, pthread_mutex_unlock(&table->lock));
	}

unlock_and_return:
	pthread_error_check(sp, pthread_mutex_unlock(&tables_lock));
}

static VModFile *find_file_holding_lock( VModFileTable *table, const char *name ) {
	for( size_t i = 0; i < table->nfiles; i++ ) {
		VModFile *file = &table->files[i];
		if( file->name != NULL && strncmp(file->name, name, file->name_len + 1) == 0 ) {
			return file;
		}
	}
	return NULL;
}

static VModFile *file_open_holding_lock( struct sess *sp, VModFileTable *table, const char *name, const char *mode ) {
	// Check if the file is open
	VModFile *file = find_file_holding_lock(table, name);
	if( file != NULL ) return file;

	// Find a free file
	for( size_t i = 0; i < table->nfiles; i++ ) {
		if( table->files[i].fd == -1 ) {
			file = &table->files[i];
			break;
		}
	}
	
	if( file == NULL ) {
		// No free files. Resize the files array
		table->nfiles += 1;
		VModFile *_files = realloc(table->files, table->nfiles * sizeof(table->files[0]));
		if( _files == NULL ) goto error_files_realloc;
		table->files = _files;
		file = &table->files[table->nfiles - 1];
	}

	// Save the file name
	file->name_len = strlen(name);
	file->name = strndup(name, file->name_len);
	if( file->name == NULL ) goto error_strdup_name;

	// Open the file
	dbgprintf(sp, "fopen('%s', '%s')", file->name, mode);
	FILE *f = fopen(file->name, mode);
	if( f == NULL ) goto error_fopen;

	int fd = fileno(f);
	if( fd == -1 ) goto error_fileno;

	file->fd = dup(fd);
	if( file->fd == -1 ) goto error_dup;

	if( fclose(f) == EOF ) goto error_fclose;

	return file;

error_dup:
error_fileno:
	fclose(f);
error_fclose:
error_fopen:
	free(file->name);
	file->name = NULL;
	file->name_len = 0;
error_strdup_name:
error_files_realloc:
	vmod_perror(sp, errno);

	return NULL;
}

static size_t vmod_file_write( struct sess *sp, int fd, const void *buf, size_t bufsiz ) {
	ssize_t count;
begin_write:
	dbgprintf(sp, "write(%d, buf, %zd)", fd, bufsiz);
	count = write(fd, buf, bufsiz);
	if( count < 0 ) {
		if( errno == EINTR ) goto begin_write;
		vmod_perror(sp, errno);
		return 0;
	}
	return (size_t) count;
}

void vmod_open( struct sess *sp, struct vmod_priv *global, const char *name, const char *mode ) {
	dbgprintf(sp, "vmod_open(sp, global, name = '%s', mode = '%s')", name, mode);
	VModFileTable *table = (VModFileTable *) global->priv;

	pthread_error_check(sp, pthread_mutex_lock(&table->lock));
	file_open_holding_lock(sp, table, name, mode);
	pthread_error_check(sp, pthread_mutex_unlock(&table->lock));
}

void vmod_close( struct sess *sp, struct vmod_priv *global, const char *name ) {
	VModFileTable *table = (VModFileTable *) global->priv;

	pthread_error_check(sp, pthread_mutex_lock(&table->lock));

	VModFile *file = find_file_holding_lock(table, name);
	if( file != NULL ) {
		close(file->fd);
		free(file->name);
		file->fd = -1;
		file->name = NULL;
		file->name_len = 0;
	}

	pthread_error_check(sp, pthread_mutex_unlock(&table->lock));
}

void vmod_write( struct sess *sp, struct vmod_priv *global, const char *name, const char *buf ) {
	dbgprintf(sp, "vmod_write(sp, global, name = '%s', buf = '%s')", name, buf);
	if( buf == NULL ) return;

	reopen_if_needed(sp);

	VModFileTable *table = (VModFileTable *) global->priv;

	pthread_error_check(sp, pthread_mutex_lock(&table->lock));

	VModFile *file = find_file_holding_lock(table, name);
	if( file == NULL )
		file = file_open_holding_lock(sp, table, name, "a+");

	if( file == NULL ) {
		VSL(SLT_VCL_error, sp->id, "Tried to write to '%s' file which wasn't open", name);
	} else {
		vmod_file_write(sp, file->fd, buf, strlen(buf));
	}

	pthread_error_check(sp, pthread_mutex_unlock(&table->lock));
}

void vmod_printf( struct sess *sp, struct vmod_priv *global, const char *name, const char *fmt, ... ) {
	dbgprintf(sp, "vmod_printf(sp, global, name = '%s', fmt = '%s', ...)", name, fmt);
	if( fmt == NULL ) return;

	reopen_if_needed(sp);

	va_list ap;
	va_start(ap, fmt);

	char *msg = NULL;
	int msglen = vasprintf(&msg, fmt, ap);

	va_end(ap);

	if( msglen == -1 ) {
		vmod_perror(sp, errno);
		return;
	}

	vmod_write(sp, global, name, msg);

	free(msg);
}

void vmod_file_free( void *priv ) {
	dbgprintf(0, "vmod_file_free");
	VModFileTable *table = (VModFileTable *) priv;

	tables_remove(table);

	pthread_error_check(NULL, pthread_mutex_destroy(&table->lock));

	for( size_t i = 0; i < table->nfiles; i++ ) {
		VModFile *file = &table->files[i];
		close(file->fd);
		free(file->name);
	}

	free(table->files);
	free(table);
}

int vmod_file_init( struct vmod_priv *global, const struct VCL_conf *conf ) {
	(void) conf;
	dbgprintf(0, "vmod_file_init");

	// Initialize the reopen flag's shm.
	reopen_flag(NULL);

	VModFileTable *table = malloc(sizeof(VModFileTable));
	if( table == NULL ) goto error_table;
	table->files = NULL;
	table->nfiles = 0;

	pthread_mutexattr_t attrs;

	errno = pthread_mutexattr_init(&attrs);
	if( errno != 0 ) goto error_mutexattr_init;

	errno = pthread_mutexattr_settype(&attrs, PTHREAD_MUTEX_RECURSIVE);
	if( errno != 0 ) goto error_mutexattr_settype;

	errno = pthread_mutex_init(&table->lock, &attrs);
	if( errno != 0 ) goto error_mutex_init;

	errno = pthread_mutexattr_destroy(&attrs);
	if( errno != 0 ) goto error_mutexattr_destroy;

	tables_insert(table);

	global->priv = table;
	global->free = vmod_file_free;

	return 0;

error_mutexattr_destroy:
	pthread_mutex_destroy(&table->lock);
error_mutex_init:
error_mutexattr_settype:
	pthread_mutexattr_destroy(&attrs);
error_mutexattr_init:
	free(table);
error_table:
	vmod_perror(NULL, errno);

	return -1;
}
