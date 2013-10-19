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
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

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

static void vmod_perror( struct sess *sp, int err ) {
	char buf[256];
	VSL(SLT_VCL_error, sp == NULL ? 0 : sp->id, "%s", strerror_r(err, buf, 256));
}

static void pthread_error_check( struct sess *sp, int err ) {
	if( err != 0 )
		vmod_perror(sp, err);
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
	dbgprintf(sp, "fopen(%s, %s)", file->name, mode);
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
