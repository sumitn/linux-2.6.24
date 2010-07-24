/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2006  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.
*/

#include "fuse_i.h"

#include <linux/pagemap.h>
#include <linux/file.h>
#include <linux/gfp.h>
#include <linux/sched.h>
#include <linux/namei.h>

#include "fist.h"
#include "sfuse.h"

static void fuse_lk_fill(struct fuse_req *req, struct file *file,
			 const struct file_lock *fl, int opcode, pid_t pid,
			 int flock)
{
   struct inode *inode = file->f_path.dentry->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_file *ff = file->private_data;
   struct fuse_lk_in *arg = &req->misc.lk_in;

   arg->fh = ff->fh;
   arg->owner = fuse_lock_owner_id(fc, fl->fl_owner);
   arg->lk.start = fl->fl_start;
   arg->lk.end = fl->fl_end;
   arg->lk.type = fl->fl_type;
   arg->lk.pid = pid;
   if (flock)
      arg->lk_flags |= FUSE_LK_FLOCK;
   req->in.h.opcode = opcode;
   req->in.h.nodeid = get_node_id(inode);
   req->in.numargs = 1;
   req->in.args[0].size = sizeof(*arg);
   req->in.args[0].value = arg;
}

static int convert_fuse_file_lock(const struct fuse_file_lock *ffl,
				  struct file_lock *fl)
{
   switch (ffl->type) {
      case F_UNLCK:
	 break;

      case F_RDLCK:
      case F_WRLCK:
	 if (ffl->start > OFFSET_MAX || ffl->end > OFFSET_MAX ||
	     ffl->end < ffl->start)
	    return -EIO;

	 fl->fl_start = ffl->start;
	 fl->fl_end = ffl->end;
	 fl->fl_pid = ffl->pid;
	 break;

      default:
	 return -EIO;
   }
   fl->fl_type = ffl->type;
   return 0;
}

static int fuse_getlk(struct file *file, struct file_lock *fl)
{
   struct inode *inode = file->f_path.dentry->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_req *req;
   struct fuse_lk_out outarg;
   int err;

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return PTR_ERR(req);

   fuse_lk_fill(req, file, fl, FUSE_GETLK, 0, 0);
   req->out.numargs = 1;
   req->out.args[0].size = sizeof(outarg);
   req->out.args[0].value = &outarg;
   request_send(fc, req);
   err = req->out.h.error;
   fuse_put_request(fc, req);
   if (!err)
      err = convert_fuse_file_lock(&outarg.lk, fl);

   return err;
}

static int fuse_setlk(struct file *file, struct file_lock *fl, int flock)
{
   struct inode *inode = file->f_path.dentry->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_req *req;
   int opcode = (fl->fl_flags & FL_SLEEP) ? FUSE_SETLKW : FUSE_SETLK;
   pid_t pid = fl->fl_type != F_UNLCK ? current->tgid : 0;
   int err;

   /* Unlock on close is handled by the flush method */
   if (fl->fl_flags & FL_CLOSE)
      return 0;

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return PTR_ERR(req);

   fuse_lk_fill(req, file, fl, opcode, pid, flock);
   request_send(fc, req);
   err = req->out.h.error;
   /* locking is restartable */
   if (err == -EINTR)
      err = -ERESTARTSYS;
   fuse_put_request(fc, req);
   return err;
}

ssize_t fuse_file_aio_read(struct kiocb *iocb, const struct iovec *iov,
				  unsigned long nr_segs, loff_t pos)
{
   struct inode *inode = iocb->ki_filp->f_mapping->host;
   struct fuse_file *ff;

   fuse_init_file_inode(inode);

   ff = fuse_file_alloc();
   if(!ff) return -ENOMEM;

   if (pos + iov_length(iov, nr_segs) > i_size_read(inode)) {
      int err;
      /*
       * If trying to read past EOF, make sure the i_size
       * attribute is up-to-date.
       */
      err = fuse_update_attributes(inode, NULL, iocb->ki_filp, NULL);
      if (err)
	 return err;
   }

   return generic_file_aio_read(iocb, iov, nr_segs, pos);
}

static int fuse_file_mmap(struct file *file, struct vm_area_struct *vma)
{
   if ((vma->vm_flags & VM_SHARED)) {
      if ((vma->vm_flags & VM_WRITE))
	 return -ENODEV;
      else
	 vma->vm_flags &= ~VM_MAYWRITE;
   }
   return generic_file_mmap(file, vma);
}

static int fuse_send_open(struct inode *inode, struct file *file, int isdir,
			  struct fuse_open_out *outargp)
{
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_open_in inarg;
   struct fuse_req *req;
   int err;

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return PTR_ERR(req);

   memset(&inarg, 0, sizeof(inarg));
   inarg.flags = file->f_flags & ~(O_CREAT | O_EXCL | O_NOCTTY);
   if (!fc->atomic_o_trunc)
      inarg.flags &= ~O_TRUNC;
   req->in.h.opcode = isdir ? FUSE_OPENDIR : FUSE_OPEN;
   req->in.h.nodeid = get_node_id(inode);
   req->in.numargs = 1;
   req->in.args[0].size = sizeof(inarg);
   req->in.args[0].value = &inarg;
   req->out.numargs = 1;
   req->out.args[0].size = sizeof(*outargp);
   req->out.args[0].value = outargp;
   request_send(fc, req);
   err = req->out.h.error;
   fuse_put_request(fc, req);

   return err;
}

int fuse_open_common(struct inode *inode, struct file *file, int isdir)
{
   struct fuse_open_out outarg;
   struct fuse_file *ff;

#ifdef STACKABLE_FUSE
   struct dentry *lower_dentry = NULL;
   file_t *lower_file = NULL;
#endif /* STACKABLE_FUSE */

   int err;

   /* VFS checks this, but only _after_ ->open() */
   if (file->f_flags & O_DIRECT)
      return -EINVAL;

   err = generic_file_open(inode, file);
   if (err)
      return err;

   ff = fuse_file_alloc();
   if (!ff)
      return -ENOMEM;

   err = fuse_send_open(inode, file, isdir, &outarg);
   if (err)
      fuse_file_free(ff);
   else {
      if (isdir)
	 outarg.open_flags &= ~FOPEN_DIRECT_IO;
      fuse_finish_open(inode, file, ff, &outarg);
   }

   return err;
}

static int fuse_open(struct inode *inode, struct file *file)
{
   return fuse_open_common(inode, file, 0);
}

static int fuse_release(struct inode *inode, struct file *file)
{
   return fuse_release_common(inode, file, 0);
}

static int fuse_flush(struct file *file, fl_owner_t id)
{
   struct inode *inode = file->f_path.dentry->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_file *ff = file->private_data;
   struct fuse_req *req;
   struct fuse_flush_in inarg;
   int err;

   if (is_bad_inode(inode))
      return -EIO;

   if (fc->no_flush)
      return 0;

   req = fuse_get_req_nofail(fc, file);
   memset(&inarg, 0, sizeof(inarg));
   inarg.fh = ff->fh;
   inarg.lock_owner = fuse_lock_owner_id(fc, id);
   req->in.h.opcode = FUSE_FLUSH;
   req->in.h.nodeid = get_node_id(inode);
   req->in.numargs = 1;
   req->in.args[0].size = sizeof(inarg);
   req->in.args[0].value = &inarg;
   req->force = 1;
   request_send(fc, req);
   err = req->out.h.error;
   fuse_put_request(fc, req);
   if (err == -ENOSYS) {
      fc->no_flush = 1;
      err = 0;
   }
   return err;
}

static int fuse_fsync(struct file *file, struct dentry *de, int datasync)
{
   return fuse_fsync_common(file, de, datasync, 0);
}

static int fuse_file_lock(struct file *file, int cmd, struct file_lock *fl)
{
   struct inode *inode = file->f_path.dentry->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   int err;

   if (cmd == F_GETLK) {
      if (fc->no_lock) {
	 posix_test_lock(file, fl);
	 err = 0;
      } else
	 err = fuse_getlk(file, fl);
   } else {
      if (fc->no_lock)
	 err = posix_lock_file_wait(file, fl);
      else
	 err = fuse_setlk(file, fl, 0);
   }
   return err;
}

static int fuse_file_flock(struct file *file, int cmd, struct file_lock *fl)
{
   struct inode *inode = file->f_path.dentry->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   int err;

   if (fc->no_lock) {
      err = flock_lock_file_wait(file, fl);
   } else {
      /* emulate flock with POSIX locks */
      fl->fl_owner = (fl_owner_t) file;
      err = fuse_setlk(file, fl, 1);
   }

   return err;
}

static const struct file_operations fuse_file_operations = {
   .llseek		= generic_file_llseek,
   .read		= do_sync_read,
   .aio_read	        = fuse_file_aio_read,
   .write		= do_sync_write,
   .aio_write	        = generic_file_aio_write,
   .mmap		= fuse_file_mmap,
   .open		= fuse_open,
   .flush		= fuse_flush,
   .release	        = fuse_release,
   .fsync		= fuse_fsync,
   .lock		= fuse_file_lock,
   .flock		= fuse_file_flock,
   .splice_read	        = generic_file_splice_read,
};

#if BITS_PER_LONG >= 64
static inline void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_time = time;
}

static inline u64 fuse_dentry_time(struct dentry *entry)
{
	return entry->d_time;
}
#else
/*
 * On 32 bit archs store the high 32 bits of time in d_fsdata
 */
static void fuse_dentry_settime(struct dentry *entry, u64 time)
{
	entry->d_time = time;
	entry->d_fsdata = (void *) (unsigned long) (time >> 32);
}

static u64 fuse_dentry_time(struct dentry *entry)
{
	return (u64) entry->d_time +
		((u64) (unsigned long) entry->d_fsdata << 32);
}
#endif

/*
 * FUSE caches dentries and attributes with separate timeout.  The
 * time in jiffies until the dentry/attributes are valid is stored in
 * dentry->d_time and fuse_inode->i_time respectively.
 */

/*
 * Calculate the time in jiffies until a dentry/attributes are valid
 */
static u64 time_to_jiffies(unsigned long sec, unsigned long nsec)
{
	if (sec || nsec) {
		struct timespec ts = {sec, nsec};
		return get_jiffies_64() + timespec_to_jiffies(&ts);
	} else
		return 0;
}

/*
 * Set dentry and possibly attribute timeouts from the lookup/mk*
 * replies
 */
static void fuse_change_entry_timeout(struct dentry *entry,
				      struct fuse_entry_out *o)
{
	fuse_dentry_settime(entry,
		time_to_jiffies(o->entry_valid, o->entry_valid_nsec));
}

static u64 attr_timeout(struct fuse_attr_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

static u64 entry_attr_timeout(struct fuse_entry_out *o)
{
	return time_to_jiffies(o->attr_valid, o->attr_valid_nsec);
}

/*
 * Mark the attributes as stale, so that at the next call to
 * ->getattr() they will be fetched from userspace
 */
void fuse_invalidate_attr(struct inode *inode)
{
	get_fuse_inode(inode)->i_time = 0;
}

/*
 * Just mark the entry as stale, so that a next attempt to look it up
 * will result in a new lookup call to userspace
 *
 * This is called when a dentry is about to become negative and the
 * timeout is unknown (unlink, rmdir, rename and in some cases
 * lookup)
 */
static void fuse_invalidate_entry_cache(struct dentry *entry)
{
	fuse_dentry_settime(entry, 0);
}

/*
 * Same as fuse_invalidate_entry_cache(), but also try to remove the
 * dentry from the hash
 */
static void fuse_invalidate_entry(struct dentry *entry)
{
	d_invalidate(entry);
	fuse_invalidate_entry_cache(entry);
}

static void fuse_lookup_init(struct fuse_req *req, struct inode *dir,
			     struct dentry *entry,
			     struct fuse_entry_out *outarg)
{
	struct fuse_conn *fc = get_fuse_conn(dir);

	memset(outarg, 0, sizeof(struct fuse_entry_out));
	req->in.h.opcode = FUSE_LOOKUP;
	req->in.h.nodeid = get_node_id(dir);
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(struct fuse_entry_out);
	req->out.args[0].value = outarg;
}

static u64 fuse_get_attr_version(struct fuse_conn *fc)
{
	u64 curr_version;

	/*
	 * The spin lock isn't actually needed on 64bit archs, but we
	 * don't yet care too much about such optimizations.
	 */
	spin_lock(&fc->lock);
	curr_version = fc->attr_version;
	spin_unlock(&fc->lock);

	return curr_version;
}

/*
 * Check whether the dentry is still valid
 *
 * If the entry validity timeout has expired and the dentry is
 * positive, try to redo the lookup.  If the lookup results in a
 * different inode, then let the VFS invalidate the dentry and redo
 * the lookup once more.  If the lookup results in the same inode,
 * then refresh the attributes, timeouts and mark the dentry valid.
 */
static int fuse_dentry_revalidate(struct dentry *entry, struct nameidata *nd)
{
	struct inode *inode = entry->d_inode;

	if (inode && is_bad_inode(inode))
		return 0;
	else if (fuse_dentry_time(entry) < get_jiffies_64()) {
		int err;
		struct fuse_entry_out outarg;
		struct fuse_conn *fc;
		struct fuse_req *req;
		struct fuse_req *forget_req;
		struct dentry *parent;
		u64 attr_version;

		/* For negative dentries, always do a fresh lookup */
		if (!inode)
			return 0;

		fc = get_fuse_conn(inode);
		req = fuse_get_req(fc);
		if (IS_ERR(req))
			return 0;

		forget_req = fuse_get_req(fc);
		if (IS_ERR(forget_req)) {
			fuse_put_request(fc, req);
			return 0;
		}

		attr_version = fuse_get_attr_version(fc);

		parent = dget_parent(entry);
		fuse_lookup_init(req, parent->d_inode, entry, &outarg);
		request_send(fc, req);
		dput(parent);
		err = req->out.h.error;
		fuse_put_request(fc, req);
		/* Zero nodeid is same as -ENOENT */
		if (!err && !outarg.nodeid)
			err = -ENOENT;
		if (!err) {
			struct fuse_inode *fi = get_fuse_inode(inode);
			if (outarg.nodeid != get_node_id(inode)) {
				fuse_send_forget(fc, forget_req,
						 outarg.nodeid, 1);
				return 0;
			}
			spin_lock(&fc->lock);
			fi->nlookup ++;
			spin_unlock(&fc->lock);
		}
		fuse_put_request(fc, forget_req);
		if (err || (outarg.attr.mode ^ inode->i_mode) & S_IFMT)
			return 0;

		fuse_change_attributes(inode, &outarg.attr,
				       entry_attr_timeout(&outarg),
				       attr_version);
		fuse_change_entry_timeout(entry, &outarg);
	}
	return 1;
}

static int invalid_nodeid(u64 nodeid)
{
	return !nodeid || nodeid == FUSE_ROOT_ID;
}

static struct dentry_operations fuse_dentry_operations = {
	.d_revalidate	= fuse_dentry_revalidate,
};

int fuse_valid_type(int m)
{
	return S_ISREG(m) || S_ISDIR(m) || S_ISLNK(m) || S_ISCHR(m) ||
		S_ISBLK(m) || S_ISFIFO(m) || S_ISSOCK(m);
}

/*
 * Add a directory inode to a dentry, ensuring that no other dentry
 * refers to this inode.  Called with fc->inst_mutex.
 */
static int fuse_d_add_directory(struct dentry *entry, struct inode *inode)
{
	struct dentry *alias = d_find_alias(inode);
	if (alias) {
		/* This tries to shrink the subtree below alias */
		fuse_invalidate_entry(alias);
		dput(alias);
		if (!list_empty(&inode->i_dentry))
			return -EBUSY;
	}
	d_add(entry, inode);
	return 0;
}

static int fuse_inode_eq(struct inode *inode, void *_nodeidp)
{
   unsigned long nodeid = *(unsigned long *) _nodeidp;
   if (get_node_id(inode) == nodeid)
      return 1;
   else
      return 0;
}

static int fuse_inode_set(struct inode *inode, void *_nodeidp)
{
   unsigned long nodeid = *(unsigned long *) _nodeidp;
   get_fuse_inode(inode)->nodeid = nodeid;
   return 0;
}

static size_t fuse_send_read(struct fuse_req *req, struct file *file,
			     struct inode *inode, loff_t pos, size_t count,
			     fl_owner_t owner)
{
   struct fuse_conn *fc = get_fuse_conn(inode);

   fuse_read_fill(req, file, inode, pos, count, FUSE_READ);
   if (owner != NULL) {
      struct fuse_read_in *inarg = &req->misc.read_in;

      inarg->read_flags |= FUSE_READ_LOCKOWNER;
      inarg->lock_owner = fuse_lock_owner_id(fc, owner);
   }
   request_send(fc, req);
   return req->out.args[0].size;
}

static int fuse_readpage(struct file *file, struct page *page)
{
   struct inode *inode = page->mapping->host;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_req *req;
   int err;

   err = -EIO;
   if (is_bad_inode(inode))
      goto out;

   req = fuse_get_req(fc);
   err = PTR_ERR(req);
   if (IS_ERR(req))
      goto out;

   req->out.page_zeroing = 1;
   req->num_pages = 1;
   req->pages[0] = page;
   fuse_send_read(req, file, inode, page_offset(page), PAGE_CACHE_SIZE,
		  NULL);
   err = req->out.h.error;
   fuse_put_request(fc, req);
   if (!err)
      SetPageUptodate(page);
   fuse_invalidate_attr(inode); /* atime changed */
  out:
   unlock_page(page);
   return err;
}

static int fuse_write_begin(struct file *file, struct address_space *mapping,
			    loff_t pos, unsigned len, unsigned flags,
			    struct page **pagep, void **fsdata)
{
   pgoff_t index = pos >> PAGE_CACHE_SHIFT;

   *pagep = __grab_cache_page(mapping, index);
   if (!*pagep)
      return -ENOMEM;
   return 0;
}

static void fuse_write_fill(struct fuse_req *req, struct file *file,
			    struct inode *inode, loff_t pos, size_t count,
			    int writepage)
{
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_file *ff = file->private_data;
   struct fuse_write_in *inarg = &req->misc.write.in;
   struct fuse_write_out *outarg = &req->misc.write.out;

   memset(inarg, 0, sizeof(struct fuse_write_in));
   inarg->fh = ff->fh;
   inarg->offset = pos;
   inarg->size = count;
   inarg->write_flags = writepage ? FUSE_WRITE_CACHE : 0;
   inarg->flags = file->f_flags;
   req->in.h.opcode = FUSE_WRITE;
   req->in.h.nodeid = get_node_id(inode);
   req->in.argpages = 1;
   req->in.numargs = 2;
   if (fc->minor < 9)
      req->in.args[0].size = FUSE_COMPAT_WRITE_IN_SIZE;
   else
      req->in.args[0].size = sizeof(struct fuse_write_in);
   req->in.args[0].value = inarg;
   req->in.args[1].size = count;
   req->out.numargs = 1;
   req->out.argpages = 1;
   req->out.argvar = 1;
   req->out.args[0].size = count; //sizeof(struct fuse_write_out);
//   req->out.args[0].value = outarg;
}

static size_t fuse_send_write2(struct fuse_req *req, struct file *file,
			      struct inode *inode, loff_t pos, size_t count,
			      fl_owner_t owner, int write)
{
   struct fuse_conn *fc = get_fuse_conn(inode);
   fuse_write_fill(req, file, inode, pos, count, 0);
   if (owner != NULL) {
      struct fuse_write_in *inarg = &req->misc.write.in;
      inarg->write_flags |= FUSE_WRITE_LOCKOWNER;
      inarg->lock_owner = fuse_lock_owner_id(fc, owner);
   }

   if(write == 2)
      req->in.h.opcode = FUSE_WRITE_READ;
   request_send(fc, req);
   return req->misc.write.out.size;
}

static size_t fuse_send_write(struct fuse_req *req, struct file *file,
			      struct inode *inode, loff_t pos, size_t count,
			      fl_owner_t owner)
{
   return fuse_send_write2(req, file, inode, pos, count, owner, 1);
}

static int fuse_buffered_write(struct file *file, struct inode *inode,
			       loff_t pos, unsigned count, struct page *page)
{
   int err;
   size_t nres;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_inode *fi = get_fuse_inode(inode);
   unsigned offset = pos & (PAGE_CACHE_SIZE - 1);
   struct fuse_req *req;

   if (is_bad_inode(inode))
      return -EIO;

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return PTR_ERR(req);

   req->num_pages = 1;
   req->pages[0] = page;
   req->page_offset = offset;
   nres = fuse_send_write(req, file, inode, pos, count, NULL);
   err = req->out.h.error;
   fuse_put_request(fc, req);
   if (!err && !nres)
      err = -EIO;
   if (!err) {
      pos += nres;
      spin_lock(&fc->lock);
      fi->attr_version = ++fc->attr_version;
      if (pos > inode->i_size)
	 i_size_write(inode, pos);
      spin_unlock(&fc->lock);

      if (count == PAGE_CACHE_SIZE)
	 SetPageUptodate(page);
   }
   fuse_invalidate_attr(inode);
   return err ? err : nres;
}

static int fuse_write_end(struct file *file, struct address_space *mapping,
			  loff_t pos, unsigned len, unsigned copied,
			  struct page *page, void *fsdata)
{
   struct inode *inode = mapping->host;
   int res = 0;

   if (copied)
      res = fuse_buffered_write(file, inode, pos, copied, page);

   unlock_page(page);
   page_cache_release(page);
   return res;
}

struct fuse_fill_data {
      struct fuse_req *req;
      struct file *file;
      struct inode *inode;
};

struct fuse_file *fuse_file_get(struct fuse_file *ff)
{
   atomic_inc(&ff->count);
   return ff;
}

static void fuse_release_end(struct fuse_conn *fc, struct fuse_req *req)
{
   dput(req->dentry);
   mntput(req->vfsmount);
   fuse_put_request(fc, req);
}

static void fuse_file_put(struct fuse_file *ff)
{
   if (atomic_dec_and_test(&ff->count)) {
      struct fuse_req *req = ff->reserved_req;
      struct fuse_conn *fc = get_fuse_conn(req->dentry->d_inode);
      req->end = fuse_release_end;
      request_send_background(fc, req);
      kfree(ff);
   }
}

static void fuse_readpages_end(struct fuse_conn *fc, struct fuse_req *req)
{
   int i;

   fuse_invalidate_attr(req->pages[0]->mapping->host); /* atime changed */

   for (i = 0; i < req->num_pages; i++) {
      struct page *page = req->pages[i];
      if (!req->out.h.error)
	 SetPageUptodate(page);
      else
	 SetPageError(page);
      unlock_page(page);
   }
   if (req->ff)
      fuse_file_put(req->ff);
   fuse_put_request(fc, req);
}

static void fuse_send_readpages(struct fuse_req *req, struct file *file,
				struct inode *inode)
{
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct sfuse_file_info *sfi = file->private_data;

   loff_t pos = page_offset(req->pages[0]);
   size_t count = req->num_pages << PAGE_CACHE_SHIFT;
   req->out.page_zeroing = 1;
   fuse_read_fill(req, file, inode, pos, count, FUSE_READ);
   if (fc->async_read) {
      struct fuse_file *ff = sfi->ff;
      req->ff = fuse_file_get(ff);
      req->end = fuse_readpages_end;
      request_send_background(fc, req);
   } else {
      request_send(fc, req);
      fuse_readpages_end(fc, req);
   }
}

static int fuse_readpages_fill(void *_data, struct page *page)
{
   struct fuse_fill_data *data = _data;
   struct fuse_req *req = data->req;
   struct inode *inode = data->inode;
   struct fuse_conn *fc = get_fuse_conn(inode);

   if (req->num_pages &&
       (req->num_pages == FUSE_MAX_PAGES_PER_REQ ||
	(req->num_pages + 1) * PAGE_CACHE_SIZE > fc->max_read ||
	req->pages[req->num_pages - 1]->index + 1 != page->index)) {
      fuse_send_readpages(req, data->file, inode);
      data->req = req = fuse_get_req(fc);
      if (IS_ERR(req)) {
	 unlock_page(page);
	 return PTR_ERR(req);
      }
   }
   req->pages[req->num_pages] = page;
   req->num_pages ++;
   return 0;
}

static int fuse_readpages(struct file *file, struct address_space *mapping,
			  struct list_head *pages, unsigned nr_pages)
{
   struct inode *inode = mapping->host;
   struct fuse_conn *fc = NULL;
   struct fuse_fill_data data;
//   struct sfuse_sb_info *sbi = get_fuse_conn(inode);
   int err;

//   fc = sbi->fc;
   fc = get_fuse_conn(inode);

   err = -EIO;
   if (is_bad_inode(inode))
      goto out;

   data.file = file;
   data.inode = inode;
   data.req = fuse_get_req(fc);
   err = PTR_ERR(data.req);
   if (IS_ERR(data.req))
      goto out;

   err = read_cache_pages(mapping, pages, fuse_readpages_fill, &data);
   if (!err) {
      if (data.req->num_pages)
	 fuse_send_readpages(data.req, file, inode);
      else
	 fuse_put_request(fc, data.req);
   }
  out:
   return err;
}

static int fuse_set_page_dirty(struct page *page)
{
   printk("fuse_set_page_dirty: should not happen\n");
   dump_stack();
   return 0;
}

static sector_t fuse_bmap(struct address_space *mapping, sector_t block)
{
   struct inode *inode = mapping->host;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_req *req;
   struct fuse_bmap_in inarg;
   struct fuse_bmap_out outarg;
   int err;

   if (!inode->i_sb->s_bdev || fc->no_bmap)
      return 0;

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return 0;

   memset(&inarg, 0, sizeof(inarg));
   inarg.block = block;
   inarg.blocksize = inode->i_sb->s_blocksize;
   req->in.h.opcode = FUSE_BMAP;
   req->in.h.nodeid = get_node_id(inode);
   req->in.numargs = 1;
   req->in.args[0].size = sizeof(inarg);
   req->in.args[0].value = &inarg;
   req->out.numargs = 1;
   req->out.args[0].size = sizeof(outarg);
   req->out.args[0].value = &outarg;
   request_send(fc, req);
   err = req->out.h.error;
   fuse_put_request(fc, req);
   if (err == -ENOSYS)
      fc->no_bmap = 1;

   return err ? 0 : outarg.block;
}

struct address_space_operations fuse_file_aops  = {
   .readpage	= fuse_readpage,
   .write_begin	= fuse_write_begin,
   .write_end	= fuse_write_end,
   .readpages	= fuse_readpages,
   .set_page_dirty	= fuse_set_page_dirty,
   .bmap		= fuse_bmap,
};

void fuse_init_file_inode(struct inode *inode)
{
//   inode->i_fop = &fuse_file_operations;
   inode->i_data.a_ops = &fuse_file_aops;
   /* Changing it to SFUSE operations */
   inode->i_fop = &sfuse_main_fops;
}

static void fuse_init_inode(struct inode *inode, struct fuse_attr *attr)
{
   inode->i_mode = attr->mode & S_IFMT;
   inode->i_size = attr->size;
   if (S_ISREG(inode->i_mode)) {
      fuse_init_common(inode);
      fuse_init_file_inode(inode);
   } else if (S_ISDIR(inode->i_mode))
      fuse_init_dir(inode);
   else if (S_ISLNK(inode->i_mode))
      fuse_init_symlink(inode);
   else if (S_ISCHR(inode->i_mode) || S_ISBLK(inode->i_mode) ||
	    S_ISFIFO(inode->i_mode) || S_ISSOCK(inode->i_mode)) {
      fuse_init_common(inode);
      init_special_inode(inode, inode->i_mode,
			 new_decode_dev(attr->rdev));
   } else
      BUG();
}

struct inode *fuse_iget(struct super_block *sb, unsigned long nodeid,
			int generation, struct fuse_attr *attr,
			u64 attr_valid, u64 attr_version)
{
   struct inode *inode;
   struct fuse_inode *fi = NULL;
   struct fuse_conn *fc = get_fuse_conn_super(sb);

  retry:
   inode = iget5_locked(sb, nodeid, fuse_inode_eq, fuse_inode_set, &nodeid);

   if (!inode)
      return NULL;

   if ((inode->i_state & I_NEW)) {
      inode->i_flags |= S_NOATIME|S_NOCMTIME;
      inode->i_generation = generation;
      inode->i_data.backing_dev_info = &fc->bdi;
      fuse_init_inode(inode, attr);
      unlock_new_inode(inode);
   } else if ((inode->i_mode ^ attr->mode) & S_IFMT) {
      /* Inode has changed type, any I/O on the old should fail */
      make_bad_inode(inode);
      iput(inode);
      printk("Retrying\n");
      goto retry;
   }

   fi = get_fuse_inode(inode);

   spin_lock(&fc->lock);
   fi->nlookup++;
   spin_unlock(&fc->lock);
   fuse_change_attributes(inode, attr, attr_valid, attr_version);

   printk("Leaving\n");
   return inode;
}

static struct dentry *fuse_lookup(struct inode *dir, struct dentry *entry,
				  struct nameidata *nd)
{
   int err;
   struct fuse_entry_out outarg;
   struct inode *inode = NULL;
   struct fuse_conn *fc = get_fuse_conn(dir);
   struct fuse_req *req;
   struct fuse_req *forget_req;
   u64 attr_version;

   if (entry->d_name.len > FUSE_NAME_MAX)
      return ERR_PTR(-ENAMETOOLONG);

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return ERR_PTR(PTR_ERR(req));

   forget_req = fuse_get_req(fc);
   if (IS_ERR(forget_req)) {
      fuse_put_request(fc, req);
      return ERR_PTR(PTR_ERR(forget_req));
   }

   attr_version = fuse_get_attr_version(fc);

   fuse_lookup_init(req, dir, entry, &outarg);
   request_send(fc, req);
   err = req->out.h.error;
   fuse_put_request(fc, req);
   /* Zero nodeid is same as -ENOENT, but with valid timeout */
   if (!err && outarg.nodeid &&
       (invalid_nodeid(outarg.nodeid) ||
	!fuse_valid_type(outarg.attr.mode)))
      err = -EIO;
   if (!err && outarg.nodeid) {
      inode = fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			&outarg.attr, entry_attr_timeout(&outarg),
			attr_version);
      if (!inode) {
	 fuse_send_forget(fc, forget_req, outarg.nodeid, 1);
	 return ERR_PTR(-ENOMEM);
      }
   }
   fuse_put_request(fc, forget_req);
   if (err && err != -ENOENT)
      return ERR_PTR(err);

   if (inode && S_ISDIR(inode->i_mode)) {
      mutex_lock(&fc->inst_mutex);
      err = fuse_d_add_directory(entry, inode);
      mutex_unlock(&fc->inst_mutex);
      if (err) {
	 iput(inode);
	 return ERR_PTR(err);
      }
   } else
      d_add(entry, inode);

   entry->d_op = &fuse_dentry_operations;
   if (!err)
      fuse_change_entry_timeout(entry, &outarg);
   else
      fuse_invalidate_entry_cache(entry);
   return NULL;
}

void fuse_release_fill(struct fuse_file *ff, u64 nodeid, int flags, int opcode)
{
   struct fuse_req *req = ff->reserved_req;
   struct fuse_release_in *inarg = &req->misc.release_in;

   inarg->fh = ff->fh;
   inarg->flags = flags;
   req->in.h.opcode = opcode;
   req->in.h.nodeid = nodeid;
   req->in.numargs = 1;
   req->in.args[0].size = sizeof(struct fuse_release_in);
   req->in.args[0].value = inarg;
}

/*
 * Synchronous release for the case when something goes wrong in CREATE_OPEN
 */
static void fuse_sync_release(struct fuse_conn *fc, struct fuse_file *ff,
			      u64 nodeid, int flags)
{
	fuse_release_fill(ff, nodeid, flags, FUSE_RELEASE);
	ff->reserved_req->force = 1;
	request_send(fc, ff->reserved_req);
	fuse_put_request(fc, ff->reserved_req);
	kfree(ff);
}

struct fuse_file *fuse_file_alloc(void)
{
   struct fuse_file *ff;
   ff = kmalloc(sizeof(struct fuse_file), GFP_KERNEL);
   if (ff) {
      ff->reserved_req = fuse_request_alloc();
      if (!ff->reserved_req) {
	 kfree(ff);
	 ff = NULL;
      } else {
	 INIT_LIST_HEAD(&ff->write_entry);
	 atomic_set(&ff->count, 0);
      }
   }
   return ff;
}

void fuse_file_free(struct fuse_file *ff)
{
   fuse_request_free(ff->reserved_req);
   kfree(ff);
}

void fuse_send_forget(struct fuse_conn *fc, struct fuse_req *req,
		      unsigned long nodeid, u64 nlookup)
{
   struct fuse_forget_in *inarg = &req->misc.forget_in;
   inarg->nlookup = nlookup;
   req->in.h.opcode = FUSE_FORGET;
   req->in.h.nodeid = nodeid;
   req->in.numargs = 1;
   req->in.args[0].size = sizeof(struct fuse_forget_in);
   req->in.args[0].value = inarg;
   request_send_noreply(fc, req);
}

static int fuse_get_user_pages(struct fuse_req *req, const char __user *buf,
			       unsigned nbytes, int write)
{
   unsigned long user_addr = (unsigned long) buf;
   unsigned offset = user_addr & ~PAGE_MASK;
   int npages;

   /* This doesn't work with nfsd */
   if (!current->mm)
      return -EPERM;

   nbytes = min(nbytes, (unsigned) FUSE_MAX_PAGES_PER_REQ << PAGE_SHIFT);
   npages = (nbytes + offset + PAGE_SIZE - 1) >> PAGE_SHIFT;
   npages = min(max(npages, 1), FUSE_MAX_PAGES_PER_REQ);
   down_read(&current->mm->mmap_sem);
   npages = get_user_pages(current, current->mm, user_addr, npages, write,
			   0, req->pages, NULL);
   up_read(&current->mm->mmap_sem);
   if (npages < 0)
      return npages;

   req->num_pages = npages;
   req->page_offset = offset;
   return 0;
}


u64 fuse_lock_owner_id(struct fuse_conn *fc, fl_owner_t id)
{
   u32 *k = fc->scramble_key;
   u64 v = (unsigned long) id;
   u32 v0 = v;
   u32 v1 = v >> 32;
   u32 sum = 0;
   int i;

   for (i = 0; i < 32; i++) {
      v0 += ((v1 << 4 ^ v1 >> 5) + v1) ^ (sum + k[sum & 3]);
      sum += 0x9E3779B9;
      v1 += ((v0 << 4 ^ v0 >> 5) + v0) ^ (sum + k[sum>>11 & 3]);
   }

   return (u64) v0 + ((u64) v1 << 32);
}



static void fuse_release_user_pages(struct fuse_req *req, int write)
{
   unsigned i;

   for (i = 0; i < req->num_pages; i++) {
      struct page *page = req->pages[i];
      if (write)
	 set_page_dirty_lock(page);
      put_page(page);
   }
}

ssize_t fuse_direct_io(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos, int write)
{
   struct inode *inode = file->f_path.dentry->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   size_t nmax = write ? fc->max_write : fc->max_read;
   loff_t pos = *ppos;
   ssize_t res = 0;
   struct fuse_req *req;

   if (is_bad_inode(inode))
      return -EIO;

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return PTR_ERR(req);

   while (count) {
      size_t nres;
      size_t nbytes = min(count, nmax);
      int err = fuse_get_user_pages(req, buf, nbytes, !write);
      if (err) {
	 res = err;
	 break;
      }
      nbytes = (req->num_pages << PAGE_SHIFT) - req->page_offset;
      nbytes = min(count, nbytes);
      if (write > 0)
	 nres = fuse_send_write2(req, file, inode, pos, nbytes,
				current->files, write);
      else
	 nres = fuse_send_read(req, file, inode, pos, nbytes,
			       current->files);
      fuse_release_user_pages(req, !write);
      if (req->out.h.error) {
	 if (!res)
	    res = req->out.h.error;
	 break;
      } else if (nres > nbytes) {
	 res = -EIO;
	 break;
      }
      count -= nres;
      res += nres;
//      pos += nres;
      buf += nres;
      if (nres != nbytes)
	 break;
      if (count) {
	 fuse_put_request(fc, req);
	 req = fuse_get_req(fc);
	 if (IS_ERR(req))
	    break;
      }
   }
   fuse_put_request(fc, req);
   if (res > 0) {
      if (write) {
	 spin_lock(&fc->lock);
	 if (pos > inode->i_size)
	    i_size_write(inode, pos);
	 spin_unlock(&fc->lock);
      }
      *ppos = pos;
   }
   fuse_invalidate_attr(inode);

   return res;
}

static ssize_t fuse_direct_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
   return fuse_direct_io(file, buf, count, ppos, 0);
}

static ssize_t fuse_direct_write(struct file *file, const char __user *buf,
				 size_t count, loff_t *ppos)
{
   struct inode *inode = file->f_path.dentry->d_inode;
   ssize_t res;
   /* Don't allow parallel writes to the same file */
   mutex_lock(&inode->i_mutex);
   res = generic_write_checks(file, ppos, &count, 0);
   if (!res)
      res = fuse_direct_io(file, buf, count, ppos, 1);
   mutex_unlock(&inode->i_mutex);
   return res;
}

int fuse_release_common(struct inode *inode, struct file *file, int isdir)
{
   struct fuse_file *ff = file->private_data;
   if (ff) {
      struct fuse_conn *fc = get_fuse_conn(inode);

      fuse_release_fill(ff, get_node_id(inode), file->f_flags,
			isdir ? FUSE_RELEASEDIR : FUSE_RELEASE);

      /* Hold vfsmount and dentry until release is finished */
      ff->reserved_req->vfsmount = mntget(file->f_path.mnt);
      ff->reserved_req->dentry = dget(file->f_path.dentry);

      spin_lock(&fc->lock);
      list_del(&ff->write_entry);
      spin_unlock(&fc->lock);
      /*
       * Normally this will send the RELEASE request,
       * however if some asynchronous READ or WRITE requests
       * are outstanding, the sending will be delayed
       */
      fuse_file_put(ff);
   }

   /* Return value is ignored by VFS */
   return 0;
}

int fuse_fsync_common(struct file *file, struct dentry *de, int datasync,
		      int isdir)
{
   struct inode *inode = de->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_file *ff = file->private_data;
   struct fuse_req *req;
   struct fuse_fsync_in inarg;
   int err;

   if (is_bad_inode(inode))
      return -EIO;

   if ((!isdir && fc->no_fsync) || (isdir && fc->no_fsyncdir))
      return 0;

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return PTR_ERR(req);

   memset(&inarg, 0, sizeof(inarg));
   inarg.fh = ff->fh;
   inarg.fsync_flags = datasync ? 1 : 0;
   req->in.h.opcode = isdir ? FUSE_FSYNCDIR : FUSE_FSYNC;
   req->in.h.nodeid = get_node_id(inode);
   req->in.numargs = 1;
   req->in.args[0].size = sizeof(inarg);
   req->in.args[0].value = &inarg;
   request_send(fc, req);
   err = req->out.h.error;
   fuse_put_request(fc, req);
   if (err == -ENOSYS) {
      if (isdir)
	 fc->no_fsyncdir = 1;
      else
	 fc->no_fsync = 1;
      err = 0;
   }
   return err;
}

static const struct file_operations fuse_direct_io_file_operations = {
   .llseek		= generic_file_llseek,
   .read		= fuse_direct_read,
   .write		= fuse_direct_write,
   .open		= fuse_open,
   .flush		= fuse_flush,
   .release	        = fuse_release,
   .fsync		= fuse_fsync,
   .lock		= fuse_file_lock,
   .flock		= fuse_file_flock,
   /* no mmap and splice_read */
};


void fuse_finish_open(struct inode *inode, struct file *file,
		      struct fuse_file *ff, struct fuse_open_out *outarg)
{
   if (outarg->open_flags & FOPEN_DIRECT_IO)
      file->f_op = &fuse_direct_io_file_operations;
   if (!(outarg->open_flags & FOPEN_KEEP_CACHE))
      invalidate_inode_pages2(inode->i_mapping);
   ff->fh = outarg->fh;
   file->private_data = fuse_file_get(ff);
}

/*
 * Atomic create+open operation
 *
 * If the filesystem doesn't support this, then fall back to separate
 * 'mknod' + 'open' requests.
 */
static int fuse_create_open(struct inode *dir, struct dentry *entry, int mode,
			    struct nameidata *nd)
{
	int err;
	struct inode *inode;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req;
	struct fuse_req *forget_req;
	struct fuse_open_in inarg;
	struct fuse_open_out outopen;
	struct fuse_entry_out outentry;
	struct fuse_file *ff;
	struct file *file;
	int flags = nd->intent.open.flags - 1;

	if (fc->no_create)
		return -ENOSYS;

	forget_req = fuse_get_req(fc);
	if (IS_ERR(forget_req))
		return PTR_ERR(forget_req);

	req = fuse_get_req(fc);
	err = PTR_ERR(req);
	if (IS_ERR(req))
		goto out_put_forget_req;

	err = -ENOMEM;
	ff = fuse_file_alloc();
	if (!ff)
		goto out_put_request;

	flags &= ~O_NOCTTY;
	memset(&inarg, 0, sizeof(inarg));
	memset(&outentry, 0, sizeof(outentry));
	inarg.flags = flags;
	inarg.mode = mode;
	req->in.h.opcode = FUSE_CREATE;
	req->in.h.nodeid = get_node_id(dir);
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	req->out.numargs = 2;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outentry);
	req->out.args[0].value = &outentry;
	req->out.args[1].size = sizeof(outopen);
	req->out.args[1].value = &outopen;
	request_send(fc, req);
	err = req->out.h.error;
	if (err) {
		if (err == -ENOSYS)
			fc->no_create = 1;
		goto out_free_ff;
	}

	err = -EIO;
	if (!S_ISREG(outentry.attr.mode) || invalid_nodeid(outentry.nodeid))
		goto out_free_ff;

	fuse_put_request(fc, req);
	inode = fuse_iget(dir->i_sb, outentry.nodeid, outentry.generation,
			  &outentry.attr, entry_attr_timeout(&outentry), 0);
	if (!inode) {
		flags &= ~(O_CREAT | O_EXCL | O_TRUNC);
		ff->fh = outopen.fh;
		fuse_sync_release(fc, ff, outentry.nodeid, flags);
		fuse_send_forget(fc, forget_req, outentry.nodeid, 1);
		return -ENOMEM;
	}
	fuse_put_request(fc, forget_req);
	d_instantiate(entry, inode);
	fuse_change_entry_timeout(entry, &outentry);
	file = lookup_instantiate_filp(nd, entry, generic_file_open);
	if (IS_ERR(file)) {
		ff->fh = outopen.fh;
		fuse_sync_release(fc, ff, outentry.nodeid, flags);
		return PTR_ERR(file);
	}
	fuse_finish_open(inode, file, ff, &outopen);
	return 0;

 out_free_ff:
	fuse_file_free(ff);
 out_put_request:
	fuse_put_request(fc, req);
 out_put_forget_req:
	fuse_put_request(fc, forget_req);
	return err;
}

/*
 * Code shared between mknod, mkdir, symlink and link
 */
static int create_new_entry(struct fuse_conn *fc, struct fuse_req *req,
			    struct inode *dir, struct dentry *entry,
			    int mode)
{
	struct fuse_entry_out outarg;
	struct inode *inode;
	int err;
	struct fuse_req *forget_req;

	forget_req = fuse_get_req(fc);
	if (IS_ERR(forget_req)) {
		fuse_put_request(fc, req);
		return PTR_ERR(forget_req);
	}

	memset(&outarg, 0, sizeof(outarg));
	req->in.h.nodeid = get_node_id(dir);
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ENTRY_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err)
		goto out_put_forget_req;

	err = -EIO;
	if (invalid_nodeid(outarg.nodeid))
		goto out_put_forget_req;

	if ((outarg.attr.mode ^ mode) & S_IFMT)
		goto out_put_forget_req;

	inode = fuse_iget(dir->i_sb, outarg.nodeid, outarg.generation,
			  &outarg.attr, entry_attr_timeout(&outarg), 0);
	if (!inode) {
		fuse_send_forget(fc, forget_req, outarg.nodeid, 1);
		return -ENOMEM;
	}
	fuse_put_request(fc, forget_req);

	if (S_ISDIR(inode->i_mode)) {
		struct dentry *alias;
		mutex_lock(&fc->inst_mutex);
		alias = d_find_alias(inode);
		if (alias) {
			/* New directory must have moved since mkdir */
			mutex_unlock(&fc->inst_mutex);
			dput(alias);
			iput(inode);
			return -EBUSY;
		}
		d_instantiate(entry, inode);
		mutex_unlock(&fc->inst_mutex);
	} else
		d_instantiate(entry, inode);

	fuse_change_entry_timeout(entry, &outarg);
	fuse_invalidate_attr(dir);
	return 0;

 out_put_forget_req:
	fuse_put_request(fc, forget_req);
	return err;
}

static int fuse_mknod(struct inode *dir, struct dentry *entry, int mode,
		      dev_t rdev)
{
	struct fuse_mknod_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	inarg.rdev = new_encode_dev(rdev);
	req->in.h.opcode = FUSE_MKNOD;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, req, dir, entry, mode);
}

static int fuse_create(struct inode *dir, struct dentry *entry, int mode,
		       struct nameidata *nd)
{

   /*TEstingsfuse */
   return sfuse_create(dir, entry, mode, nd);

   if (nd && (nd->flags & LOOKUP_OPEN)) {
      int err = fuse_create_open(dir, entry, mode, nd);
      if (err != -ENOSYS)
	 return err;
      /* Fall back on mknod */
   }
   return fuse_mknod(dir, entry, mode, 0);
}

static int fuse_mkdir(struct inode *dir, struct dentry *entry, int mode)
{
	struct fuse_mkdir_in inarg;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.mode = mode;
	req->in.h.opcode = FUSE_MKDIR;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = entry->d_name.len + 1;
	req->in.args[1].value = entry->d_name.name;
	return create_new_entry(fc, req, dir, entry, S_IFDIR);
}

static int fuse_symlink(struct inode *dir, struct dentry *entry,
			const char *link)
{
	struct fuse_conn *fc = get_fuse_conn(dir);
	unsigned len = strlen(link) + 1;
	struct fuse_req *req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_SYMLINK;
	req->in.numargs = 2;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	req->in.args[1].size = len;
	req->in.args[1].value = link;
	return create_new_entry(fc, req, dir, entry, S_IFLNK);
}

static int fuse_unlink(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_UNLINK;
	req->in.h.nodeid = get_node_id(dir);
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		struct inode *inode = entry->d_inode;

		/* Set nlink to zero so the inode can be cleared, if
                   the inode does have more links this will be
                   discovered at the next lookup/getattr */
		clear_nlink(inode);
		fuse_invalidate_attr(inode);
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rmdir(struct inode *dir, struct dentry *entry)
{
	int err;
	struct fuse_conn *fc = get_fuse_conn(dir);
	struct fuse_req *req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_RMDIR;
	req->in.h.nodeid = get_node_id(dir);
	req->in.numargs = 1;
	req->in.args[0].size = entry->d_name.len + 1;
	req->in.args[0].value = entry->d_name.name;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		clear_nlink(entry->d_inode);
		fuse_invalidate_attr(dir);
		fuse_invalidate_entry_cache(entry);
	} else if (err == -EINTR)
		fuse_invalidate_entry(entry);
	return err;
}

static int fuse_rename(struct inode *olddir, struct dentry *oldent,
		       struct inode *newdir, struct dentry *newent)
{
	int err;
	struct fuse_rename_in inarg;
	struct fuse_conn *fc = get_fuse_conn(olddir);
	struct fuse_req *req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.newdir = get_node_id(newdir);
	req->in.h.opcode = FUSE_RENAME;
	req->in.h.nodeid = get_node_id(olddir);
	req->in.numargs = 3;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = oldent->d_name.len + 1;
	req->in.args[1].value = oldent->d_name.name;
	req->in.args[2].size = newent->d_name.len + 1;
	req->in.args[2].value = newent->d_name.name;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		/* ctime changes */
		fuse_invalidate_attr(oldent->d_inode);

		fuse_invalidate_attr(olddir);
		if (olddir != newdir)
			fuse_invalidate_attr(newdir);

		/* newent will end up negative */
		if (newent->d_inode)
			fuse_invalidate_entry_cache(newent);
	} else if (err == -EINTR) {
		/* If request was interrupted, DEITY only knows if the
		   rename actually took place.  If the invalidation
		   fails (e.g. some process has CWD under the renamed
		   directory), then there can be inconsistency between
		   the dcache and the real filesystem.  Tough luck. */
		fuse_invalidate_entry(oldent);
		if (newent->d_inode)
			fuse_invalidate_entry(newent);
	}

	return err;
}

static int fuse_link(struct dentry *entry, struct inode *newdir,
		     struct dentry *newent)
{
	int err;
	struct fuse_link_in inarg;
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.oldnodeid = get_node_id(inode);
	req->in.h.opcode = FUSE_LINK;
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = newent->d_name.len + 1;
	req->in.args[1].value = newent->d_name.name;
	err = create_new_entry(fc, req, newdir, newent, inode->i_mode);
	/* Contrary to "normal" filesystems it can happen that link
	   makes two "logical" inodes point to the same "physical"
	   inode.  We invalidate the attributes of the old one, so it
	   will reflect changes in the backing inode (link count,
	   etc.)
	*/
	if (!err || err == -EINTR)
		fuse_invalidate_attr(inode);
	return err;
}

static void fuse_fillattr(struct inode *inode, struct fuse_attr *attr,
			  struct kstat *stat)
{
	stat->dev = inode->i_sb->s_dev;
	stat->ino = attr->ino;
	stat->mode = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
	stat->nlink = attr->nlink;
	stat->uid = attr->uid;
	stat->gid = attr->gid;
	stat->rdev = inode->i_rdev;
	stat->atime.tv_sec = attr->atime;
	stat->atime.tv_nsec = attr->atimensec;
	stat->mtime.tv_sec = attr->mtime;
	stat->mtime.tv_nsec = attr->mtimensec;
	stat->ctime.tv_sec = attr->ctime;
	stat->ctime.tv_nsec = attr->ctimensec;
	stat->size = attr->size;
	stat->blocks = attr->blocks;
	stat->blksize = (1 << inode->i_blkbits);
}

static void fuse_truncate(struct address_space *mapping, loff_t offset)
{
   /* See vmtruncate() */
   unmap_mapping_range(mapping, offset + PAGE_SIZE - 1, 0, 1);
   truncate_inode_pages(mapping, offset);
   unmap_mapping_range(mapping, offset + PAGE_SIZE - 1, 0, 1);
}

void fuse_change_attributes(struct inode *inode, struct fuse_attr *attr,
			    u64 attr_valid, u64 attr_version)
{
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_inode *fi = get_fuse_inode(inode);
   loff_t oldsize;

   spin_lock(&fc->lock);
   if (attr_version != 0 && fi->attr_version > attr_version) {
      spin_unlock(&fc->lock);
      return;
   }
   fi->attr_version = ++fc->attr_version;
   fi->i_time = attr_valid;

   inode->i_ino     = attr->ino;
   inode->i_mode    = (inode->i_mode & S_IFMT) | (attr->mode & 07777);
   inode->i_nlink   = attr->nlink;
   inode->i_uid     = attr->uid;
   inode->i_gid     = attr->gid;
   inode->i_blocks  = attr->blocks;
   inode->i_atime.tv_sec   = attr->atime;
   inode->i_atime.tv_nsec  = attr->atimensec;
   inode->i_mtime.tv_sec   = attr->mtime;
   inode->i_mtime.tv_nsec  = attr->mtimensec;
   inode->i_ctime.tv_sec   = attr->ctime;
   inode->i_ctime.tv_nsec  = attr->ctimensec;

   if (attr->blksize != 0)
      inode->i_blkbits = ilog2(attr->blksize);
   else
      inode->i_blkbits = inode->i_sb->s_blocksize_bits;

   /*
    * Don't set the sticky bit in i_mode, unless we want the VFS
    * to check permissions.  This prevents failures due to the
    * check in may_delete().
    */
   fi->orig_i_mode = inode->i_mode;
   if (!(fc->flags & FUSE_DEFAULT_PERMISSIONS))
      inode->i_mode &= ~S_ISVTX;

   oldsize = inode->i_size;
   i_size_write(inode, attr->size);
   spin_unlock(&fc->lock);

   if (S_ISREG(inode->i_mode) && oldsize != attr->size) {
      if (attr->size < oldsize)
	 fuse_truncate(inode->i_mapping, attr->size);
      invalidate_inode_pages2(inode->i_mapping);
   }
}

static int fuse_do_getattr(struct inode *inode, struct kstat *stat,
			   struct file *file)
{
	int err;
	struct fuse_getattr_in inarg;
	struct fuse_attr_out outarg;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	u64 attr_version;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	attr_version = fuse_get_attr_version(fc);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	/* Directories have separate file-handle space */
	if (file && S_ISREG(inode->i_mode)) {
		struct fuse_file *ff = file->private_data;

		inarg.getattr_flags |= FUSE_GETATTR_FH;
		inarg.fh = ff->fh;
	}
	req->in.h.opcode = FUSE_GETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (!err) {
		if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
			make_bad_inode(inode);
			err = -EIO;
		} else {
			fuse_change_attributes(inode, &outarg.attr,
					       attr_timeout(&outarg),
					       attr_version);
			if (stat)
				fuse_fillattr(inode, &outarg.attr, stat);
		}
	}
	return err;
}

int fuse_update_attributes(struct inode *inode, struct kstat *stat,
			   struct file *file, bool *refreshed)
{
	struct fuse_inode *fi = get_fuse_inode(inode);
	int err;
	bool r;

	if (fi->i_time < get_jiffies_64()) {
		r = true;
		err = fuse_do_getattr(inode, stat, file);
	} else {
		r = false;
		err = 0;
		if (stat) {
			generic_fillattr(inode, stat);
			stat->mode = fi->orig_i_mode;
		}
	}

	if (refreshed != NULL)
		*refreshed = r;

	return err;
}

/*
 * Calling into a user-controlled filesystem gives the filesystem
 * daemon ptrace-like capabilities over the requester process.  This
 * means, that the filesystem daemon is able to record the exact
 * filesystem operations performed, and can also control the behavior
 * of the requester process in otherwise impossible ways.  For example
 * it can delay the operation for arbitrary length of time allowing
 * DoS against the requester.
 *
 * For this reason only those processes can call into the filesystem,
 * for which the owner of the mount has ptrace privilege.  This
 * excludes processes started by other users, suid or sgid processes.
 */
int fuse_allow_task(struct fuse_conn *fc, struct task_struct *task)
{
	if (fc->flags & FUSE_ALLOW_OTHER)
		return 1;

	if (task->euid == fc->user_id &&
	    task->suid == fc->user_id &&
	    task->uid == fc->user_id &&
	    task->egid == fc->group_id &&
	    task->sgid == fc->group_id &&
	    task->gid == fc->group_id)
		return 1;

	return 0;
}

static int fuse_access(struct inode *inode, int mask)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_access_in inarg;
	int err;

	if (fc->no_access)
		return 0;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.mask = mask;
	req->in.h.opcode = FUSE_ACCESS;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_access = 1;
		err = 0;
	}
	return err;
}

/*
 * Check permission.  The two basic access models of FUSE are:
 *
 * 1) Local access checking ('default_permissions' mount option) based
 * on file mode.  This is the plain old disk filesystem permission
 * modell.
 *
 * 2) "Remote" access checking, where server is responsible for
 * checking permission in each inode operation.  An exception to this
 * is if ->permission() was invoked from sys_access() in which case an
 * access request is sent.  Execute permission is still checked
 * locally based on file mode.
 */
static int fuse_permission(struct inode *inode, int mask, struct nameidata *nd)
{
	struct fuse_conn *fc = get_fuse_conn(inode);
	bool refreshed = false;
	int err = 0;

	if (!fuse_allow_task(fc, current))
		return -EACCES;

	/*
	 * If attributes are needed, refresh them before proceeding
	 */
	if ((fc->flags & FUSE_DEFAULT_PERMISSIONS) ||
	    ((mask & MAY_EXEC) && S_ISREG(inode->i_mode))) {
		err = fuse_update_attributes(inode, NULL, NULL, &refreshed);
		if (err)
			return err;
	}

	if (fc->flags & FUSE_DEFAULT_PERMISSIONS) {
		int err = generic_permission(inode, mask, NULL);

		/* If permission is denied, try to refresh file
		   attributes.  This is also needed, because the root
		   node will at first have no permissions */
		if (err == -EACCES && !refreshed) {
			err = fuse_do_getattr(inode, NULL, NULL);
			if (!err)
				err = generic_permission(inode, mask, NULL);
		}

		/* Note: the opposite of the above test does not
		   exist.  So if permissions are revoked this won't be
		   noticed immediately, only after the attribute
		   timeout has expired */
	} else if (nd && (nd->flags & (LOOKUP_ACCESS | LOOKUP_CHDIR))) {
		err = fuse_access(inode, mask);
	} else if ((mask & MAY_EXEC) && S_ISREG(inode->i_mode)) {
		if (!(inode->i_mode & S_IXUGO)) {
			if (refreshed)
				return -EACCES;

			err = fuse_do_getattr(inode, NULL, NULL);
			if (!err && !(inode->i_mode & S_IXUGO))
				return -EACCES;
		}
	}
	return err;
}

static int parse_dirfile(char *buf, size_t nbytes, struct file *file,
			 void *dstbuf, filldir_t filldir)
{
	while (nbytes >= FUSE_NAME_OFFSET) {
		struct fuse_dirent *dirent = (struct fuse_dirent *) buf;
		size_t reclen = FUSE_DIRENT_SIZE(dirent);
		int over;
		if (!dirent->namelen || dirent->namelen > FUSE_NAME_MAX)
			return -EIO;
		if (reclen > nbytes)
			break;

		over = filldir(dstbuf, dirent->name, dirent->namelen,
			       file->f_pos, dirent->ino, dirent->type);
		if (over)
			break;

		buf += reclen;
		nbytes -= reclen;
		file->f_pos = dirent->off;
	}

	return 0;
}

void fuse_read_fill(struct fuse_req *req, struct file *file,
		    struct inode *inode, loff_t pos, size_t count, int opcode)
{
   struct fuse_read_in *inarg = &req->misc.read_in;
   struct sfuse_file_info *sfi = file->private_data;
   struct fuse_file *ff = sfi->ff;

   inarg->fh = ff->fh;
   inarg->offset = pos;
   inarg->size = count;
   inarg->flags = file->f_flags;
   req->in.h.opcode = opcode;
   req->in.h.nodeid = get_node_id(inode);
   req->in.numargs = 1;
   req->in.args[0].size = sizeof(struct fuse_read_in);
   req->in.args[0].value = inarg;
   req->out.argpages = 1;
   req->out.argvar = 1;
   req->out.numargs = 1;
   req->out.args[0].size = count;
}

int fuse_readdir(struct file *file, void *dstbuf, filldir_t filldir)
{
   int err;
   size_t nbytes;
   struct page *page;
   struct inode *inode = file->f_path.dentry->d_inode;
   struct fuse_conn *fc = get_fuse_conn(inode);
   struct fuse_req *req;

   if (is_bad_inode(inode))
      return -EIO;

   req = fuse_get_req(fc);
   if (IS_ERR(req))
      return PTR_ERR(req);

   page = alloc_page(GFP_KERNEL);
   if (!page) {
      fuse_put_request(fc, req);
      return -ENOMEM;
   }
   req->num_pages = 1;
   req->pages[0] = page;
   fuse_read_fill(req, file, inode, file->f_pos, PAGE_SIZE, FUSE_READDIR);
   request_send(fc, req);
   nbytes = req->out.args[0].size;
   err = req->out.h.error;
   fuse_put_request(fc, req);
   if (!err)
      err = parse_dirfile(page_address(page), nbytes, file, dstbuf,
			  filldir);

   __free_page(page);
   fuse_invalidate_attr(inode); /* atime changed */
   return err;
}

static char *read_link(struct dentry *dentry)
{
	struct inode *inode = dentry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req = fuse_get_req(fc);
	char *link;

	if (IS_ERR(req))
		return ERR_PTR(PTR_ERR(req));

	link = (char *) __get_free_page(GFP_KERNEL);
	if (!link) {
		link = ERR_PTR(-ENOMEM);
		goto out;
	}
	req->in.h.opcode = FUSE_READLINK;
	req->in.h.nodeid = get_node_id(inode);
	req->out.argvar = 1;
	req->out.numargs = 1;
	req->out.args[0].size = PAGE_SIZE - 1;
	req->out.args[0].value = link;
	request_send(fc, req);
	if (req->out.h.error) {
		free_page((unsigned long) link);
		link = ERR_PTR(req->out.h.error);
	} else
		link[req->out.args[0].size] = '\0';
 out:
	fuse_put_request(fc, req);
	fuse_invalidate_attr(inode); /* atime changed */
	return link;
}

static void free_link(char *link)
{
	if (!IS_ERR(link))
		free_page((unsigned long) link);
}

static void *fuse_follow_link(struct dentry *dentry, struct nameidata *nd)
{
	nd_set_link(nd, read_link(dentry));
	return NULL;
}

static void fuse_put_link(struct dentry *dentry, struct nameidata *nd, void *c)
{
	free_link(nd_get_link(nd));
}

static int fuse_dir_open(struct inode *inode, struct file *file)
{
	return fuse_open_common(inode, file, 1);
}

static int fuse_dir_release(struct inode *inode, struct file *file)
{
	return fuse_release_common(inode, file, 1);
}

static int fuse_dir_fsync(struct file *file, struct dentry *de, int datasync)
{
	/* nfsd can call this with no file */
	return file ? fuse_fsync_common(file, de, datasync, 1) : 0;
}

static bool update_mtime(unsigned ivalid)
{
	/* Always update if mtime is explicitly set  */
	if (ivalid & ATTR_MTIME_SET)
		return true;

	/* If it's an open(O_TRUNC) or an ftruncate(), don't update */
	if ((ivalid & ATTR_SIZE) && (ivalid & (ATTR_OPEN | ATTR_FILE)))
		return false;

	/* In all other cases update */
	return true;
}

static void iattr_to_fattr(struct iattr *iattr, struct fuse_setattr_in *arg)
{
	unsigned ivalid = iattr->ia_valid;

	if (ivalid & ATTR_MODE)
		arg->valid |= FATTR_MODE,   arg->mode = iattr->ia_mode;
	if (ivalid & ATTR_UID)
		arg->valid |= FATTR_UID,    arg->uid = iattr->ia_uid;
	if (ivalid & ATTR_GID)
		arg->valid |= FATTR_GID,    arg->gid = iattr->ia_gid;
	if (ivalid & ATTR_SIZE)
		arg->valid |= FATTR_SIZE,   arg->size = iattr->ia_size;
	if (ivalid & ATTR_ATIME) {
		arg->valid |= FATTR_ATIME;
		arg->atime = iattr->ia_atime.tv_sec;
		arg->atimensec = iattr->ia_atime.tv_nsec;
		if (!(ivalid & ATTR_ATIME_SET))
			arg->valid |= FATTR_ATIME_NOW;
	}
	if ((ivalid & ATTR_MTIME) && update_mtime(ivalid)) {
		arg->valid |= FATTR_MTIME;
		arg->mtime = iattr->ia_mtime.tv_sec;
		arg->mtimensec = iattr->ia_mtime.tv_nsec;
		if (!(ivalid & ATTR_MTIME_SET))
			arg->valid |= FATTR_MTIME_NOW;
	}
}

/*
 * Set attributes, and at the same time refresh them.
 *
 * Truncation is slightly complicated, because the 'truncate' request
 * may fail, in which case we don't want to touch the mapping.
 * vmtruncate() doesn't allow for this case, so do the rlimit checking
 * and the actual truncation by hand.
 */
static int fuse_do_setattr(struct dentry *entry, struct iattr *attr,
			   struct file *file)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_setattr_in inarg;
	struct fuse_attr_out outarg;
	int err;

	if (!fuse_allow_task(fc, current))
		return -EACCES;

	if (fc->flags & FUSE_DEFAULT_PERMISSIONS) {
		err = inode_change_ok(inode, attr);
		if (err)
			return err;
	}

	if ((attr->ia_valid & ATTR_OPEN) && fc->atomic_o_trunc)
		return 0;

	if (attr->ia_valid & ATTR_SIZE) {
		unsigned long limit;
		if (IS_SWAPFILE(inode))
			return -ETXTBSY;
		limit = current->signal->rlim[RLIMIT_FSIZE].rlim_cur;
		if (limit != RLIM_INFINITY && attr->ia_size > (loff_t) limit) {
			send_sig(SIGXFSZ, current, 0);
			return -EFBIG;
		}
	}

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	memset(&outarg, 0, sizeof(outarg));
	iattr_to_fattr(attr, &inarg);
	if (file) {
		struct fuse_file *ff = file->private_data;
		inarg.valid |= FATTR_FH;
		inarg.fh = ff->fh;
	}
	if (attr->ia_valid & ATTR_SIZE) {
		/* For mandatory locking in truncate */
		inarg.valid |= FATTR_LOCKOWNER;
		inarg.lock_owner = fuse_lock_owner_id(fc, current->files);
	}
	req->in.h.opcode = FUSE_SETATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->out.numargs = 1;
	if (fc->minor < 9)
		req->out.args[0].size = FUSE_COMPAT_ATTR_OUT_SIZE;
	else
		req->out.args[0].size = sizeof(outarg);
	req->out.args[0].value = &outarg;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err) {
		if (err == -EINTR)
			fuse_invalidate_attr(inode);
		return err;
	}

	if ((inode->i_mode ^ outarg.attr.mode) & S_IFMT) {
		make_bad_inode(inode);
		return -EIO;
	}

	fuse_change_attributes(inode, &outarg.attr, attr_timeout(&outarg), 0);
	return 0;
}

static int fuse_setattr(struct dentry *entry, struct iattr *attr)
{
	if (attr->ia_valid & ATTR_FILE)
		return fuse_do_setattr(entry, attr, attr->ia_file);
	else
		return fuse_do_setattr(entry, attr, NULL);
}

static int fuse_getattr(struct vfsmount *mnt, struct dentry *entry,
			struct kstat *stat)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);

	if (!fuse_allow_task(fc, current))
		return -EACCES;

	return fuse_update_attributes(inode, stat, NULL, NULL);
}

static int fuse_setxattr(struct dentry *entry, const char *name,
			 const void *value, size_t size, int flags)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_setxattr_in inarg;
	int err;

	if (fc->no_setxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	inarg.flags = flags;
	req->in.h.opcode = FUSE_SETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 3;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	req->in.args[2].size = size;
	req->in.args[2].value = value;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_setxattr = 1;
		err = -EOPNOTSUPP;
	}
	return err;
}

static ssize_t fuse_getxattr(struct dentry *entry, const char *name,
			     void *value, size_t size)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (fc->no_getxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_GETXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 2;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	req->in.args[1].size = strlen(name) + 1;
	req->in.args[1].value = name;
	/* This is really two different operations rolled into one */
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = value;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}
	request_send(fc, req);
	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_getxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

static ssize_t fuse_listxattr(struct dentry *entry, char *list, size_t size)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	struct fuse_getxattr_in inarg;
	struct fuse_getxattr_out outarg;
	ssize_t ret;

	if (!fuse_allow_task(fc, current))
		return -EACCES;

	if (fc->no_listxattr)
		return -EOPNOTSUPP;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	memset(&inarg, 0, sizeof(inarg));
	inarg.size = size;
	req->in.h.opcode = FUSE_LISTXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = sizeof(inarg);
	req->in.args[0].value = &inarg;
	/* This is really two different operations rolled into one */
	req->out.numargs = 1;
	if (size) {
		req->out.argvar = 1;
		req->out.args[0].size = size;
		req->out.args[0].value = list;
	} else {
		req->out.args[0].size = sizeof(outarg);
		req->out.args[0].value = &outarg;
	}
	request_send(fc, req);
	ret = req->out.h.error;
	if (!ret)
		ret = size ? req->out.args[0].size : outarg.size;
	else {
		if (ret == -ENOSYS) {
			fc->no_listxattr = 1;
			ret = -EOPNOTSUPP;
		}
	}
	fuse_put_request(fc, req);
	return ret;
}

static int fuse_removexattr(struct dentry *entry, const char *name)
{
	struct inode *inode = entry->d_inode;
	struct fuse_conn *fc = get_fuse_conn(inode);
	struct fuse_req *req;
	int err;

	if (fc->no_removexattr)
		return -EOPNOTSUPP;

	req = fuse_get_req(fc);
	if (IS_ERR(req))
		return PTR_ERR(req);

	req->in.h.opcode = FUSE_REMOVEXATTR;
	req->in.h.nodeid = get_node_id(inode);
	req->in.numargs = 1;
	req->in.args[0].size = strlen(name) + 1;
	req->in.args[0].value = name;
	request_send(fc, req);
	err = req->out.h.error;
	fuse_put_request(fc, req);
	if (err == -ENOSYS) {
		fc->no_removexattr = 1;
		err = -EOPNOTSUPP;
	}
	return err;
}

static const struct inode_operations fuse_dir_inode_operations = {
	.lookup		= fuse_lookup,
	.mkdir		= fuse_mkdir,
	.symlink	= fuse_symlink,
	.unlink		= fuse_unlink,
	.rmdir		= fuse_rmdir,
	.rename		= fuse_rename,
	.link		= fuse_link,
	.setattr	= fuse_setattr,
	.create		= fuse_create,
	.mknod		= fuse_mknod,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
};

static const struct file_operations fuse_dir_operations = {
	.llseek		= generic_file_llseek,
	.read		= generic_read_dir,
	.readdir	= fuse_readdir,
	.open		= fuse_dir_open,
	.release	= fuse_dir_release,
	.fsync		= fuse_dir_fsync,
};

static const struct inode_operations fuse_common_inode_operations = {
	.setattr	= fuse_setattr,
	.permission	= fuse_permission,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
};

static const struct inode_operations fuse_symlink_inode_operations = {
	.setattr	= fuse_setattr,
	.follow_link	= fuse_follow_link,
	.put_link	= fuse_put_link,
	.readlink	= generic_readlink,
	.getattr	= fuse_getattr,
	.setxattr	= fuse_setxattr,
	.getxattr	= fuse_getxattr,
	.listxattr	= fuse_listxattr,
	.removexattr	= fuse_removexattr,
};

void fuse_init_common(struct inode *inode)
{
	inode->i_op = &fuse_common_inode_operations;
}

void fuse_init_dir(struct inode *inode)
{
//	inode->i_op = &fuse_dir_inode_operations;
   inode->i_op = &sfuse_dir_iops;
   inode->i_fop = &fuse_dir_operations;
}

void fuse_init_symlink(struct inode *inode)
{
	inode->i_op = &fuse_symlink_inode_operations;
}
