/*
 * The proc filesystem constants/structures
 */
#ifndef _LINUX_PROC_FS_H
#define _LINUX_PROC_FS_H

#include <linux/types.h>
#include <linux/fs.h>
#include <linux/refcount.h>
#include <linux/pid_namespace.h>

struct proc_dir_entry;
struct pid_namespace;

enum { /* definitions for proc mount option limit_pids */
	PROC_LIMIT_PIDS_OFF	= 0,	/* Limit pids is off */
	PROC_LIMIT_PIDS_PTRACE	= 1,	/* Limit pids to only ptracable pids */
};

struct proc_fs_info {
	struct pid_namespace *pid_ns;
	struct dentry *proc_self; /* For /proc/self */
	struct dentry *proc_thread_self; /* For /proc/thread-self/ */
	bool newinstance; /* Private flag for new separated instances */
	int limit_pids:1;
};

#ifdef CONFIG_PROC_FS

static inline struct proc_fs_info *proc_sb(struct super_block *sb)
{
	return sb->s_fs_info;
}

static inline void proc_fs_set_hide_pid(struct proc_fs_info *fs_info, int hide_pid)
{
	fs_info->pid_ns->hide_pid = hide_pid;
}

static inline void proc_fs_set_pid_gid(struct proc_fs_info *fs_info, kgid_t gid)
{
	fs_info->pid_ns->pid_gid = gid;
}

static inline void proc_fs_set_newinstance(struct proc_fs_info *fs_info, bool value)
{
	fs_info->newinstance = value;
}

static inline int proc_fs_set_limit_pids(struct proc_fs_info *fs_info, int value)
{
	if (value < PROC_LIMIT_PIDS_OFF || value > PROC_LIMIT_PIDS_PTRACE)
		return -EINVAL;

	fs_info->limit_pids = value;

	return 0;
}

static inline int proc_fs_hide_pid(struct proc_fs_info *fs_info)
{
	return fs_info->pid_ns->hide_pid;
}

static inline kgid_t proc_fs_pid_gid(struct proc_fs_info *fs_info)
{
	return fs_info->pid_ns->pid_gid;
}

static inline bool proc_fs_newinstance(struct proc_fs_info *fs_info)
{
	return fs_info->newinstance;
}

static inline int proc_fs_limit_pids(struct proc_fs_info *fs_info)
{
	return fs_info->limit_pids;
}

extern void proc_root_init(void);
extern void proc_flush_task(struct task_struct *);

extern struct proc_dir_entry *proc_symlink(const char *,
		struct proc_dir_entry *, const char *);
extern struct proc_dir_entry *proc_mkdir(const char *, struct proc_dir_entry *);
extern struct proc_dir_entry *proc_mkdir_data(const char *, umode_t,
					      struct proc_dir_entry *, void *);
extern struct proc_dir_entry *proc_mkdir_mode(const char *, umode_t,
					      struct proc_dir_entry *);
struct proc_dir_entry *proc_create_mount_point(const char *name);
 
extern struct proc_dir_entry *proc_create_data(const char *, umode_t,
					       struct proc_dir_entry *,
					       const struct file_operations *,
					       void *);

static inline struct proc_dir_entry *proc_create(
	const char *name, umode_t mode, struct proc_dir_entry *parent,
	const struct file_operations *proc_fops)
{
	return proc_create_data(name, mode, parent, proc_fops, NULL);
}

extern void proc_set_size(struct proc_dir_entry *, loff_t);
extern void proc_set_user(struct proc_dir_entry *, kuid_t, kgid_t);
extern void *PDE_DATA(const struct inode *);
extern void *proc_get_parent_data(const struct inode *);
extern void proc_remove(struct proc_dir_entry *);
extern void remove_proc_entry(const char *, struct proc_dir_entry *);
extern int remove_proc_subtree(const char *, struct proc_dir_entry *);

#else /* CONFIG_PROC_FS */

static inline void proc_root_init(void)
{
}

static inline void proc_flush_task(struct task_struct *task)
{
}

static inline void proc_fs_set_hide_pid(struct proc_fs_info *fs_info, int hide_pid)
{
}

static inline void proc_fs_set_pid_gid(struct proc_info_fs *fs_info, kgid_t gid)
{
}

static inline void proc_fs_set_newinstance(struct proc_fs_info *fs_info, bool value)
{
}

static inline int proc_fs_set_limit_pids(struct proc_fs_info *fs_info, int value)
{
	return 0;
}

static inline int proc_fs_hide_pid(struct proc_fs_info *fs_info)
{
	return 0;
}

extern kgid_t proc_fs_pid_gid(struct proc_fs_info *fs_info)
{
	return GLOBAL_ROOT_GID;
}

static inline bool proc_fs_newinstance(struct proc_fs_info *fs_info)
{
	return false;
}

static inline int proc_fs_limit_pids(struct proc_fs_info *fs_info)
{
	return 0;
}

extern inline struct proc_fs_info *proc_sb(struct super_block *sb) { return NULL;}
static inline struct proc_dir_entry *proc_symlink(const char *name,
		struct proc_dir_entry *parent,const char *dest) { return NULL;}
static inline struct proc_dir_entry *proc_mkdir(const char *name,
	struct proc_dir_entry *parent) {return NULL;}
static inline struct proc_dir_entry *proc_create_mount_point(const char *name) { return NULL; }
static inline struct proc_dir_entry *proc_mkdir_data(const char *name,
	umode_t mode, struct proc_dir_entry *parent, void *data) { return NULL; }
static inline struct proc_dir_entry *proc_mkdir_mode(const char *name,
	umode_t mode, struct proc_dir_entry *parent) { return NULL; }
#define proc_create(name, mode, parent, proc_fops) ({NULL;})
#define proc_create_data(name, mode, parent, proc_fops, data) ({NULL;})

static inline void proc_set_size(struct proc_dir_entry *de, loff_t size) {}
static inline void proc_set_user(struct proc_dir_entry *de, kuid_t uid, kgid_t gid) {}
static inline void *PDE_DATA(const struct inode *inode) {BUG(); return NULL;}
static inline void *proc_get_parent_data(const struct inode *inode) { BUG(); return NULL; }

static inline void proc_remove(struct proc_dir_entry *de) {}
#define remove_proc_entry(name, parent) do {} while (0)
static inline int remove_proc_subtree(const char *name, struct proc_dir_entry *parent) { return 0; }

#endif /* CONFIG_PROC_FS */

struct net;

static inline struct proc_dir_entry *proc_net_mkdir(
	struct net *net, const char *name, struct proc_dir_entry *parent)
{
	return proc_mkdir_data(name, 0, parent, net);
}

struct ns_common;
int open_related_ns(struct ns_common *ns,
		   struct ns_common *(*get_ns)(struct ns_common *ns));

#endif /* _LINUX_PROC_FS_H */
