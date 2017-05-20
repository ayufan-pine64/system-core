/*
 * Copyright 2016, The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <limits>
#include <thread>

#include <android-base/file.h>
#include <android-base/logging.h>
#include <android-base/parseint.h>
#include <android-base/unique_fd.h>
#include <debuggerd/client.h>
#include <debuggerd/util.h>
#include <selinux/selinux.h>

using android::base::unique_fd;

static void usage(int exit_code) {
  fprintf(stderr, "usage: debuggerd [-b] PID\n");
  fprintf(stderr, "\n");
  fprintf(stderr, "-b, --backtrace    just a backtrace rather than a full tombstone\n");
  _exit(exit_code);
}

static int get_process_info(pid_t tid, pid_t* out_pid, uid_t* out_uid, uid_t* out_gid) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/status", tid);

  FILE* fp = fopen(path, "r");
  if (!fp) {
    return -1;
  }

  int fields = 0;
  char line[1024];
  while (fgets(line, sizeof(line), fp)) {
    size_t len = strlen(line);
    if (len > 6 && !memcmp(line, "Tgid:\t", 6)) {
      *out_pid = atoi(line + 6);
      fields |= 1;
    } else if (len > 5 && !memcmp(line, "Uid:\t", 5)) {
      *out_uid = atoi(line + 5);
      fields |= 2;
    } else if (len > 5 && !memcmp(line, "Gid:\t", 5)) {
      *out_gid = atoi(line + 5);
      fields |= 4;
    }
  }
  fclose(fp);
  return fields == 7 ? 0 : -1;
}

/*
 * Corresponds with debugger_action_t enum type in
 * include/cutils/debugger.h.
 */
static const char *debuggerd_perms[] = {
  NULL, /* crash is only used on self, no check applied */
  "dump_tombstone",
  "dump_backtrace"
};

static int audit_callback(void* data, security_class_t /* cls */, char* buf, size_t len)
{
    struct debugger_request_t* req = reinterpret_cast<debugger_request_t*>(data);

    if (!req) {
        ALOGE("No debuggerd request audit data");
        return 0;
    }

    snprintf(buf, len, "pid=%d uid=%d gid=%d", req->pid, req->uid, req->gid);
    return 0;
}

static bool selinux_action_allowed(int s, debugger_request_t* request)
{
  char *scon = NULL, *tcon = NULL;
  const char *tclass = "debuggerd";
  const char *perm;
  bool allowed = false;

  if (request->action <= 0 || request->action >= (sizeof(debuggerd_perms)/sizeof(debuggerd_perms[0]))) {
    ALOGE("SELinux:  No permission defined for debugger action %d", request->action);
    return false;
  }

  perm = debuggerd_perms[request->action];

  if (getpeercon(s, &scon) < 0) {
    ALOGE("Cannot get peer context from socket\n");
    goto out;
  }

  if (getpidcon(request->tid, &tcon) < 0) {
    ALOGE("Cannot get context for tid %d\n", request->tid);
    goto out;
  }

  allowed = (selinux_check_access(scon, tcon, tclass, perm, reinterpret_cast<void*>(request)) == 0);

out:
   freecon(scon);
   freecon(tcon);
   return allowed;
}

static int read_request(int fd, debugger_request_t* out_request) {
  ucred cr;
  socklen_t len = sizeof(cr);
  int status = getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &cr, &len);
  if (status != 0) {
    ALOGE("cannot get credentials");
    return -1;
  }

  ALOGV("reading tid");
  fcntl(fd, F_SETFL, O_NONBLOCK);

  pollfd pollfds[1];
  pollfds[0].fd = fd;
  pollfds[0].events = POLLIN;
  pollfds[0].revents = 0;
  status = TEMP_FAILURE_RETRY(poll(pollfds, 1, 3000));
  if (status != 1) {
    ALOGE("timed out reading tid (from pid=%d uid=%d)\n", cr.pid, cr.uid);
    return -1;
  }

  debugger_msg_t msg;
  memset(&msg, 0, sizeof(msg));
  status = TEMP_FAILURE_RETRY(read(fd, &msg, sizeof(msg)));
  if (status < 0) {
    ALOGE("read failure? %s (pid=%d uid=%d)\n", strerror(errno), cr.pid, cr.uid);
    return -1;
  }
  if (status != sizeof(debugger_msg_t)) {
    ALOGE("invalid crash request of size %d (from pid=%d uid=%d)\n", status, cr.pid, cr.uid);
    return -1;
  }

  out_request->action = static_cast<debugger_action_t>(msg.action);
  out_request->tid = msg.tid;
  out_request->pid = cr.pid;
  out_request->uid = cr.uid;
  out_request->gid = cr.gid;
  out_request->abort_msg_address = msg.abort_msg_address;
  out_request->original_si_code = msg.original_si_code;

  if (msg.action == DEBUGGER_ACTION_CRASH) {
    // Ensure that the tid reported by the crashing process is valid.
    char buf[64];
    struct stat s;
    snprintf(buf, sizeof buf, "/proc/%d/task/%d", out_request->pid, out_request->tid);
    if (stat(buf, &s)) {
      ALOGE("tid %d does not exist in pid %d. ignoring debug request\n",
          out_request->tid, out_request->pid);
      return -1;
    }
  } else if (cr.uid == 0
            || (cr.uid == AID_SYSTEM && msg.action == DEBUGGER_ACTION_DUMP_BACKTRACE)) {
    // Only root or system can ask us to attach to any process and dump it explicitly.
    // However, system is only allowed to collect backtraces but cannot dump tombstones.
    status = get_process_info(out_request->tid, &out_request->pid,
                              &out_request->uid, &out_request->gid);
    if (status < 0) {
      ALOGE("tid %d does not exist. ignoring explicit dump request\n", out_request->tid);
      return -1;
    }

    if (!selinux_action_allowed(fd, out_request))
      return -1;
  } else {
    // No one else is allowed to dump arbitrary processes.
    return -1;
  }
  return 0;
}

static int activity_manager_connect() {
  android::base::unique_fd amfd(socket(PF_UNIX, SOCK_STREAM, 0));
  if (amfd.get() < -1) {
    ALOGE("debuggerd: Unable to connect to activity manager (socket failed: %s)", strerror(errno));
    return -1;
  }

  struct sockaddr_un address;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  // The path used here must match the value defined in NativeCrashListener.java.
  strncpy(address.sun_path, "/data/system/ndebugsocket", sizeof(address.sun_path));
  if (TEMP_FAILURE_RETRY(connect(amfd.get(), reinterpret_cast<struct sockaddr*>(&address),
                                 sizeof(address))) == -1) {
    ALOGE("debuggerd: Unable to connect to activity manager (connect failed: %s)", strerror(errno));
    return -1;
  }

  struct timeval tv;
  memset(&tv, 0, sizeof(tv));
  tv.tv_sec = 1;  // tight leash
  if (setsockopt(amfd.get(), SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) == -1) {
    ALOGE("debuggerd: Unable to connect to activity manager (setsockopt SO_SNDTIMEO failed: %s)",
          strerror(errno));
    return -1;
  }

  tv.tv_sec = 3;  // 3 seconds on handshake read
  if (setsockopt(amfd.get(), SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == -1) {
    ALOGE("debuggerd: Unable to connect to activity manager (setsockopt SO_RCVTIMEO failed: %s)",
          strerror(errno));
    return -1;
  }

  return amfd.release();
}

static void activity_manager_write(int pid, int signal, int amfd, const std::string& amfd_data) {
  if (amfd == -1) {
    return;
  }

  // Activity Manager protocol: binary 32-bit network-byte-order ints for the
  // pid and signal number, followed by the raw text of the dump, culminating
  // in a zero byte that marks end-of-data.
  uint32_t datum = htonl(pid);
  if (!android::base::WriteFully(amfd, &datum, 4)) {
    ALOGE("AM pid write failed: %s\n", strerror(errno));
    return;
  }
  datum = htonl(signal);
  if (!android::base::WriteFully(amfd, &datum, 4)) {
    ALOGE("AM signal write failed: %s\n", strerror(errno));
    return;
  }

  if (!android::base::WriteFully(amfd, amfd_data.c_str(), amfd_data.size())) {
    ALOGE("AM data write failed: %s\n", strerror(errno));
    return;
  }

  // Send EOD to the Activity Manager, then wait for its ack to avoid racing
  // ahead and killing the target out from under it.
  uint8_t eodMarker = 0;
  if (!android::base::WriteFully(amfd, &eodMarker, 1)) {
    ALOGE("AM eod write failed: %s\n", strerror(errno));
    return;
  }
  // 3 sec timeout reading the ack; we're fine if the read fails.
  android::base::ReadFully(amfd, &eodMarker, 1);
}

static bool should_attach_gdb(const debugger_request_t& request) {
  if (request.action == DEBUGGER_ACTION_CRASH) {
    return property_get_bool("debug.debuggerd.wait_for_gdb", false);
  }
  return false;
}

#if defined(__LP64__)
static bool is32bit(pid_t tid) {
  char* exeline;
  if (asprintf(&exeline, "/proc/%d/exe", tid) == -1) {
    return false;
  }
  int fd = TEMP_FAILURE_RETRY(open(exeline, O_RDONLY | O_CLOEXEC));
  int saved_errno = errno;
  free(exeline);
  if (fd == -1) {
    ALOGW("Failed to open /proc/%d/exe %s", tid, strerror(saved_errno));
    return false;
  }

  char ehdr[EI_NIDENT];
  ssize_t bytes = TEMP_FAILURE_RETRY(read(fd, &ehdr, sizeof(ehdr)));
  close(fd);
  if (bytes != (ssize_t) sizeof(ehdr) || memcmp(ELFMAG, ehdr, SELFMAG) != 0) {
    return false;
  }
  if (ehdr[EI_CLASS] == ELFCLASS32) {
    return true;
  }
  return false;
}

static void redirect_to_32(int fd, debugger_request_t* request) {
  debugger_msg_t msg;
  memset(&msg, 0, sizeof(msg));
  msg.tid = request->tid;
  msg.action = request->action;

  int sock_fd = socket_local_client(DEBUGGER32_SOCKET_NAME, ANDROID_SOCKET_NAMESPACE_ABSTRACT,
                                    SOCK_STREAM | SOCK_CLOEXEC);
  if (sock_fd < 0) {
    ALOGE("Failed to connect to debuggerd32: %s", strerror(errno));
    return;
  }

  if (TEMP_FAILURE_RETRY(write(sock_fd, &msg, sizeof(msg))) != (ssize_t) sizeof(msg)) {
    ALOGE("Failed to write request to debuggerd32 socket: %s", strerror(errno));
    close(sock_fd);
    return;
  }

  char ack;
  if (TEMP_FAILURE_RETRY(read(sock_fd, &ack, 1)) == -1) {
    ALOGE("Failed to read ack from debuggerd32 socket: %s", strerror(errno));
    close(sock_fd);
    return;
  }

  char buffer[1024];
  ssize_t bytes_read;
  while ((bytes_read = TEMP_FAILURE_RETRY(read(sock_fd, buffer, sizeof(buffer)))) > 0) {
    ssize_t bytes_to_send = bytes_read;
    ssize_t bytes_written;
    do {
      bytes_written = TEMP_FAILURE_RETRY(write(fd, buffer + bytes_read - bytes_to_send,
                                               bytes_to_send));
      if (bytes_written == -1) {
        if (errno == EAGAIN) {
          // Retry the write.
          continue;
        }
        ALOGE("Error while writing data to fd: %s", strerror(errno));
        break;
      }

static void ptrace_siblings(pid_t pid, pid_t main_tid, std::set<pid_t>& tids) {
  char task_path[64];

  snprintf(task_path, sizeof(task_path), "/proc/%d/task", pid);

  std::unique_ptr<DIR, int (*)(DIR*)> d(opendir(task_path), closedir);

  // Bail early if the task directory cannot be opened.
  if (!d) {
    ALOGE("debuggerd: failed to open /proc/%d/task: %s", pid, strerror(errno));
    return;
  }

  struct dirent* de;
  while ((de = readdir(d.get())) != NULL) {
    // Ignore "." and "..".
    if (!strcmp(de->d_name, ".") || !strcmp(de->d_name, "..")) {
      continue;
    }

    char* end;
    pid_t tid = strtoul(de->d_name, &end, 10);
    if (*end) {
      continue;
    }

    if (tid == main_tid) {
      continue;
    }

    if (ptrace(PTRACE_ATTACH, tid, 0, 0) < 0) {
      ALOGE("debuggerd: ptrace attach to %d failed: %s", tid, strerror(errno));
      continue;
    }

    tids.insert(tid);
  }
}

static bool perform_dump(const debugger_request_t& request, int fd, int tombstone_fd,
                         BacktraceMap* backtrace_map, const std::set<pid_t>& siblings,
                         int* crash_signal, std::string* amfd_data) {
  if (TEMP_FAILURE_RETRY(write(fd, "\0", 1)) != 1) {
    ALOGE("debuggerd: failed to respond to client: %s\n", strerror(errno));
    return false;
  }

  int total_sleep_time_usec = 0;
  while (true) {
    int signal = wait_for_signal(request.tid, &total_sleep_time_usec);
    switch (signal) {
      case -1:
        ALOGE("debuggerd: timed out waiting for signal");
        return false;

      case SIGSTOP:
        if (request.action == DEBUGGER_ACTION_DUMP_TOMBSTONE) {
          ALOGV("debuggerd: stopped -- dumping to tombstone");
          engrave_tombstone(tombstone_fd, backtrace_map, request.pid, request.tid, siblings, signal,
                            request.original_si_code, request.abort_msg_address, amfd_data);
        } else if (request.action == DEBUGGER_ACTION_DUMP_BACKTRACE) {
          ALOGV("debuggerd: stopped -- dumping to fd");
          dump_backtrace(fd, backtrace_map, request.pid, request.tid, siblings, nullptr);
        } else {
          ALOGV("debuggerd: stopped -- continuing");
          if (ptrace(PTRACE_CONT, request.tid, 0, 0) != 0) {
            ALOGE("debuggerd: ptrace continue failed: %s", strerror(errno));
            return false;
          }
          continue;  // loop again
        }
        break;

      case SIGABRT:
      case SIGBUS:
      case SIGFPE:
      case SIGILL:
      case SIGSEGV:
#ifdef SIGSTKFLT
      case SIGSTKFLT:
#endif
      case SIGSYS:
      case SIGTRAP:
        ALOGV("stopped -- fatal signal\n");
        *crash_signal = signal;
        engrave_tombstone(tombstone_fd, backtrace_map, request.pid, request.tid, siblings, signal,
                          request.original_si_code, request.abort_msg_address, amfd_data);
        break;

      default:
        ALOGE("debuggerd: process stopped due to unexpected signal %d\n", signal);
        break;
    }
    break;
  }

  return true;
}

static bool drop_privileges() {
  // AID_LOG: for reading the logs data associated with the crashing process.
  // AID_READPROC: for reading /proc/<PID>/{comm,cmdline}.
  gid_t groups[] = { AID_DEBUGGERD, AID_LOG, AID_READPROC };
  if (setgroups(sizeof(groups)/sizeof(groups[0]), groups) != 0) {
    ALOGE("debuggerd: failed to setgroups: %s", strerror(errno));
    return false;
  }

  if (setresgid(AID_DEBUGGERD, AID_DEBUGGERD, AID_DEBUGGERD) != 0) {
    ALOGE("debuggerd: failed to setresgid: %s", strerror(errno));
    return false;
  }

  if (setresuid(AID_DEBUGGERD, AID_DEBUGGERD, AID_DEBUGGERD) != 0) {
    ALOGE("debuggerd: failed to setresuid: %s", strerror(errno));
    return false;
  }

  return true;
}

static void worker_process(int fd, debugger_request_t& request) {
  // Open the tombstone file if we need it.
  std::string tombstone_path;
  int tombstone_fd = -1;
  switch (request.action) {
    case DEBUGGER_ACTION_DUMP_TOMBSTONE:
    case DEBUGGER_ACTION_CRASH:
      tombstone_fd = open_tombstone(&tombstone_path);
      if (tombstone_fd == -1) {
        ALOGE("debuggerd: failed to open tombstone file: %s\n", strerror(errno));
        exit(1);
      }
      break;

    case DEBUGGER_ACTION_DUMP_BACKTRACE:
      break;

    default:
      ALOGE("debuggerd: unexpected request action: %d", request.action);
      exit(1);
  }

  // At this point, the thread that made the request is blocked in
  // a read() call.  If the thread has crashed, then this gives us
  // time to PTRACE_ATTACH to it before it has a chance to really fault.
  //
  // The PTRACE_ATTACH sends a SIGSTOP to the target process, but it
  // won't necessarily have stopped by the time ptrace() returns.  (We
  // currently assume it does.)  We write to the file descriptor to
  // ensure that it can run as soon as we call PTRACE_CONT below.
  // See details in bionic/libc/linker/debugger.c, in function
  // debugger_signal_handler().

  // Attach to the target process.
  if (ptrace(PTRACE_ATTACH, request.tid, 0, 0) != 0) {
    ALOGE("debuggerd: ptrace attach failed: %s", strerror(errno));
    exit(1);
  }

  // Don't attach to the sibling threads if we want to attach gdb.
  // Supposedly, it makes the process less reliable.
  bool attach_gdb = should_attach_gdb(request);
  if (attach_gdb) {
    // Open all of the input devices we need to listen for VOLUMEDOWN before dropping privileges.
    if (init_getevent() != 0) {
      ALOGE("debuggerd: failed to initialize input device, not waiting for gdb");
      attach_gdb = false;
    }
  });
}

int main(int argc, char* argv[]) {
  if (argc <= 1) usage(0);
  if (argc > 3) usage(1);
  if (argc == 3 && strcmp(argv[1], "-b") != 0 && strcmp(argv[1], "--backtrace") != 0) usage(1);
  bool backtrace_only = argc == 3;

  pid_t pid;
  if (!android::base::ParseInt(argv[argc - 1], &pid, 1, std::numeric_limits<pid_t>::max())) {
    usage(1);
  }

  unique_fd piperead, pipewrite;
  if (!Pipe(&piperead, &pipewrite)) {
    err(1, "failed to create pipe");
  }

  std::thread redirect_thread = spawn_redirect_thread(std::move(piperead));
  if (!debuggerd_trigger_dump(pid, std::move(pipewrite),
                              backtrace_only ? kDebuggerdBacktrace : kDebuggerdTombstone, 0)) {
    redirect_thread.join();
    errx(1, "failed to dump process %d", pid);
  }

  redirect_thread.join();
  return 0;
}
