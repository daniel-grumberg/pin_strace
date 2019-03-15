/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sys/syscall.h>

#include <fcntl.h>
#include <sys/mman.h>

namespace {
struct SysEntry {
  size_t NumArgs;
  const char *Name;
};
} // namespace

static const SysEntry SysEntries[] = {
#include "syscall_list.inc"
};

static FILE *Output = NULL;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "",
                            "specify file name for MyPinTool output");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
static INT32 usage() {
  std::cerr << "This tool implements strace via DBI with Intel Pin"
            << std::endl;

  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

  return -1;
}

static bool isPrintable(char C) { return ((C >= ' ') && (C <= '~')); }

static void printProtection(long Flags, FILE *Output) {
  if (!Flags)
    fputs("PROT_NONE", Output);
  else {
    bool FirstFlag = true;

    if (Flags & PROT_EXEC) {
      fputs("PROT_EXEC", Output);
      FirstFlag = false;
    }

    if (Flags & PROT_READ) {
      if (!FirstFlag)
        fputc('|', Output);
      else
        FirstFlag = false;
      fputs("PROT_READ", Output);
    }

    if (Flags & PROT_WRITE) {
      if (!FirstFlag)
        fputc('|', Output);
      else
        FirstFlag = false;
      fputs("PROT_WRITE", Output);
    }
  }
}

static void printMmapFlags(long Flags, FILE *Output) {
  if (Flags & MAP_SHARED)
    fputs("MAP_SHARED", Output);
  else
    fputs("MAP_PRIVATE", Output);

  if (Flags & MAP_32BIT)
    fputs("|MAP_32BIT", Output);

  if (Flags & MAP_ANONYMOUS)
    fputs("|MAP_ANONYMOUS", Output);

  if (Flags & MAP_DENYWRITE)
    fputs("|MAP_DENYWRITE", Output);

  if (Flags & MAP_EXECUTABLE)
    fputs("|MAP_EXECUTABLE", Output);

  if (Flags & MAP_FILE)
    fputs("|MAP_FILE", Output);

  if (Flags & MAP_FIXED)
    fputs("|MAP_FIXED", Output);

  if (Flags & MAP_GROWSDOWN)
    fputs("|MAP_GROWSDOWN", Output);

  if (Flags & MAP_HUGETLB)
    fputs("|MAP_HUGETLB", Output);

  if (Flags & MAP_LOCKED)
    fputs("|MAP_LOCKED", Output);

  if (Flags & MAP_NONBLOCK)
    fputs("|MAP_NONBLOCK", Output);

  if (Flags & MAP_NORESERVE)
    fputs("|MAP_NORESERVE", Output);

  if (Flags & MAP_POPULATE)
    fputs("|MAP_POPULATE", Output);

  if (Flags & MAP_STACK)
    fputs("|MAP_STACK", Output);

  // if (Flags & MAP_UNINITIALIZED)
  //    fputs("|MAP_UNINITIALIZED", Output);
}

static bool printOpenFlags(long Flags, FILE *Output) {
  bool Result = false;

  if (Flags & O_RDWR)
    fputs("O_RDWR", Output);

  else if (Flags & O_WRONLY)
    fputs("O_WRONLY", Output);

  else
    fputs("O_RDONLY", Output);

  // Creation and file status Flags
  if (Flags & O_APPEND)
    fputs("|O_APPEND", Output);

  if (Flags & O_ASYNC)
    fputs("|O_ASYNC", Output);

  if (Flags & O_CLOEXEC)
    fputs("|O_CLOEXEC", Output);

  if (Flags & O_CREAT) {
    fputs("|O_CREAT", Output);
    Result = true;
  }

  if (Flags & O_DIRECT)
    fputs("|O_DIRECT", Output);

  if (Flags & O_DIRECTORY)
    fputs("|O_DIRECTORY", Output);

  if (Flags & O_DSYNC)
    fputs("|O_DSYNC", Output);

  if (Flags & O_EXCL)
    fputs("|O_EXCL", Output);

  if (Flags & O_NOATIME)
    fputs("|O_NOATIME", Output);

  if (Flags & O_NOCTTY)
    fputs("|O_NOCTTY", Output);

  if (Flags & O_NOFOLLOW)
    fputs("|O_NOFOLLOW", Output);

  if (Flags & O_NONBLOCK)
    fputs("|O_NONBLOCK", Output);

  if (Flags & O_PATH)
    fputs("|O_PATH", Output);

  if (Flags & O_SYNC)
    fputs("|O_SYNC", Output);

  if (Flags & O_TMPFILE) {
    fputs("|O_TMPFILE", Output);
    Result = true;
  }

  if (Flags & O_TRUNC)
    fputs("|O_TRUNC", Output);

  return Result;
}

void printNonPrintable(char C, FILE *Output) {
  switch (C) {
  case '\n':
    fputs("\\n", Output);
    break;
  case '\t':
    fputs("\\t", Output);
    break;
  default:
    fprintf(Output, "\\x%02X", C);
    break;
  }
}

void printString(const char *String, ADDRINT Length, FILE *Output) {
  fputc('\"', Output);
  for (size_t Ind = 0; (Length ? (Ind < Length) : true) && String[Ind]; Ind++) {
    if (isPrintable(String[Ind]))
      fputc(String[Ind], Output);
    else
      printNonPrintable(String[Ind], Output);
  }
  fputc('\"', Output);
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

static VOID SysBefore(FILE *Output, ADDRINT Ip, ADDRINT Nr, const long Args[]) {
  fprintf(Output, "%s(", SysEntries[Nr].Name);
  // Special case for exit system calls... Can we intercept after this?
  if ((Nr == __NR_exit) || (Nr == __NR_exit_group)) {
    fprintf(Output, "%ld) = ?\n", Args[0]);
    fflush(Output);
  }

  switch (Nr) {
  case __NR_mprotect:
    fprintf(Output, "0x%lX, 0x%lX, ", Args[0], Args[1]);
    printProtection(Args[2], Output);
    break;

  case __NR_access:
    printString(reinterpret_cast<const char *>(Args[0]), 0, Output);
    fprintf(Output, ", %lX", Args[1]);
    break;

  case __NR_mmap:
    for (size_t Argno = 0; Argno < SysEntries[Nr].NumArgs; ++Argno) {
      if (!Argno)
        fprintf(Output, "0x%lX", Args[Argno]);

      else if (Argno == 2) {
        fputs(", ", Output);
        printProtection(Args[2], Output);
      } else if (Argno == 3) {
        fputs(", ", Output);
        printMmapFlags(Args[3], Output);
      } else
        fprintf(Output, ", 0x%lX", Args[Argno]);
    }
    break;

  case __NR_open:
    printString(reinterpret_cast<const char *>(Args[0]), 0, Output);
    fputs(", ", Output);
    if (printOpenFlags(Args[1], Output)) {
      fprintf(Output, ", %lo", Args[2]);
    }
    break;

  case __NR_write:
    for (size_t Argno = 0; Argno < SysEntries[Nr].NumArgs; ++Argno) {
      if (!Argno)
        fprintf(Output, "0x%lX", Args[Argno]);

      else if (Argno == 1) {
        fputs(", ", Output);
        printString(reinterpret_cast<const char *>(Args[Argno]),
                    Args[Argno + 1], Output);
      } else
        fprintf(Output, ", 0x%lX", Args[Argno]);
    }
    break;

  case __NR_read:
    fprintf(Output, "0x%lx", Args[0]);
    break;

  default:
    for (size_t Argno = 0; Argno < SysEntries[Nr].NumArgs; ++Argno) {
      if (!Argno)
        fprintf(Output, "0x%lX", Args[Argno]);
      else
        fprintf(Output, ", 0x%lX", Args[Argno]);
    }
    break;
  }
  fflush(Output);
}

static VOID SysAfter(FILE *Output, long Ret) {
  if (Ret > -1)
    fprintf(Output, ") = 0x%lX\n", Ret);
  else
    fprintf(Output, ") = %ld (error)\n", Ret);
  fflush(Output);
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

static VOID SyscallEntry(THREADID ThreadIndex, CONTEXT *Context,
                         SYSCALL_STANDARD Std, VOID *V) {
  //FILE *Output = reinterpret_cast<FILE *>(V);

  long LocalArgs[] = {(long)PIN_GetSyscallArgument(Context, Std, 0),
                      (long)PIN_GetSyscallArgument(Context, Std, 1),
                      (long)PIN_GetSyscallArgument(Context, Std, 2),
                      (long)PIN_GetSyscallArgument(Context, Std, 3),
                      (long)PIN_GetSyscallArgument(Context, Std, 4),
                      (long)PIN_GetSyscallArgument(Context, Std, 5)};

  SysBefore(Output, PIN_GetContextReg(Context, REG_INST_PTR),
            PIN_GetSyscallNumber(Context, Std), LocalArgs);
}

static VOID SyscallExit(THREADID ThreadIndex, CONTEXT *Context,
                        SYSCALL_STANDARD Std, VOID *V) {
  //FILE *Output = reinterpret_cast<FILE *>(V);

  // Special case reads to get the read strings
  if (PIN_GetSyscallNumber(Context, Std) == __NR_read) {
    fputs(", ", Output);
    const char *ReadString =
        reinterpret_cast<const char *>(PIN_GetSyscallArgument(Context, Std, 1));
    const long Length = PIN_GetSyscallArgument(Context, Std, 2);
    printString(ReadString, Length, Output);
    fprintf(Output, ", 0x%lX", Length);
  }

  SysAfter(Output, (long)PIN_GetSyscallReturn(Context, Std));
}

static VOID Fini(INT32 Code, VOID *V) {
  //FILE *Output = reinterpret_cast<FILE *>(V);
  fflush(Output);
  fclose(Output);
}

/* ===================================================================== */
// Main procedure
/* ===================================================================== */

int main(int argc, char *argv[]) {
  // Initialize PIN library. Print help message if -h(elp) is specified
  // in the command line or the command line is invalid
  if (PIN_Init(argc, argv))
    return usage();

  string FileName = KnobOutputFile.Value();
  if (FileName.empty()) {
    std::cerr << "You have to dump to a file as many applications will close "
                 "stderr"
              << std::endl;
    return -1;
  }
  Output = fopen(FileName.c_str(), "w");

  std::cerr << "===============================================" << std::endl;
  std::cerr << "This application is instrumented by PinStrace" << std::endl;
  std::cerr << "See file " << KnobOutputFile.Value() << " for analysis results"
            << std::endl;
  std::cerr << "===============================================" << std::endl;

  PIN_AddSyscallEntryFunction(SyscallEntry, (VOID *)Output);
  PIN_AddSyscallExitFunction(SyscallExit, (VOID *)Output);
  PIN_AddFiniFunction(Fini, (VOID *)Output);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}

/* ===================================================================== */
/* eof */
/* ===================================================================== */
