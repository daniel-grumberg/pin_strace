/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <fstream>
#include <iostream>
#include <sys/syscall.h>

#include <fcntl.h>
#include <sys/mman.h>

namespace {
struct OStreamWrapper {
public:
  OStreamWrapper() : _Out(&std::clog), _IsFileStream(false) {}
  OStreamWrapper(std::string &FileName) : _IsFileStream(true) {
    _Out = new std::ofstream(FileName.c_str());
  }

  // Shallow is fine as we only delete in Fini
  OStreamWrapper(const OStreamWrapper &Other) = default;
  OStreamWrapper &operator=(const OStreamWrapper &Other) = default;

  ~OStreamWrapper() {
    *_Out << "\n";
    _Out->flush();
    if (_IsFileStream) {
      std::ofstream *FileOut = static_cast<std::ofstream *>(_Out);
      FileOut->close();
      delete FileOut;
    }
  }
  std::ostream &getStream() { return *_Out; }

private:
  std::ostream *_Out;
  bool _IsFileStream;
};
} // namespace

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
  cerr << "This tool implements strace via DBI with Intel Pin" << endl;

  cerr << KNOB_BASE::StringKnobSummary() << endl;

  return -1;
}

static bool isPrintable(char Ch) { return ((Ch >= ' ') && (Ch <= '~')); }

static void printProtection(long Flags, std::ostream &Output) {
  if (!Flags)
    Output << "PROT_NONE";
  else {
    bool FirstFlag = true;

    if (Flags & PROT_EXEC) {
      Output << "PROT_EXEC";
      FirstFlag = false;
    }

    if (Flags & PROT_READ) {
      if (!FirstFlag)
        Output << "|";
      else
        FirstFlag = false;
      Output << "PROT_READ";
    }

    if (Flags & PROT_WRITE) {
      if (!FirstFlag)
        Output << "|";
      else
        FirstFlag = false;
      Output << "PROT_WRITE";
    }
  }
}


static void printMmapFlags(long Flags, std::ostream &Output) {
  if (Flags & MAP_SHARED)
    Output << "MAP_SHARED";
  else
    Output << "MAP_PRIVATE";

  if (Flags & MAP_32BIT)
    Output << "|MAP_32BIT";

  if (Flags & MAP_ANONYMOUS)
    Output << "|MAP_ANONYMOUS";

  if (Flags & MAP_DENYWRITE)
    Output << "|MAP_DENYWRITE";

  if (Flags & MAP_EXECUTABLE)
    Output << "|MAP_EXECUTABLE";

  if (Flags & MAP_FILE)
    Output << "|MAP_FILE";

  if (Flags & MAP_FIXED)
    Output << "|MAP_FIXED";

  if (Flags & MAP_GROWSDOWN)
    Output << "|MAP_GROWSDOWN";

  if (Flags & MAP_HUGETLB)
    Output << "|MAP_HUGETLB";

  if (Flags & MAP_LOCKED)
    Output << "|MAP_LOCKED";

  if (Flags & MAP_NONBLOCK)
    Output << "|MAP_NONBLOCK";

  if (Flags & MAP_NORESERVE)
    Output << "|MAP_NORESERVE";

  if (Flags & MAP_POPULATE)
    Output << "|MAP_POPULATE";

  if (Flags & MAP_STACK)
    Output << "|MAP_STACK";

  // if (Flags & MAP_UNINITIALIZED)
  //    Output << "|MAP_UNINITIALIZED";
}

static bool printOpenFlags(long Flags, std::ostream &Output) {
  bool Result = false;

  if (Flags & O_RDWR)
    Output << "O_RDWR";

  else if (Flags & O_WRONLY)
    Output << "O_WRONLY";

  else
    Output << "O_RDONLY";

  // Creation and file status Flags
  if (Flags & O_APPEND)
    Output << "|O_APPEND";

  if (Flags & O_ASYNC)
    Output << "|O_ASYNC";

  if (Flags & O_CLOEXEC)
    Output << "|O_CLOEXEC";

  if (Flags & O_CREAT) {
    Output << "|O_CREAT";
    Result = true;
  }

  if (Flags & O_DIRECT)
    Output << "|O_DIRECT";

  if (Flags & O_DIRECTORY)
    Output << "|O_DIRECTORY";

  if (Flags & O_DSYNC)
    Output << "|O_DSYNC";

  if (Flags & O_EXCL)
    Output << "|O_EXCL";

  if (Flags & O_NOATIME)
    Output << "|O_NOATIME";

  if (Flags & O_NOCTTY)
    Output << "|O_NOCTTY";

  if (Flags & O_NOFOLLOW)
    Output << "|O_NOFOLLOW";

  if (Flags & O_NONBLOCK)
    Output << "|O_NONBLOCK";

  if (Flags & O_PATH)
    Output << "|O_PATH";

  if (Flags & O_SYNC)
    Output << "|O_SYNC";

  if (Flags & O_TMPFILE) {
    Output << "|O_TMPFILE";
    Result = true;
  }

  if (Flags & O_TRUNC)
    Output << "|O_TRUNC";

  return Result;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

static VOID SysBefore(std::ostream &Output, ADDRINT Ip, ADDRINT Nr,
                      ADDRINT Arg1, ADDRINT Arg2, ADDRINT Arg3, ADDRINT Arg4,
                      ADDRINT Arg5, ADDRINT Arg6) {
  Output << "In ";
}

static VOID SysAfter(std::ostream &Output, ADDRINT Ret) {
  Output << "and out.\n";
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

static VOID SyscallEntry(THREADID ThreadIndex, CONTEXT *Context,
                         SYSCALL_STANDARD Std, VOID *V) {
  OStreamWrapper *Output = static_cast<OStreamWrapper *>(V);
  SysBefore(Output->getStream(), PIN_GetContextReg(Context, REG_INST_PTR),
            PIN_GetSyscallNumber(Context, Std),
            PIN_GetSyscallArgument(Context, Std, 0),
            PIN_GetSyscallArgument(Context, Std, 1),
            PIN_GetSyscallArgument(Context, Std, 2),
            PIN_GetSyscallArgument(Context, Std, 3),
            PIN_GetSyscallArgument(Context, Std, 4),
            PIN_GetSyscallArgument(Context, Std, 5));
}

static VOID SyscallExit(THREADID ThreadIndex, CONTEXT *Context,
                        SYSCALL_STANDARD Std, VOID *V) {
  OStreamWrapper *Output = static_cast<OStreamWrapper *>(V);
  SysAfter(Output->getStream(), PIN_GetSyscallReturn(Context, Std));
}

static VOID Fini(INT32 Code, VOID *V) {
  OStreamWrapper *Output = static_cast<OStreamWrapper *>(V);
  delete Output;
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

  OStreamWrapper *Output =
      FileName.empty() ? new OStreamWrapper() : new OStreamWrapper(FileName);

  cerr << "===============================================" << endl;
  cerr << "This application is instrumented by PinStace" << endl;
  if (!KnobOutputFile.Value().empty()) {
    cerr << "See file " << KnobOutputFile.Value() << " for analysis results"
         << endl;
  }
  cerr << "===============================================" << endl;

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
