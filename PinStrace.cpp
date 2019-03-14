/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs
 *  and could serve as the starting point for developing your first PIN tool
 */

#include "pin.H"
#include <fstream>
#include <iostream>

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

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

static VOID SysBefore(std::ostream &Output, ADDRINT Ip, ADDRINT Nr,
                      ADDRINT Arg1, ADDRINT Arg2, ADDRINT Arg3, ADDRINT Arg4,
                      ADDRINT Arg5, ADDRINT Arg6) {
  Output << "In ";
}

static VOID SysAfter(std::ostream &Output, ADDRINT Ret) {
  Output <<"and out.\n";
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
