/*****************************************************************************\
* Qemu Simulation Framework (qsim)                                            *
* Qsim is a modified version of the Qemu emulator (www.qemu.org), couled     *
* a C++ API, for the use of computer architecture researchers.                *
*                                                                             *
* This work is licensed under the terms of the GNU GPL, version 2. See the    *
* COPYING file in the top-level directory.                                    *
\*****************************************************************************/
#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>
#include <thread>

#include <qsim.h>
#include <qsim-load.h>
#include <capstone.h>

#include "cs_disas.h"

using Qsim::OSDomain;

using std::ostream;
using std::to_string;

class FenceCounter {
public:
  FenceCounter(OSDomain &osd) :
	  osd(osd), finished(false), unid_fences(0), full_fences(0),
    llsc(0), icount(0), mcount(0)
  { 
    if (osd.getCpuType(0) == "a64") {
      dis = new cs_disas(CS_ARCH_ARM64, CS_MODE_ARM);
    } else {
      dis = new cs_disas(CS_ARCH_X86, CS_MODE_64);
    }

    osd.set_app_start_cb(this, &FenceCounter::app_start_cb);
  }

  bool hasFinished() { return finished; }

  int app_start_cb(int c) {
    static bool ran = false;
    if (!ran) {
      ran = true;
      if (osd.getCpuType(0) == "a64")
        osd.set_inst_cb(this, &FenceCounter::a64_inst_cb);
      else
        osd.set_inst_cb(this, &FenceCounter::x86_inst_cb);

      osd.set_mem_cb(this, &FenceCounter::mem_cb);

      osd.set_app_end_cb(this, &FenceCounter::app_end_cb);

      std::cout << "icount, uni, full" << std::endl;
      return 1;
    }

    return 0;
  }

  int app_end_cb(int c)   { finished = true; return 1; }

  void mem_cb(int c, uint64_t v, uint64_t p, uint8_t s, int w) {
    mcount++;
  }

  void x86_inst_cb(int c, uint64_t v, uint64_t p, uint8_t l, const uint8_t *b, 
               enum inst_type t)
  {
    cs_insn *insn = NULL;

    int count = dis->decode((unsigned char *)b, l, insn);

    if (!count)
      return;

    insn[0].address = v;

    switch (insn[0].id) {
    case X86_INS_MFENCE:
    case X86_INS_SFENCE:
    case X86_INS_LFENCE:
      full_fences++;
      break;
    case X86_INS_XCHG:
      llsc++;
    default:
      if (insn[0].detail->x86.prefix[0] == X86_PREFIX_LOCK)
        llsc++;
      break;
    }

    dis->free_insn(insn, count);

    icount++;
  }

  void a64_inst_cb(int c, uint64_t v, uint64_t p, uint8_t l, const uint8_t *b, 
               enum inst_type t)
  {
    cs_insn *insn = NULL;

    int count = dis->decode((unsigned char *)b, l, insn);
    insn[0].address = v;

    switch (insn[0].id) {
    case ARM64_INS_STLR:
    case ARM64_INS_STLRB:
    case ARM64_INS_STLRH:
    case ARM64_INS_LDAR:
    case ARM64_INS_LDARB:
    case ARM64_INS_LDARH:
      unid_fences++;
      break;
    case ARM64_INS_STLXR:
    case ARM64_INS_STLXRB:
    case ARM64_INS_STLXRH:
    case ARM64_INS_LDAXR:
    case ARM64_INS_LDAXRB:
    case ARM64_INS_LDAXRH:
      llsc++;
      break;
    case ARM64_INS_DMB:
    case ARM64_INS_DSB:
    case ARM64_INS_ISB:
      full_fences++;
      break;
    default:
      break;
    }

    dis->free_insn(insn, count);

    icount++;

    return;
  }

  void print_stats(std::ofstream& out)
  {
    std::cout << "uni: " << unid_fences << " llsc: " << llsc << " full: " << full_fences << " icount: "<< icount << std::endl;
    out << "uni: " << unid_fences << " llsc: " << llsc << " full: " << full_fences << " icount: "<< icount << std::endl;
  }

  void print_stats_csv(std::ofstream& out)
  {
    std::cout << "uni: " << unid_fences << " llsc: " << llsc << " full: " << full_fences << " icount: "<< icount << " mcount: " << mcount << std::endl;
    out << "," + to_string(unid_fences) + "," + to_string(llsc) + "," + to_string(full_fences) + "," + to_string(icount) + "," + to_string(mcount) << std::endl;
  }

  uint64_t geticount(void) { return icount; }

  ~FenceCounter() { delete dis; }

private:
  OSDomain &osd;
  bool finished;
  uint64_t unid_fences;
  uint64_t full_fences;
  uint64_t llsc;
  uint64_t icount, mcount;
  cs_disas* dis;

  static const char * itype_str[];
};

int main(int argc, char** argv) {
  using std::istringstream;
  using std::ofstream;

  ofstream *outfile(NULL);

  unsigned n_cpus = 1;

  std::string qsim_prefix(getenv("QSIM_PREFIX"));

  if (argc < 4) {
    std::cerr << "Usage: " << argv[0] << " <ncpus> <state_file> <benchmark.tar>\n";
    exit(1);
  }

  // Read number of CPUs as a parameter. 
  istringstream s(argv[1]);
  s >> n_cpus;

  OSDomain *osd_p(NULL);

  // Create new OSDomain from saved state.
  osd_p = new OSDomain(n_cpus, argv[2]);
  OSDomain &osd(*osd_p);

  // Attach a FenceCounter if a trace file is given.
  FenceCounter fc(osd);

  Qsim::load_file(osd, argv[3]);
  std::string bench(argv[3]);
  std::string filename = bench.substr(bench.find_last_of("/")+1);
  std::string ofname = std::string(filename.substr(0, filename.find_last_of("."))) + ".out";
  std::cout << ofname << std::endl;
  std::ofstream out;
  out.open(ofname, std::ofstream::out | std::ofstream::app);
  // If this OSDomain was created from a saved state, the app start callback was
  // received prior to the state being saved.
  fc.app_start_cb(0);

  osd.connect_console(std::cout);

  // The main loop: run until 'finished' is true.
  unsigned long inst_per_iter = 1000000;
  while (!fc.hasFinished()) {
    osd.run(inst_per_iter);

    // count for 1000M instructions max
    if (fc.geticount() > 2000 * 1000000)
      break;
  }
  
  fc.print_stats_csv(out);
  if (outfile) { outfile->close(); }
  delete outfile;

  delete osd_p;

  return 0;
}
