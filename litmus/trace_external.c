#include <linux/module.h>

#include <litmus/trace.h>
#include <litmus/sched_trace.h>
#include <litmus/litmus.h>

#ifdef CONFIG_LITMUS_NVIDIA
#define EXX_TS(evt) \
void __##evt(void) { evt; } \
EXPORT_SYMBOL(__##evt);

EXX_TS(TS_NV_TOPISR_START)
EXX_TS(TS_NV_TOPISR_END)
EXX_TS(TS_NV_BOTISR_START)
EXX_TS(TS_NV_BOTISR_END)
EXX_TS(TS_NV_RELEASE_BOTISR_START)
EXX_TS(TS_NV_RELEASE_BOTISR_END)
#endif /* end LITMUS_NVIDIA */
