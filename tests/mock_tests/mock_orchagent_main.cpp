extern "C" {
#include <sai.h>
#include <saistatus.h>
}

#include "orchdaemon.h"

/* Global variables */
sai_object_id_t gVirtualRouterId;
sai_object_id_t gUnderlayIfId;
sai_object_id_t gSwitchId = SAI_NULL_OBJECT_ID;
MacAddress gMacAddress;
MacAddress gSagMacAddress;
MacAddress gVxlanMacAddress;

string gMySwitchType = "switch";
int32_t gVoqMySwitchId = 0;
string gMyHostName = "Linecard1";
string gMyAsicName = "Asic0";
bool gTraditionalFlexCounter = false;

VRFOrch *gVrfOrch;

void syncd_apply_view() {}
