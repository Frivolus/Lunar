#include <windows.h>

namespace lunar::hyperion {

// Neutralisation des sondes anti-debug. A implementer.
bool hide_from_debugger() {
    return true;
}

}
