#include <napi.h>
#include "openabejs/openabejs.h"

Napi::Object InitAll(Napi::Env env, Napi::Object exports) {

  return OpenABEjs::Init(env, exports);
}

NODE_API_MODULE(NODE_GYP_MODULE_NAME, InitAll);
