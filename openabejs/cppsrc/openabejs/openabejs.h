
#include <napi.h>
#include <string>
#include <map>
#include <openabe/openabe.h>
using namespace oabe;
using namespace std;

class OpenABEjs: public Napi::ObjectWrap<OpenABEjs> {
  public:
    static Napi::Object Init(Napi::Env env, Napi::Object exports);
    OpenABEjs(const Napi::CallbackInfo& info);
    ~OpenABEjs();


  private:
    static Napi::FunctionReference constructor;
    bool hasSecretParams;
    bool hasPublicParams;
    OpenABEByteString secretParams;
    OpenABEByteString publicParams;
    map<string,OpenABEByteString> keys;





    void generateParams(const Napi::CallbackInfo& info);
    Napi::Value exportPublicParams(const Napi::CallbackInfo& info);
    void importPublicParams(const Napi::CallbackInfo& info);
    Napi::Value exportSecretParams(const Napi::CallbackInfo& info);
    void importSecretParams(const Napi::CallbackInfo& info);
    void keygen(const Napi::CallbackInfo& info);
    Napi::Value exportUserKey(const Napi::CallbackInfo& info);
    void importUserKey(const Napi::CallbackInfo& info);
    Napi::Value encrypt(const Napi::CallbackInfo& info);
    Napi::Value decrypt(const Napi::CallbackInfo& info);


};
