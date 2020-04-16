#include "openabejs.h"
#include <stdio.h>
#include <sys/wait.h>
#include <execinfo.h>
#include <string.h>
#include <unistd.h>
#include <iostream>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <fstream>
using namespace std;

Napi::Object OpenABEjs::Init(Napi::Env env, Napi::Object exports) {
  InitializeOpenABE();
  Napi::HandleScope scope(env);
  Napi::Function func = DefineClass(env, "OpenABEjs", {
   InstanceMethod("generateParams", &OpenABEjs::generateParams),
   InstanceMethod("importPublicParams", &OpenABEjs::importPublicParams),
   InstanceMethod("exportPublicParams", &OpenABEjs::exportPublicParams),
   InstanceMethod("importSecretParams", &OpenABEjs::importSecretParams),
   InstanceMethod("exportSecretParams", &OpenABEjs::exportSecretParams),
   InstanceMethod("keygen",&OpenABEjs::keygen),
   InstanceMethod("exportUserKey",&OpenABEjs::exportUserKey),
   InstanceMethod("importUserKey", &OpenABEjs::importUserKey),
   InstanceMethod("encrypt", &OpenABEjs::encrypt),
   InstanceMethod("decrypt", &OpenABEjs::decrypt),
  });

  constructor = Napi::Persistent(func);
  constructor.SuppressDestruct();
  exports.Set("OpenABEjs", func);
  return exports;
}

OpenABEjs::OpenABEjs(const Napi::CallbackInfo& info):
  Napi::ObjectWrap<OpenABEjs>(info),
  hasSecretParams(false),
  hasPublicParams(false) {
  Napi::Env env = info.Env();
  Napi::HandleScope scope(env);
}


OpenABEjs::~OpenABEjs(){

}

Napi::FunctionReference OpenABEjs::constructor;






void OpenABEjs::generateParams(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  try{
    std::unique_ptr<OpenABEContextSchemeCPA> abe = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);
    abe->generateParams("BN_P254", "mpk", "msk");
    abe->exportKey("mpk",this->publicParams);
    abe->exportKey("msk",this->secretParams);
    this->hasSecretParams = true;
    this->hasPublicParams = true;
  } catch(const OpenABE_ERROR& e){
    Napi::TypeError::New(env,OpenABE_errorToString(e)).ThrowAsJavaScriptException();
  }

}


Napi::Value OpenABEjs::exportPublicParams(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  if(!this->hasPublicParams){
    Napi::Error::New(env,"No public parameters to export.").ThrowAsJavaScriptException();
    Napi::Value result;
    return result;

  }

  Napi::ArrayBuffer result  = Napi::ArrayBuffer::New(env,this->publicParams.size());
  memcpy(result.Data(), this->publicParams.getInternalPtr(),this->publicParams.size());

  return result;
}


void OpenABEjs::importPublicParams(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  if(info.Length() < 1 || !info[0].IsArrayBuffer()){
    Napi::TypeError::New(env,"ArrayBuffer expected").ThrowAsJavaScriptException();
    return;
  }
  Napi::ArrayBuffer new_params = info[0].As<Napi::ArrayBuffer>();


  try{
    this->publicParams.zeroize();
    this->publicParams.appendArray((uint8_t*)new_params.Data(),new_params.ByteLength());
    std::unique_ptr<OpenABEContextSchemeCPA> abe = nullptr;
    abe = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);
    abe->loadMasterPublicParams("mpk",this->publicParams);
    this->hasPublicParams = true;

  } catch(const OpenABE_ERROR& e){
    Napi::TypeError::New(env,OpenABE_errorToString(e)).ThrowAsJavaScriptException();
  }
  return;
}


Napi::Value OpenABEjs::exportSecretParams(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  if(!this->hasSecretParams){
    Napi::Error::New(env,"No secret parameters to export.").ThrowAsJavaScriptException();
    Napi::Value result;
    return result;

  }

  Napi::ArrayBuffer result  = Napi::ArrayBuffer::New(env,this->secretParams.size());
  memcpy(result.Data(), this->secretParams.getInternalPtr(),this->secretParams.size());

  return result;
}


void OpenABEjs::importSecretParams(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  if(info.Length() < 1 || !info[0].IsArrayBuffer()){
    Napi::TypeError::New(env,"ArrayBuffer expected").ThrowAsJavaScriptException();
    return;
  }

  Napi::ArrayBuffer new_params = info[0].As<Napi::ArrayBuffer>();


  try{
    this->secretParams.zeroize();
    this->secretParams.appendArray((uint8_t*)new_params.Data(),new_params.ByteLength());

    this->hasSecretParams = true;
  } catch(const OpenABE_ERROR& e){
    Napi::TypeError::New(env,OpenABE_errorToString(e)).ThrowAsJavaScriptException();
  }

  return;
}

void OpenABEjs::keygen(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  if(info.Length()<2 || !info[0].IsString() || !info[1].IsString()){
    Napi::TypeError::New(env, "Two strings expected").ThrowAsJavaScriptException();
    return;
  }
  string attrs = info[0].As<Napi::String>().Utf8Value();

  string username = info[1].As<Napi::String>().Utf8Value();
  try{
    std::unique_ptr<OpenABEContextSchemeCPA> abe = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);

    abe->loadMasterPublicParams("mpk",this->publicParams);
    abe->loadMasterSecretParams("msk",this->secretParams);

    std::unique_ptr<OpenABEFunctionInput> keyInput = createAttributeList(attrs);

    abe->keygen(keyInput.get(),username,"mpk","msk");

    OpenABEByteString result;
    abe->exportKey(username,result);

    this->keys[username] = result;
  } catch(const OpenABE_ERROR& e){
    Napi::Error::New(env,OpenABE_errorToString(e)).ThrowAsJavaScriptException();
  }
  return;
}


Napi::Value OpenABEjs::exportUserKey(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  if(info.Length()<1 || !info[0].IsString()){
    Napi::TypeError::New(env, "String expected").ThrowAsJavaScriptException();
    Napi::Value result;
    return result;
  }
  string username = info[0].As<Napi::String>().Utf8Value();
  string userKey;
  if(this->keys.count(username)==0){ //why the hell is the "contains" method called count in c++? Wierd
    Napi::Error::New(env,"No key with name: "+ username).ThrowAsJavaScriptException();
    Napi::Value result;
    return result;
  }

  Napi::ArrayBuffer result  = Napi::ArrayBuffer::New(env,this->keys[username].size());
  memcpy(result.Data(), this->keys[username].getInternalPtr(),this->keys[username].size());

  return result;

}



void OpenABEjs::importUserKey(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  if(info.Length()<2 || !info[0].IsString() || !info[1].IsArrayBuffer()){
    Napi::TypeError::New(env, "A String and an ArrayBuffer is expected").ThrowAsJavaScriptException();
    return;
  }
  string username = info[0].As<Napi::String>().Utf8Value();
  Napi::ArrayBuffer key = info[1].As<Napi::ArrayBuffer>();
  try{
    OpenABEByteString result;
    result.appendArray((uint8_t*)key.Data(),key.ByteLength());
    this->keys[username] = result;

    std::unique_ptr<OpenABEContextSchemeCPA> abe = nullptr;
    abe = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);
    abe->loadMasterPublicParams("mpk",this->publicParams);
    abe->loadUserSecretParams(username,this->keys[username]);
  } catch(const OpenABE_ERROR& e){
    Napi::Error::New(env,OpenABE_errorToString(e)).ThrowAsJavaScriptException();
  }
  return;
}


Napi::Value OpenABEjs::encrypt(const Napi::CallbackInfo& info){
  Napi::Env env = info.Env();
  string at = info[0].As<Napi::String>().Utf8Value();

  int pipeToWorker[2];
  int pipeFromWorker[2];
  pipe(pipeToWorker);
  pipe(pipeFromWorker);
  Napi::Object global = env.Global();
  vector<napi_value> x; //dummy vector
  string cwd = global.Get("process").As<Napi::Object>().Get("cwd").As<Napi::Function>().Call(x).As<Napi::String>().Utf8Value();
  string path;

  if(cwd.substr(cwd.length()-9,9) == "openabejs"){
    path = cwd + "/cppsrc/openabejs/encrypt";
  } else{
    path = cwd + "/openabejs/cppsrc/openabejs/encrypt";
  }
  //test if program exists
  ifstream testFile(path);
  if(!testFile){
    Napi::Error::New(env,"Encrypt program cannot be found at "+path).ThrowAsJavaScriptException();
    Napi::Value result;
    return result;

  }
  int pid = fork();
  if(pid==0){
    char* argv[] = {"encrypt",(char*)0};
    char* env[] = {(char*)0};
    dup2(pipeFromWorker[1],5);
    dup2(pipeToWorker[0],6);
    //for testing purposes, find encrypt if we are in the module or in a containing module

    execve(path.c_str(),argv,env);
    cout<<"Could not Execve into encrypt process"<<endl;
    exit(1);
  }else {
    int paramSize = this->publicParams.size();

    write(pipeToWorker[1],&paramSize,sizeof(int));
    //write public params
    write(pipeToWorker[1],this->publicParams.getInternalPtr(),paramSize);
    //write size of attr string
    int at_size = at.size();
    write(pipeToWorker[1],&at_size,sizeof(int));
    //write  access tree
    write(pipeToWorker[1],at.data(),at_size);

    wait(&pid);
    //get the results
    int key_size = 0;
    int ct_size = 0;
    read(pipeFromWorker[0],&key_size,sizeof(int));
    if(key_size==0){
      OpenABE_ERROR errCode;
      read(pipeFromWorker[0],&errCode,sizeof(OpenABE_ERROR));
      const char* errorMsg = OpenABE_errorToString(errCode);
      Napi::Error::New(env,errorMsg).ThrowAsJavaScriptException();
      Napi::Value result;
      return result;
    }
    Napi::ArrayBuffer key = Napi::ArrayBuffer::New(env,key_size);
    read(pipeFromWorker[0],key.Data(),key_size);

    read(pipeFromWorker[0],&ct_size,sizeof(int));
    Napi::ArrayBuffer ciphertext = Napi::ArrayBuffer::New(env,ct_size);
    read(pipeFromWorker[0],ciphertext.Data(),ct_size);

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("key",key);
    obj.Set("ciphertext",ciphertext);
    return obj;
  }
}

Napi::Value OpenABEjs::decrypt(const Napi::CallbackInfo& info){

  Napi::Env env = info.Env();
  if(info.Length()<2 || !info[0].IsString() || !info[1].IsArrayBuffer()){
    Napi::TypeError::New(env, "A String and an ArrayBuffer is expected").ThrowAsJavaScriptException();
    Napi::Value result;
    return result;
  }
  string username = info[0].As<Napi::String>().Utf8Value();
  if(this->keys.count(username)==0 ){ //why the hell is the "contains" method called count in c++? Wierd
    Napi::Error::New(env,"No key with name: "+ username).ThrowAsJavaScriptException();
    Napi::Value result;
    return result;
  }

  Napi::ArrayBuffer ciphertext = info[1].As<Napi::ArrayBuffer>();
  int pipeToWorker[2];
  int pipeFromWorker[2];
  pipe(pipeToWorker);
  pipe(pipeFromWorker);
  Napi::Object global = env.Global();
  vector<napi_value> x; //dummy vector
  string cwd = global.Get("process").As<Napi::Object>().Get("cwd").As<Napi::Function>().Call(x).As<Napi::String>().Utf8Value();
  string path;
  if(cwd.substr(cwd.length()-9,9) == "openabejs"){
    path = cwd + "/cppsrc/openabejs/decrypt";
  } else{
    path = cwd + "/openabejs/cppsrc/openabejs/decrypt";
  }
  ifstream testFile(path);
  if(!testFile){
    Napi::Error::New(env,"Encrypt program cannot be found at "+path).ThrowAsJavaScriptException();
    Napi::Value result;
    return result;

  }
  int pid = fork();
  if(pid==0){
    char* argv[] = {"encrypt",(char*)0};
    char* env[] = {(char*)0};
    dup2(pipeFromWorker[1],5);
    dup2(pipeToWorker[0],6);

    execve(path.c_str(),argv,env);    cout<<"FAIL"<<endl;
    exit(1);
  }else {
    int paramSize = this->publicParams.size();

    write(pipeToWorker[1],&paramSize,sizeof(int));
    //write public params
    write(pipeToWorker[1],this->publicParams.getInternalPtr(),paramSize);
    //write size of attr string
    int priv_key_size = keys[username].size();
    write(pipeToWorker[1],&priv_key_size,sizeof(int));
    //write  access tree
    write(pipeToWorker[1],keys[username].getInternalPtr(),priv_key_size);

    int ct_size = ciphertext.ByteLength();
    write(pipeToWorker[1],&ct_size,sizeof(int));

    write(pipeToWorker[1],ciphertext.Data(),ct_size);
    wait(&pid);
    //get the results
    int key_size = 0;
    read(pipeFromWorker[0],&key_size,sizeof(int));
    //check to see if there is an error
    if(key_size==0){
      OpenABE_ERROR errCode;
      read(pipeFromWorker[0],&errCode,sizeof(OpenABE_ERROR));
      const char* errorMsg = OpenABE_errorToString(errCode);

      Napi::Error::New(env,errorMsg).ThrowAsJavaScriptException();

      Napi::Value result;
      return result;
    }

    Napi::ArrayBuffer key = Napi::ArrayBuffer::New(env,key_size);
    read(pipeFromWorker[0],key.Data(),key_size);

    Napi::Object obj = Napi::Object::New(env);
    obj.Set("key",key);
    return obj;
  }
}
