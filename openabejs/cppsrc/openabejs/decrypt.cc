#include <string>
#include <openabe/openabe.h>
#include <fstream>
#include <unistd.h>
#include <sys/wait.h>
using namespace std;
using namespace oabe;





int main(){

  InitializeOpenABE();
  std::unique_ptr<OpenABEContextSchemeCPA> abe = nullptr;
  abe = OpenABE_createContextABESchemeCPA(OpenABE_SCHEME_CP_WATERS);

  int param_size = 0;
  int key_size = 0;
  int ct_size= 0;

  read(6,&param_size,sizeof(int));
  uint8_t* param_buffer = new uint8_t[param_size];
  read(6,param_buffer,param_size);

  read(6,&key_size,sizeof(int));
  uint8_t* key_buffer = new uint8_t[key_size];
  read(6,key_buffer,key_size);

  read(6,&ct_size,sizeof(int));
  uint8_t* ct_buffer = new uint8_t[ct_size];
  read(6,ct_buffer,ct_size);


  try{

  OpenABEByteString public_params;
  public_params.appendArray(param_buffer,param_size);

  OpenABEByteString user_key;
  user_key.appendArray(key_buffer,key_size);

  OpenABEByteString ct_string;
  ct_string.appendArray(ct_buffer,ct_size);

  OpenABECiphertext ct;

  ct.loadFromBytes(ct_string);



  abe->loadMasterPublicParams("mpk",public_params);
  abe->loadUserSecretParams("user",user_key);

  OpenABEContextGenericCCA x(move(abe));
  unique_ptr<OpenABERNG> rng(new OpenABERNG());

  shared_ptr<OpenABESymKey> key = make_shared<OpenABESymKey>();
  int result = x.decryptKEM("mpk","user",&ct,32,key);
  //SEND KEY
  OpenABEByteString keyBuf;
  key->exportKeyToBytes(keyBuf);

  int key_size = keyBuf.size();

  if(key_size == 0){
    int err = 0;
    int errCode = result;
    write(5,&err,sizeof(int));
    write(5,&errCode,sizeof(int));
  }
  write(5,&key_size,sizeof(int));
  write(5,keyBuf.getInternalPtr(),key_size);
  //SEND CIPHERTEXT


} catch(const OpenABE_ERROR& e){
  //on error, write 0, then the error code
  int err = 0;
  int errCode = e;
  write(5,&err,sizeof(int));
  write(5,&errCode,sizeof(int));
}
  close(5);
  close(6);
  exit(0);
}
