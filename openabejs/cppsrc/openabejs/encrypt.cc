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
  int at_size= 0;
  read(6,&param_size,sizeof(int));
  uint8_t* param_buffer = new uint8_t[param_size];
  read(6,param_buffer,param_size);

  read(6,&at_size,sizeof(int));
  char* at_buffer = new char[at_size];
  read(6,at_buffer,at_size);

  string at(at_buffer);
  try{

  OpenABEByteString public_params;
  public_params.appendArray(param_buffer,param_size);
  std::unique_ptr<OpenABEFunctionInput> encInput = createPolicyTree(at);
  abe->loadMasterPublicParams("mpk",public_params);
  OpenABEContextGenericCCA x(move(abe));
  unique_ptr<OpenABERNG> rng(new OpenABERNG());

  shared_ptr<OpenABESymKey> key = make_shared<OpenABESymKey>();
  OpenABECiphertext ct;
  x.encryptKEM(rng.get(),"mpk",encInput.get(),32,key,&ct);
  //SEND KEY
  OpenABEByteString keyBuf;
  key->exportKeyToBytes(keyBuf);

  int key_size = keyBuf.size();


  write(5,&key_size,sizeof(int));
  write(5,keyBuf.getInternalPtr(),key_size);
  //SEND CIPHERTEXT
  OpenABEByteString ctBuf;
  ct.exportToBytes(ctBuf);
  int ct_size = ctBuf.size();
  write(5,&ct_size,sizeof(int));
  write(5,ctBuf.getInternalPtr(),ct_size);

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
