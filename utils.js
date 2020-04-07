const crypto = require('crypto')

const PUB_KEY_MODULUS_LENGTH = 4096
const PUB_KEY_ENCODING = {type:'spki', format:'pem'}
const PRIV_KEY_ENCODING = {type:'pkcs8',format:'pem'}
const ALOGRITHM = 'aes-256-cbc'



module.exports.symEncrypt = async (key)=>{

  const iv = await this.genRandomBytes(16)
  const cipher = crypto.createCipheriv(ALOGRITHM, key, iv);

  return [iv,cipher]
}

module.exports.symDecrypt = async (key,iv) =>{
  return crypto.createDecipheriv(ALOGRITHM, key,iv)
}

module.exports.hybridEncrypt = async (pubKey,data) => {
  //generate key
  const key = await module.exports.genRandomBytes(32)
  const encryptedKey = crypto.publicEncrypt(pubKey,key)
  const [iv, cipher] = await module.exports.symEncrypt(key)

  let ciphertext = cipher.update(data)
  ciphertext += cipher.final()
  return [iv, encryptedKey, ciphertext]
}


module.exports.genRandomBytes = async (size) => {
  return new Promise((resolve,reject)=>{
    crypto.randomBytes(size,(err,buf)=>{
      if(err){
        reject(err)
      }
      resolve(buf)
    })
  })
}

module.exports.genKeyPair = async ()=>{
  return new Promise((resolve,reject)=>{
    crypto.generateKeyPair('rsa',{modulusLength: PUB_KEY_MODULUS_LENGTH},
                          (err,publicKey,privateKey)=>{
      if(err)
        reject(err)
      resolve({pub:publicKey,priv:privateKey})
    })
  })
}

module.exports.compareArrays = (a1,a2) => {
  if(a1.byteLength!=a2.byteLength){
    return false
  }
  for(var i =0;i<a1.byteLength;i++){
    if(a1[i]!=a2[i]){
      return false
    }
  }
  return true
}
