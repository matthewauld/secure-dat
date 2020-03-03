const {DatArchive} = require('dat-sdk/auto')
const OpenAbeJS = require('../openabejs/build/Release/openabejs.node').OpenABEjs
const crypto = require('crypto')
const fs = require('fs')
const { Readable } = require('stream')
const SecureParams = require('./secure-params')
//TODO- move into some kind of versioning params object
const DIFFIE_PRIME = '/qiSrdIq5bXLJCLu+GWZTaSjolgLZBz0Lu0qI662JSpuu5RvlrZV8hRReAc2WAsZtUCmq4w90ArRQd1aVFhOWJTTq49Pl9cqnoBd3e6nF5Iwo9lAmYHshbwfW+NWwUI9KHtA37Xlnnn2o2n1UIF4GWu8u0TP2SFIyL/VIKk/Snv3Xg+F/Y8P9akh/eQ3vg0XuOaZiXDedvZq6SoIQzKTFxapFkD9JGDZ5sTYnK+tREQz/bkSmURyQWsPUhghn41dfcDXNiPoSeZgS/utp5XxRtUyvnpWdHWyCNBab7zNrCfN0S3WgVRWjtjiaBelNNb8fFf4MErp5hylVfQrcHSosw=='
const PUB_KEY_MODULUS_LENGTH = 4096
const PUB_KEY_ENCODING = {type:'spki', format:'pem'}
const PRIV_KEY_ENCODING = {type:'pkcs8',format:'pem'}
const PLAINTEXT = 101


module.exports = class SecureDat{
  constructor(key,opts){
    this.params = null
    this.abe = new OpenAbeJS()
    if(key == null){
      this._archivePromise = DatArchive.create(opts)
    } else {

      this._archivePromise = DatArchive.load(key,opts).then(()=>{
        this._load(params)
      })
    }


  }


  async addUser(attributes,url){

    //get the other users config file and parse
    const otherKey = await DatArchive.resolveName(url)

    //check to see if user already exists
    if(this.params.users.has(otherKey)){
      throw new Error("User already exists!")
    }
    const other = await DatArchive.load(otherKey,{sparse:true})
    const config_data = await other.readFile('/.sdat/config','utf8')
    const config = JSON.parse(config_data)
    const joinKey = crypto.createPublicKey({key:config.joinKey,format:PUB_KEY_ENCODING.format,type:PUB_KEY_ENCODING.type})
    const otherDiffie = Buffer.from(config.diffiePublic,'base64')

    //compute Shared Secret, and hash it to get the new index
    const secret = this.diffie.computeSecret(otherDiffie)
    const hash = crypto.createHash('sha256')
    const index = hash.update(secret.toString('base64')).digest('hex')

    this.params.users.set(otherKey,{index:index,attributes:attributes,pubKey:joinKey})
    //generate a new key, encrypt it, and add it to the users folder.

    //TODO: turn this into a one step process
    this.abe.keygen(attributes,index)
    const newKey = Buffer.from(this.abe.exportUserKey(index));
    const encryptedKey = crypto.publicEncrypt(joinKey,newKey);
    console.log("here1", index)
    await this._write(`/.sdat/users/${index}`, encryptedKey.toString('base64'))
    console.log("here2")

  }


  async write(filename,data,accessTree,opts={}){
    if(!accessTree){
      throw new Error("missing accessTree. To encrypt in plaintext, pass PLAINTEXT")
    } else if(accessTree == PLAINTEXT){
      this._write(filename, data,opts)
    }

    const sKey = this.abe.encrypt(accessTree)

  }

  async _load(params){
    if(typeof params == SecureParam){
      this.params = params
    } else{
      this.params = await SecureParams.load(params)
      this.diffie = crypto.createDiffieHellman(this.params.diffiePrime)
      this.oabe.importPublicParams(this.params.publicParams)
      this.oabe.importSecretParams(this.params.secretParams)
      //generate a master key, only used for this instance.
      //TODO: fix hardcoded 1000. Also, this might be slow? Should we generate and save master?
      this.oabe.keygen(this.params.attrs.join('|')+'|version=1000')
    }
  }


  async _init(paramPath){
    //inialize params
    this.abe.generateParams()
    let publicParams = Buffer.from(this.abe.exportPublicParams())
    let secretParams = Buffer.from(this.abe.exportSecretParams())
    //create an attribute for superuser.
    let diffiePrime = Buffer.from(DIFFIE_PRIME,'base64')
    await this.mkdir('/.sdat')
    await this.mkdir('/.sdat/users')
    await this._write('/.sdat/version','1')
    await this._write('/.sdat/pub_params',publicParams.toString('base64'))
    this.diffie = crypto.createDiffieHellman(diffiePrime)

    //generate the diffiePair and pub pair to allow adding and being added to other dats
    let diffieSecret = this.diffie.generateKeys()
    let diffiePublic = this.diffie.getPrivateKey()
    let joinKey =  await this._genKeyPair()
    let config_file = {joinKey:joinKey.pub.export(PUB_KEY_ENCODING),diffiePublic:diffiePublic.toString('base64')}
    await this._write('/.sdat/config',JSON.stringify(config_file))
    let pubDatKey = await DatArchive.resolveName(this.archive.url)
    let secDatKey = await this.archive.getSecretKey()
    this.params = new SecureParams(paramPath,
                                   publicParams,
                                   secretParams,
                                   diffiePrime,
                                   diffieSecret,
                                   diffiePublic,
                                   joinKey,
                                   pubDatKey,
                                   secDatKey)
  }





  async _genKeyPair(){
    return new Promise((resolve,reject)=>{
      crypto.generateKeyPair('rsa',{modulusLength: PUB_KEY_MODULUS_LENGTH},
                            (err,publicKey,privateKey)=>{
        if(err)
          reject(err)
        resolve({pub:publicKey,priv:privateKey})
      })
    })
  }

  async _write(filename,data,opts={}){
    await this.archive.writeFile(filename,data,opts)
  }

  async _read(path,opts={}){
    await this.archive.readFile(filename,path,opts)

  }




  static async new(opts){
    const sdat = new SecureDat(null,opts,{})

    sdat.archive = await sdat._archivePromise
    await sdat._init()
    return sdat
  }

  static async loadSecureDat(key,opts,params){
      const sdat = new SecureDat(key,opts,params)
      sdat.archive = await sdat._archivePromise
      return sdat
  }


  /*
  * CARRYTHROUGH - these function carrythough to the underlying dat archive without modification
  */
  async mkdir(path){
    await this.archive.mkdir(path)
  }
}
