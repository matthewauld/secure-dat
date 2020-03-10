const {DatArchive} = require('dat-sdk/auto')
const OpenAbeJS = require('../openabejs/build/Release/openabejs.node').OpenABEjs
const crypto = require('crypto')
const fs = require('fs')
const { Readable, Writable } = require('stream')
const SecureParams = require('./secure-params')
//TODO- move into some kind of versioning params object
const DIFFIE_PRIME = '/qiSrdIq5bXLJCLu+GWZTaSjolgLZBz0Lu0qI662JSpuu5RvlrZV8hRReAc2WAsZtUCmq4w90ArRQd1aVFhOWJTTq49Pl9cqnoBd3e6nF5Iwo9lAmYHshbwfW+NWwUI9KHtA37Xlnnn2o2n1UIF4GWu8u0TP2SFIyL/VIKk/Snv3Xg+F/Y8P9akh/eQ3vg0XuOaZiXDedvZq6SoIQzKTFxapFkD9JGDZ5sTYnK+tREQz/bkSmURyQWsPUhghn41dfcDXNiPoSeZgS/utp5XxRtUyvnpWdHWyCNBab7zNrCfN0S3WgVRWjtjiaBelNNb8fFf4MErp5hylVfQrcHSosw=='
const PUB_KEY_MODULUS_LENGTH = 4096
const PUB_KEY_ENCODING = {type:'spki', format:'pem'}
const PRIV_KEY_ENCODING = {type:'pkcs8',format:'pem'}
const PLAINTEXT = 101


module.exports = class SecureDat{
  constructor(key,opts){
    //TODO, right now, constrcor does not work without init.
    this.params = null
    this.abe = new OpenAbeJS()
    if(key == null){
      this._archivePromise =  DatArchive.create(opts).then(a=>this.archive = a)
    } else {

      this._archivePromise = DatArchive.load(key,opts).then(a=>this.archive = a)
    }


  }


  async addUser(attributes,url){
    //add the version number to the attribute list
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
    await this._write(`/.sdat/users/${index}`, encryptedKey.toString('base64'))

  }
  async readFile(filename,opts={}){

  }

  async writeFile(filename,data,accessTree,opts={}){
    if(!(data instanceof Readable) &&  !(typeof data ==='string')){
      throw new Error("Data must be be either a readable stream or a string")
    }
    if(!this.params){
      throw new Error("Cannot write to a SecureDat you do not own")
    }

    const algorithm = 'aes-256-cbc'
    //ensure there is an access tree
    if(!accessTree){
      throw new Error("missing accessTree. To encrypt in plaintext, pass PLAINTEXT")
    } else if(accessTree == PLAINTEXT){
      this._write(filename, data,opts)
    }
    //initalize iv, generate ciphertext
    const iv = await this._genRandomBytes(16)
    const sKey = this.abe.encrypt(accessTree)
    const key = Buffer.from(sKey.key)
    const keyCiphertext = Buffer.from(sKey.ciphertext)

    const cipher = crypto.createCipheriv(algorithm, key, iv);
    const writeStream = await this._createWriteStream(filename,opts)
    console.log(writeStream)
    //write the access tree, iv, and the key ciphertext as the first two lines.
    writeStream.write(accessTree)
    writeStream.write(`\n`)
    writeStream.write(iv.toString('base64'))
    writeStream.write(`\n`)
    writeStream.write(keyCiphertext.toString('base64'))
    writeStream.write(`\n`)

    //encrypt and write the data
    return new Promise((resolve,reject)=>{
      writeStream.on('finish',()=>{resolve()})
      writeStream.on('error',e=>reject(error))
      if(data instanceof Readable){
        data.pipe(cipher).pipe(writeStream)
      } else {
        cipher.pipe(writeStream)

        cipher.end(data)

      }
    })
  }

  async _genRandomBytes(size){
    return new Promise((resolve,reject)=>{
      crypto.randomBytes(size,(err,buf)=>{
        if(err){
          reject(err)
        }
        resolve(buf)
      })
    })
  }

  async _load(params,key){
    if (params instanceof SecureParam){
      this.params = params
    } else{
      this.params = await SecureParams.load(params)
      this.diffie = crypto.createDiffieHellman(this.params.diffiePrime)
      this.abe.importPublicParams(this.params.publicParams)

      if(this.params.owner){
        this.abe.importSecretParams(this.params.secretParams)
        //generate a master key, only used for this instance.
        //TODO: fix hardcoded 1000. Also, this might be slow? Should we generate and save master?
        this.abe.keygen('user',this.params.attrs.join('|')+'|version=1000')
      } else{
        const key = Buffer.from(key,'base64')
        this.abe.importUserKey('user',key.buf)
      }
    }
  }


  async _init(paramPath){
    //inialize params
    this.abe.generateParams()
    let publicParams = Buffer.from(this.abe.exportPublicParams())
    let secretParams = Buffer.from(this.abe.exportSecretParams())
    let diffiePrime = Buffer.from(DIFFIE_PRIME,'base64')
    await this.mkdir('/.sdat')
    await this.mkdir('/.sdat/users')
    await this._write('/.sdat/version','1')
    await this._write('/.sdat/pub_params',publicParams.toString('base64'))
    this.diffie = crypto.createDiffieHellman(diffiePrime)
    let version =1
    //generate the diffiePair and pub pair to allow adding and being added to other dats
    let diffieSecret = this.diffie.generateKeys()
    let diffiePublic = this.diffie.getPrivateKey()
    let joinKey =  await this._genKeyPair()
    let config_file = {joinKey:joinKey.pub.export(PUB_KEY_ENCODING),diffiePublic:diffiePublic.toString('base64')}
    await this._write('/.sdat/config',JSON.stringify(config_file))
    let pubDatKey = await DatArchive.resolveName(this.archive.url)
    let secDatKey = await this.archive.getSecretKey()
    this.params = new SecureParams(paramPath,
                                   null,
                                   null,
                                   null,
                                   null,
                                   publicParams,
                                   secretParams,
                                   diffiePrime,
                                   diffieSecret,
                                   diffiePublic,
                                   joinKey,
                                   pubDatKey,
                                   secDatKey,
                                   version)
    this.abe.keygen('user',this.params.attrs.join('|')+'|version=1000')
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
    return await this.archive.writeFile(filename,data,opts)
  }

  async _read(filename,opts={}){
    return await this.archive.readFile(filename,opts)

  }

  async _createWriteStream(filename,opts){
    return await this.archive._archive.createWriteStream(filename, opts)
  }

  async _createReadStream(filename,opts){
    return await this.archive._archive.createReadStream(filename, opts)
  }



  static async new(opts){
    const sdat = new SecureDat(null,opts,{})

    await sdat._archivePromise
    await sdat._init()
    return sdat
  }

  static async loadSecureDat(key,opts,params){
      const sdat = new SecureDat(key,opts)
      await sdat._archivePromise
      await sdat._load(params)
      return sdat
  }


  /*
  * CARRYTHROUGH - these function carrythough to the underlying dat archive without modification
  */
  async mkdir(path){
    console.log()
    await this.archive.mkdir(path)
  }
}
