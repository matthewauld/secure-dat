const {DatArchive} = require('dat-sdk/auto')
const OpenAbeJS = require('openabejs').OpenABEjs
const crypto = require('crypto')
const fs = require('fs')
const { Readable, Writable } = require('stream')
const SecureParams = require('./secure-params')
const utils = require('./utils')
const attributeParser = require('./attributeParser')
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



  getJoinIndex(otherConfig){

    const otherDiffie = Buffer.from(otherConfig.diffiePublic,'base64')
    const diffie = crypto.createDiffieHellman(Buffer.from(DIFFIE_PRIME,'base64'))
    diffie.setPrivateKey(this.params.diffieSecret)
    const secret = diffie.computeSecret(otherDiffie)
    const hash = crypto.createHash('sha256')
    const index = hash.update(secret.toString('base64')).digest('hex')
    return index
  }


  async _getGuestUserKey(key){

    const config_data = await this._read('/.sdat/config','utf8')
    const config = JSON.parse(config_data)
    const index = this.getJoinIndex(config)

    const keyfile = await this._read(`/.sdat/users/${index}`)
    let userKey = utils.hybridDecrypt(keyfile,this.params.joinKey.priv)
    return Buffer.alloc(Buffer.byteLength(userKey,'base64'),userKey,'base64')
  }




  async addUser(attributes,url, opts ={}){
    if(!this.owner){
      throw new Error("Cannot add user to a SecureDat you do not own")
    }
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
    const index = this.getJoinIndex(config)

    //generate a new key, encrypt it, and add it to the users folder.

    //TODO: turn this into a one step process
    await this.generateUserKey(attributes,index,joinKey)
    this.params.users.set(otherKey,{index:index,attributes:attributes,pubKey:config.joinKey})
  }


  async generateUserKey(attributes,index,joinKey){
    const attributeList = `${attributes}version=${this.params.version}|`
    this.abe.keygen(attributeList,index)
    const newKey = Buffer.from(this.abe.exportUserKey(index))

    const [iv,encryptedKey, ciphertext] = await  utils.hybridEncrypt(joinKey,newKey)
    let keyfile = `${iv.toString('base64')}\n ${encryptedKey.toString('base64')}\n${ciphertext}`
    await this._write(`/.sdat/users/${index}`, keyfile)
  }


  async removeUser(key){
    //Ensure user exists
    if(!this.params.users.has(key)){
      throw Error("No user exists with that key")
    }
    //remove the users key file
    const user = this.params.users.get(key)
     await this.unlink(`/.sdat/users/${user.index}`)

    //add any attribute they had to the dirty attribute lits
    let attrs = attributeParser.parseAttributeList(user.attributes)
    for (let attr of attrs){
      if (attr != 'version'){
        this.params.dirtyAttrs.push(attr)
      }
    }
    //delete the user from the param file
    this.params.users.delete(key)
  }


  async readFile(filename,opts){
    //get return format
    let encoding = 'utf8'
    if(typeof opts === 'string'){
      encoding = opts
    } else if(opts && opts.encoding){
      encoding = opts.encoding
    }
    //ensure there is an up-to-date user key
    if(!this.validUserKey){
      this.genUserKey()
    }

    let contents = await this._read(filename)
    contents = contents.split('\n',4)
    if (contents.length != 4){
      throw new Error("Malformed file")
    }

    const accessTree   = contents[0]
    const iv           = Buffer.from(contents[1],'base64')
    const encryptedKey = Buffer.from(contents[2],'base64')
    const ciphertext   = Buffer.from(contents[3],'base64')
    //test to ensure you can access the file
    let testKey = this.abe.encrypt(accessTree)

    let  testPlaintext;
    try{

      testPlaintext = this.abe.decrypt('user',testKey.ciphertext)

    } catch (e){
      throw Error("You do not have access to this file")
    }





    if(utils.compareArrays(testKey.key,testPlaintext)){
      throw Error("You do not have access to this file")
    }
    //decrypt the key
    // TODO: Should this be using a zero IV?
    let key = Buffer.from(this.abe.decrypt('user', encryptedKey.buffer).key)
    let decipher  = await utils.symDecrypt(key,iv)
    let data = decipher.update(ciphertext,null, encoding)
    data += decipher.final(encoding);

    return data
 }


  async writeFile(filename,data,accessTree,opts={}){


    if(!(data instanceof Readable) &&  !(typeof data ==='string')){
      throw new Error("Data must be be either a readable stream or a string")
    }
    //TODO: fix this
    if(!this.owner){
      throw new Error("Cannot write to a SecureDat you do not own")
    }
    //check to see if keys need to be refreshed
    const attrs = attributeParser.parseAttributeTree(accessTree)
    const dirty = attrs.reduce((acc,attr)=>{
      return acc || this.params.dirtyAttrs.includes(attr)
    },false)
    if(dirty){
      await this.updateVersion()
    }
    accessTree =`( ${accessTree} ) and version >= ${this.params.version}`
    const algorithm = 'aes-256-cbc'
    //ensure there is an access tree
    if(!accessTree){
      throw new Error("missing accessTree. To encrypt in plaintext, pass PLAINTEXT")
    }
    if(accessTree == PLAINTEXT){
      this._write(filename, data,opts)
    }
    //initalize iv, generate ciphertext
    const sKey = this.abe.encrypt(accessTree)
    const key = Buffer.from(sKey.key)
    const keyCiphertext = Buffer.from(sKey.ciphertext)

    const [iv,cipher] = await utils.symEncrypt(key)
    //write the access tree, iv, and the key ciphertext as the first three lines.
    let header = `${accessTree}\n${iv.toString('base64')}\n${keyCiphertext.toString('base64')}\n`
    //encrypt and write the data
    let ciphertext = cipher.update(data,'utf8','base64')
    ciphertext+= cipher.final('base64')
    await this._write(filename,header+ciphertext)
    this.updateAttributes(attrs)

  }


  async updateVersion(){
    //increment current version
    this.params.version += 1

    //regenerate all non-owner keys
    for (let user of this.params.users){
      await this.generateUserKey(user[1].attributes,user[1].index,user[1].pubKey)
    }
  }


  updateAttributes(attrs){
    //TODO: add a tree parser. This only handles simple and/or statements for testing
    attrs.forEach((attr)=>{
      if(!this.params.attrs.includes(attr)){
          this.params.attrs.push(attr)
          this.validUserKey = false
      }

    })
  }


  genUserKey(){
    this.abe.keygen(this.params.attrs.join('|')+'| version = 1000 ','user')
    this.validUserKey = true
  }


  async _load(params,key){
    //load Paramaters
    if (params instanceof SecureParams){
      this.params = params
    } else{
      this.params = await SecureParams.load(params)


    }
      this.owner = (this.params.pubDatKey == key)?true:false

    if(this.owner){
      this.abe.importPublicParams(this.params.publicParams.buffer)
      this.abe.importSecretParams(this.params.secretParams.buffer)
      //key is false, as another key m that key must be regenerated at each
      this.validUserKey = false
    } else {
      const pubParams = await this._read('/.sdat/pub_params')
      this.abe.importPublicParams(Buffer.alloc(Buffer.byteLength(pubParams,'base64'),pubParams,'base64').buffer)
      let userKey
      try{
         userKey = await this._getGuestUserKey(key)
      } catch(e){
        throw new Error("You do not have access to this dat")
      }

      this.abe.importUserKey('user',userKey.buffer)
      this.validUserKey = true
    }
  }



  async _init(paramPath){
    //inialize params
    this.abe.generateParams()
    const publicParams = Buffer.from(this.abe.exportPublicParams())
    const secretParams = Buffer.from(this.abe.exportSecretParams())
    const diffiePrime = Buffer.from(DIFFIE_PRIME,'base64')
    const version = 1
    await this.mkdir('/.sdat')
    await this.mkdir('/.sdat/users')
    await this._write('/.sdat/version','1')
    await this._write('/.sdat/pub_params',publicParams.toString('base64'))
    const diffie = crypto.createDiffieHellman(diffiePrime)
    //generate the diffiePair and pub pair to allow adding and being added to other dats
    const diffiePublic = diffie.generateKeys()
    const diffieSecret = diffie.getPrivateKey()
    const joinKey =  await utils.genKeyPair()
    const config_file = {joinKey:joinKey.pub.export(PUB_KEY_ENCODING),diffiePublic:diffiePublic.toString('base64')}
    await this._write('/.sdat/config',JSON.stringify(config_file))
    const pubDatKey = await DatArchive.resolveName(this.archive.url)
    const secDatKey = await this.archive.getSecretKey()
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
    this.validUserKey = false
    this.owner = true
    this.params.save()
  }







  /*
   * STATIC FUNCTIONS
   *
   */

  static async new(opts,paramPath){
    const sdat = new SecureDat(null,opts,{})

    await sdat._archivePromise
    await sdat._init(paramPath)
    return sdat
  }

  static async load(key,opts,params){
      const sdat = new SecureDat(key,opts)
      await sdat._archivePromise
      await sdat._load(params,key)
      return sdat
  }


  /*
  * PASSTHROUGH -HIDDEN - these function carrythough to the underlying dat, may be modified, and may be unstable.
  * Allows for changes to underlying Dat SDK
  */

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



  /*
  * PASSTHROUGH - these function carry through to the underlying dat archive without modification
  */




  async unlink(filename){
    return await this.archive.unlink(filename)
  }

  async mkdir(path){
    return await this.archive.mkdir(path)
  }
}
