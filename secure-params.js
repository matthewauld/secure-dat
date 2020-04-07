const PUB_KEY_ENCODING = {type:'spki', format:'pem'}
const PRIV_KEY_ENCODING = {type:'pkcs8',format:'pem'}
const fs = require('fs').promises


module.exports = class SecureParams{
  constructor(paramPath,
               attrs,
               dirtyAttrs,
               users,
               myKeys,
               publicParams,
               secretParams,
               diffiePrime,
               diffieSecret,
               diffiePublic,
               joinKey,
               pubDatKey,
               secDatKey,
               version){
    this.paramPath    = paramPath
    this.attrs        = attrs?attrs:[]
    this.dirtyAttrs   = dirtyAttrs?dirtyAttrs:[]
    this.users        = new Map(users)
    this.myKeys       = new Map(myKeys)
    this.publicParams = publicParams
    this.secretParams = secretParams
    this.diffiePrime  = diffiePrime
    this.diffieSecret = diffieSecret
    this.diffiePublic = diffiePublic
    this.joinKey      = joinKey
    this.pubDatKey    = pubDatKey
    this.secDatKey    = secDatKey
    this.version      = version
    //is this the owner?
  }

  async serialize(){
    // TODO: add 'encrypt and to dat' option
    let saveObject = {
      attrs: this.attrs,
      users: Array.from(this.users),
      myKeys: Array.from(this.myKeys),
      publicParams: this.publicParams?this.publicParams.toString('base64'):null,
      secretParams: this.secretParams?this.secretParams.toString('base64'):null,
      diffiePrime: this.diffiePrime?this.diffiePrime.toString('base64'):null,
      diffieSecret: this.diffieSecret?this.diffieSecret.toString('base64'):null,
      diffiePublic: this.diffieSecret?this.diffieSecret.toString('base64'):null,
      joinKey: this.joinKey?{
        pub: this.joinKey.pub.export(PUB_KEY_ENCODING),
        priv: this.joinKey.priv.export(PRIV_KEY_ENCODING),
      }:null,
      pubDatKey: this.pubDatKey,
      secDatKey: this.secDatKey?this.secDatKey.toString('base64'):null,
      version: this.version,
    }
    return JSON.stringify(saveObject)

  }
  async save(){
    const paramFile = await fs.open(this.paramPath,'w')
    await paramFile.writeFile(await this.serialize())
    await paramFile.close()
  }

  
  autoSave(){

  }

  static async load(path){
    const paramFile = await fs.open(path,'r')
    const params = JSON.parse(await paramFile.readFile('utf8'))
    await paramFile.close()
    return new SecureParams(path,
                 params.attrs,
                 params.dirtyAttrs,
                 params.users,
                 params.myKeys,
                 params.publicParams,
                 params.secretParams,
                 params.diffiePrime,
                 params.diffieSecret,
                 params.diffiePublic,
                 params.joinKey,
                 params.pubDatKey,
                 params.secDatKey,
                 params.version)
  }

}
