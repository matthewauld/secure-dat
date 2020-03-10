const PUB_KEY_ENCODING = {type:'spki', format:'pem'}
const PRIV_KEY_ENCODING = {type:'pkcs8',format:'pem'}



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
    this.users        = users?users:new Map()
    this.myKeys       = myKeys?myKeys:new Map()
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
    this.owner = this.secretParams?true:false
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
      diffieSecret: this.DiffieSecret?this.DiffieSecret.toString('base64'):null,
      diffiePublic: this.DiffieSecret?this.DiffieSecret.toString('base64'):null,
      joinKey: this.joinKey?{
        pub: this.joinKey.pub.export(PUB_KEY_ENCODING),
        priv: this.joinKey.priv.export(PRIV_KEY_ENCODING),
      }:null,
      pubDatKey: this.pubDatKey,
      secDatKey: this.secDatKey?this.secDatKey.toString('base64'):null
    }
    return JSON.stringify(saveObject)

  }

  autoSave(){

  }

  static async load(path){

  }

}
