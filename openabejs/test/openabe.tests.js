var test = require('tape');
var assert = require('assert')
const openabejs = require('../build/Release/openabejs.node');


test('test initalize single openabejs object',async assert=>{
  assert.plan(1)
  try{
    const obj =  new openabejs.OpenABEjs()
    assert.assert(obj instanceof openabejs.OpenABEjs)
  } catch(e){
  assert.fail(e)
  assert.end();
  }
})

test('test multiple openabejs objects',async assert=>{
  assert.plan(3)
  try{
    const obj1 =  new openabejs.OpenABEjs()
    const obj2 =  new openabejs.OpenABEjs()

    assert.assert(obj1 instanceof openabejs.OpenABEjs)
    assert.assert(obj2 instanceof openabejs.OpenABEjs)
    assert.assert(obj2 !== obj1)
  } catch(e){
  assert.fail(e)
  assert.end();
  }
})

test('test parameter errors, TODO: add more for invalid strings!',async assert=>{

  try{
    const obj2 =  new openabejs.OpenABEjs()
    assert.throws(()=>{obj2.exportPublicParams()},new Error("No public parameters to export."))
    assert.throws(()=>{obj2.exportSecretParams()},new Error("No secret parameters to export."))
    assert.throws(()=>{obj2.importSecretParams()},new TypeError("String expected"))
    assert.throws(()=>{obj2.importPublicParams()},new TypeError("String expected"))
    assert.throws(()=>{obj2.importSecretParams("This wont work...")}, Error)
    assert.throws(()=>{obj2.importPublicParams("This wont work...")}, Error)
    assert.end();
  } catch(e){
  assert.fail(e)
  assert.end();
  }
})

test('test parameter import export',async assert=>{
  assert.plan(4)
  try{
    const obj1 =  new openabejs.OpenABEjs()
    const obj2 =  new openabejs.OpenABEjs()
    obj1.generateParams()
    let sec = obj1.exportSecretParams()
    let pub = obj1.exportPublicParams()
    assert.ok(sec)
    assert.ok(pub)
    obj2.importPublicParams(pub)
    obj2.importSecretParams(sec)
    assert.equal(compareArrays(obj2.exportSecretParams(),obj1.exportSecretParams()),true)
    assert.equal(compareArrays(obj2.exportPublicParams(),obj1.exportPublicParams()),true)
  } catch(e){
  assert.fail(e)
  assert.end();
  }
})

test('test user key generation',async assert=>{
  try{
    const obj1 =  new openabejs.OpenABEjs()
    const obj2 =  new openabejs.OpenABEjs()
    obj1.generateParams()
    obj1.keygen("foo|bar","testUser");
    let key = obj1.exportUserKey("testUser")
    const params = obj1.exportPublicParams()
    obj2.importPublicParams(params)
    obj2.importUserKey("testUser",key)
    assert.equal(compareArrays(key,obj2.exportUserKey("testUser")),true)
    assert.end()
  } catch(e){
    assert.fail(e)
    assert.end();
  }
})

test("test basic encrypt/decrypt", async assert=>{
  try{
    //setup two instaces with the same keys
    const obj1 =  new openabejs.OpenABEjs()
    const obj2 =  new openabejs.OpenABEjs()
    obj1.generateParams()
    obj1.keygen("foo|bar","testUser")
    let key = obj1.exportUserKey("testUser")
    const params = obj1.exportPublicParams()
    obj2.importPublicParams(params)
    obj2.importUserKey("testUser",key)
    let encrypted_key = obj1.encrypt("foo and bar")
    let decrypted_key = obj2.decrypt("testUser",encrypted_key.ciphertext)
    assert.true(compareArrays(encrypted_key.key,decrypted_key.key))



    assert.end()
  } catch(e){
    assert.fail(e)
    assert.end();
  }
})


function compareArrays(a1, a2){
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
