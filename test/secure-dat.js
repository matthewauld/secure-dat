var test = require('tape');
var assert = require('assert')
var SecureDat = require('../secure-dat.js')

test('test init',async assert=>{
  assert.plan(6)
  try{
    let sdat = await SecureDat.new()
    assert.ok(sdat, "static new function returns null")
    assert.ok(sdat.params.publicParams,"check if public params are null")
    assert.ok(sdat.params.secretParams,"check if secret params are null")
    assert.ok(sdat.params.joinKey,"check if joinkey is null")
    assert.ok(sdat.params.diffiePublic,"check if diffie is null")
    let x = await  sdat.archive.readdir('/.sdat')
    assert.equal(x.length,4,"right number of new files")
  } catch(e){
    assert.fail(e)
    assert.end();
  }
})
