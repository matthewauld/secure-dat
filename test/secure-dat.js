var test = require('tape');
var assert = require('assert')
var SecureDat = require('../secure-dat.js')

test('test init',async assert=>{
  assert.plan(6)
  try{
    let sdat = await SecureDat.new()
    assert.ok(sdat, "Ensure static new function returns valid response")
    assert.ok(sdat.params.publicParams,"Ensure  public params are not null")
    assert.ok(sdat.params.secretParams,"Ensure  secret params are not null")
    assert.ok(sdat.params.joinKey,"Ensure  joinkey is not null")
    assert.ok(sdat.params.diffiePublic,"ensure diffeis not null")
    let x = await  sdat.archive.readdir('/.sdat')
    assert.equal(x.length,4,"Ensure right number of new files")
  } catch(e){
    assert.fail(e)
    assert.end();
  }
})
test('')
