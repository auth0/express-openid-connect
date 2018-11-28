const fs = require('fs');
const { JSDOM } = require('jsdom');
const { assert } = require('chai');
const HTMLFormElement = require('jsdom/lib/jsdom/living/nodes/HTMLFormElement-impl').implementation;
const repostHTML = fs.readFileSync(`${__dirname}/../views/repost.html`, 'utf8');
const querystring = require('querystring');

describe('FORM for repost HTML', function() {
  let dom;
  let form;
  let originalSubmit;
  const fields = { foo:'123', bar:'4556' };

  //this is a hack because form.submit is not supported yet:
  // https://github.com/jsdom/jsdom/issues/123
  before(function(){
    originalSubmit = HTMLFormElement.prototype.submit;
    HTMLFormElement.prototype.submit = function() {
      this.setAttribute('submitted', true);
    };
  });

  after(function(){
    HTMLFormElement.prototype.submit = originalSubmit;
  });
  ///end of hack

  before(function() {
    dom = new JSDOM(repostHTML, {
      url: `https://localhost/callback#${querystring.encode(fields)}`,
      runScripts: 'dangerously',
    });
    form = dom.window.document.querySelector('form');
  });

  it('should have method post', function() {
    assert.equal(form.getAttribute('method'), 'POST');
  });

  it('should contains the fields', function() {
    const inputs = form.getElementsByTagName('input');
    Object.keys(fields).forEach((name, index) => {
      assert.equal(inputs[index].getAttribute('type'), 'hidden');
      assert.equal(inputs[index].getAttribute('name'), name);
      assert.equal(inputs[index].getAttribute('value'), fields[name]);
    });
  });

  it('should submit the form', function() {
    assert.equal(form.getAttribute('submitted'), true);
  });
});
