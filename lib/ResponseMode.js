/**
 *
 * Specifies the mode of the response according to
 * [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html) and
 * [OAuth 2.0 Form Post Response Mode](https://openid.net/specs/oauth-v2-form-post-response-mode-1_0.html).
 *
 * @enum {string}
 *
*/
module.exports = {

  /**
  * Uses the default mode for the response_type
  * as stated in [OAuth 2.0 Multiple Response Type Encoding Practices](https://openid.net/specs/oauth-v2-multiple-response-types-1_0.html)
  */
  Default: undefined,

  /**
  * Authorization Response parameters are encoded in
  * the query string added to the redirect_uri when redirecting back to the Client.
  */
  Query: 'query',

  /**
  * Authorization Response parameters are encoded as HTML form values
  * that are auto-submitted in the User Agent, and thus are transmitted via the HTTP POST method
  * to the Client, with the result parameters being encoded in the body using the application/x-www-form-urlencoded format.
  * The action attribute of the form is the Client's Redirection URI and the method of the form attribute is POST.
  */
  FormPost: 'form_post'
};
