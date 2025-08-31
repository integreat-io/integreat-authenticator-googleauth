# Google Auth authenticator for Integreat

Uses Google's Auth to authenticate.

[![npm Version](https://img.shields.io/npm/v/integreat-authenticator-googleauth.svg)](https://www.npmjs.com/package/integreat-authenticator-googleauth)
[![Maintainability](https://api.codeclimate.com/v1/badges/6cfc3f8c23594ffb7e12/maintainability)](https://codeclimate.com/github/integreat-io/integreat-authenticator-googleauth/maintainability)

## Getting started

### Prerequisits

Requires node v20 and Integreat v1.0.

### Installing and using

Install from npm:

```
npm install integreat-authenticator-googleauth
```

The authenticator supports the following options:

- `type`: `'accessToken'` is the default and returns a Google access token. Set
  to `'idToken'` to return a Google ID token (JWT).
- `aud`: The audience for the ID token. When not set, the `url` will be used
  as audience. Not relevant for access token.
- `url`: The url to call when fetching the ID token. No default. Not relevant
  for access token.
- `scopes`: A scope string or an array of scope strings. Default is
  `'https://www.googleapis.com/auth/cloud-platform'`. If you need to have no
  scopes for some reason, set it to an empty array.

### Running the tests

The tests can be run with `npm test`.

## Contributing

Please read
[CONTRIBUTING](https://github.com/integreat-io/integreat-authenticator-googleauth/blob/master/CONTRIBUTING.md)
for details on our code of conduct, and the process for submitting pull
requests.

## License

This project is licensed under the ISC License - see the
[LICENSE](https://github.com/integreat-io/integreat-authenticator-googleauth/blob/master/LICENSE)
file for details.
